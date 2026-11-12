"""Reusable, offline Linux kernel network lab. No copied VMs or applications.

The Lab API creates only owned network namespaces. nft/tc/sysctl operations
always execute in one of those namespaces, never the host network namespace.
The generic echo self-check is not a product/NAT-traversal acceptance test.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
PROFILES = SOURCE.with_name("profiles.json")
EVIDENCE = ROOT / "evidence/network-lab"
STATE = ROOT / "state/network-lab"
PUBLIC_B = "198.18.20.2"
WAN = "198.18.0.1"
UDP_PORT, TCP_PORT = 38552, 38553


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def persist(path, value):
    pending = path.with_suffix(".pending.json")
    pending.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pending.replace(path)


def load_profiles(path=PROFILES):
    raw = json.loads(Path(path).read_bytes())
    if raw.get("schema") != "RR_KERNEL_NETWORK_PROFILES_V1" or not 1 <= len(raw["profiles"]) <= 32:
        raise ValueError("PROFILE_SCHEMA_OR_COUNT")
    result = {}
    allowed = {"description", "packets", "payloadBytes", "intervalMS", "receiveWindowMS", "seed", "nat",
               "links", "mtu", "block", "event", "expect"}
    bounds = {"packets": (1, 128), "payloadBytes": (64, 4096), "intervalMS": (5, 100),
              "receiveWindowMS": (250, 6000), "seed": (0, 4294967295), "mtu": (576, 9000)}
    link_bounds = {"delayMS": (0, 2000), "jitterMS": (0, 500), "lossPercent": (0, 100),
                   "duplicatePercent": (0, 50), "reorderPercent": (0, 100), "rateKbit": (32, 1000000)}
    for name, patch in raw["profiles"].items():
        if not re.fullmatch(r"[a-z0-9-]{1,40}", name):
            raise ValueError("PROFILE_NAME")
        item = {**raw["defaults"], **patch}
        if set(item) - allowed:
            raise ValueError("UNKNOWN_PROFILE_FIELD")
        for key, (low, high) in bounds.items():
            if key in item and (type(item[key]) is not int or not low <= item[key] <= high):
                raise ValueError("PROFILE_INTEGER_BOUND:" + key)
        if item["nat"] not in ("single", "double") or item.get("block") not in (None, "udp", "peer", "one-way"):
            raise ValueError("NAT_OR_BLOCK_MODE")
        if item.get("event") not in (None, "link-flap", "conntrack-clear", "port-change"):
            raise ValueError("EVENT_MODE")
        if item["expect"] not in ("healthy", "delay", "impaired", "loss", "reorder", "duplicate", "blocked", "recovery"):
            raise ValueError("EXPECTATION")
        links = item.get("links", {})
        if set(links) - {"na", "nb", "xa"}:
            raise ValueError("LINK_SCOPE")
        for props in links.values():
            if set(props) - {*link_bounds, "burst"}:
                raise ValueError("UNKNOWN_LINK_FIELD")
            for key, value in props.items():
                if key == "burst":
                    if len(value) != 4 or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 100 for v in value):
                        raise ValueError("BURST_MODEL_BOUND")
                elif type(value) not in (int, float) or not math.isfinite(value) or not link_bounds[key][0] <= value <= link_bounds[key][1]:
                    raise ValueError("LINK_NUMERIC_BOUND:" + key)
            if props.get("jitterMS", 0) > props.get("delayMS", 0) or props.get("reorderPercent", 0) and not props.get("delayMS"):
                raise ValueError("JITTER_OR_REORDER_REQUIRES_DELAY")
        result[name] = item
    return result


def process_identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return {"pid": pid, "startTicks": text[text.rfind(")") + 2:].split()[19]}
    except FileNotFoundError:
        return None


class Lab:
    """One topology and one owner; reuse it for all profiles and product probes."""
    def __init__(self, operation, output):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("LINUX_ROOT_REQUIRED_FOR_OWNED_NETNS")
        for tool in ("ip", "tc", "nft", "sysctl", "conntrack"):
            if not shutil.which(tool):
                raise RuntimeError("LAB_DEPENDENCY_MISSING:" + tool)
        import fcntl
        STATE.mkdir(parents=True, exist_ok=True)
        self.lock = (STATE / "owner.lock").open("a+")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.operation, self.output = operation, output
        prefix = "rrnl" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:7]
        self.names = {role: prefix + "-" + role for role in ("a", "na", "xa", "w", "nb", "b")}
        self.owned, self.children, self.commands, self.cleanup = {}, [], [], []
        self.endpoint_maps = {}
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.owner = process_identity(os.getpid())
        self.ledger = STATE / "active.json"
        existing = set(self.run(["ip", "netns", "list"]).stdout.split())
        if any(name in existing for name in self.names.values()):
            self.lock.close()
            raise RuntimeError("EXISTING_LAB_NAMESPACE_INSPECT_ORIGINAL_OWNER")

    def run(self, argv, role=None, text=None, check=True):
        if role is not None:
            self.assert_owned(role)
            argv = ["ip", "netns", "exec", self.names[role], *map(str, argv)]
        proc = subprocess.run(argv, input=text, text=True, capture_output=True, timeout=15)
        self.commands.append({"argv": argv, "exitCode": proc.returncode,
                              "stdoutSha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                              "stderr": proc.stderr[-900:]})
        if check and proc.returncode:
            raise RuntimeError("LAB_COMMAND_FAILED:" + " ".join(argv) + ":" + proc.stderr[-900:])
        return proc

    def assert_owned(self, role):
        handle = Path("/run/netns") / self.names[role]
        current = handle.stat()
        if self.owned.get(role) != [current.st_dev, current.st_ino]:
            raise RuntimeError("NAMESPACE_OWNER_CHANGED")

    def checkpoint(self):
        persist(self.ledger, {"operationId": self.operation, "bootId": self.boot, "owner": self.owner,
                              "names": self.names, "namespaceIdentities": self.owned,
                              "children": [record for _, _, record in self.children], "output": str(self.output)})

    def create(self):
        for role, name in self.names.items():
            self.run(["ip", "netns", "add", name])
            handle = (Path("/run/netns") / name).stat()
            self.owned[role] = [handle.st_dev, handle.st_ino]
            self.checkpoint()
            self.run(["ip", "link", "set", "lo", "up"], role)
        links = [("a", "eth0", "10.231.1.2/24", "na", "lan", "10.231.1.1/24"),
                 ("na", "uplink", "100.64.10.2/24", "xa", "lan", "100.64.10.1/24"),
                 ("xa", "uplink", "198.18.10.3/24", "w", "wa", "198.18.10.1/24"),
                 ("nb", "uplink", "198.18.20.2/24", "w", "wb", "198.18.20.1/24"),
                 ("b", "eth0", "10.231.2.2/24", "nb", "lan", "10.231.2.1/24")]
        for index, (left, dev_l, addr_l, right, dev_r, addr_r) in enumerate(links):
            # Create both ends directly in owned namespaces. No root-namespace
            # veth/interface is left behind even if subsequent configuration fails.
            self.run(["ip", "link", "add", dev_l, "type", "veth", "peer", "name", dev_r,
                      "netns", self.names[right]], left)
            for role, dev, addr in ((left, dev_l, addr_l), (right, dev_r, addr_r)):
                self.run(["ip", "addr", "add", addr, "dev", dev], role)
                self.run(["ip", "link", "set", dev, "up"], role)
        self.run(["ip", "addr", "add", "198.18.10.2/32", "dev", "lo"], "na")
        self.run(["ip", "addr", "add", WAN + "/32", "dev", "lo"], "w")
        self.routes = {"a": [("default", "10.231.1.1")], "na": [("default", "100.64.10.1")],
                  "xa": [("default", "198.18.10.1"), ("198.18.10.2/32", "100.64.10.2")],
                  "w": [("198.18.10.2/32", "198.18.10.3")],
                  "nb": [("default", "198.18.20.1")], "b": [("default", "10.231.2.1")]}
        self.restore_routes()
        for role in ("na", "xa", "w", "nb"):
            self.run(["sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0",
                      "net.ipv4.conf.default.rp_filter=0"], role)
        return links

    def restore_routes(self):
        # Link-down may remove a static gateway route. The topology owner alone
        # restores its declared routes; it never invents an application route.
        for role, entries in self.routes.items():
            for address, gateway in entries:
                self.run(["ip", "route", "replace", address, "via", gateway], role)

    def replace_table(self, role, body):
        # Namespace identity is checked before both the existence read and change.
        old = self.run(["nft", "list", "table", "ip", "rrlab"], role, check=False)
        prefix = "delete table ip rrlab\n" if old.returncode == 0 else ""
        self.run(["nft", "-f", "-"], role, text=prefix + "table ip rrlab {\n" + body + "\n}\n")

    def configure(self, profile):
        self.profile = profile
        self.endpoint_maps = {}
        for role in ("na", "nb"):
            number = 1 if role == "na" else 2
            public = "198.18.10.2" if role == "na" else PUBLIC_B
            block = 'ip protocol udp counter drop comment "blocked_udp";' if role == "na" and profile.get("block") == "udp" else ""
            snat = f"snat to {public}"
            body = f'''chain pre {{ type nat hook prerouting priority dstnat; policy accept;
                iifname "uplink" udp dport {UDP_PORT} dnat to 10.231.{number}.2:{UDP_PORT}; }}
              chain post {{ type nat hook postrouting priority srcnat; policy accept;
                oifname "uplink" ip saddr 10.231.{number}.0/24 {snat}; }}
              chain forward {{ type filter hook forward priority filter; policy drop;
                {block} ct state established,related counter accept;
                iifname "lan" oifname "uplink" counter accept;
                ct status dnat counter accept; counter drop; }}'''
            self.replace_table(role, body)
        outer = 'oifname "uplink" ip saddr 198.18.10.2 snat to 198.18.10.3;' if profile["nat"] == "double" else ""
        self.replace_table("xa", f'chain pre {{ type nat hook prerouting priority dstnat; policy accept; }}\n'
                                 f'chain post {{ type nat hook postrouting priority srcnat; policy accept; {outer} }}')
        blocked = ""
        if profile.get("block") == "peer":
            blocked = f'ip daddr {PUBLIC_B} ip protocol udp counter drop comment "blocked_peer";'
        if profile.get("block") == "one-way":
            blocked = f'ip saddr {{ 198.18.10.2, 198.18.10.3 }} ip daddr {PUBLIC_B} ip protocol udp counter drop comment "blocked_one_way";'
        self.replace_table("w", f'chain forward {{ type filter hook forward priority filter; policy accept; {blocked} }}')
        mtu = str(profile.get("mtu", 1500))
        for role, dev in (("a", "eth0"), ("na", "lan"), ("na", "uplink"), ("xa", "lan"), ("xa", "uplink"),
                          ("w", "wa"), ("w", "wb"), ("nb", "uplink"), ("nb", "lan"), ("b", "eth0")):
            self.run(["ip", "link", "set", dev, "mtu", mtu, "up"], role)
        self.restore_routes()
        self.set_link_conditions(profile)
        for role in ("na", "xa", "nb", "w"):
            self.run(["conntrack", "-F"], role)

    def set_link_conditions(self, profile):
        """Change owned qdiscs without retiring NAT maps or live connections."""
        for role in ("na", "xa", "nb"):
            self.run(["tc", "qdisc", "del", "dev", "uplink", "root"], role, check=False)
            props = profile.get("links", {}).get(role)
            if props:
                args = ["tc", "qdisc", "add", "dev", "uplink", "root", "netem", "limit", "256"]
                if props.get("delayMS"):
                    args += ["delay", str(props["delayMS"]) + "ms"]
                    if props.get("jitterMS"):
                        args += [str(props["jitterMS"]) + "ms", "distribution", "normal"]
                if props.get("lossPercent"):
                    args += ["loss", "random", str(props["lossPercent"]) + "%"]
                if props.get("burst"):
                    args += ["loss", "gemodel", *[str(v) + "%" for v in props["burst"]]]
                for field, flag in (("duplicatePercent", "duplicate"), ("reorderPercent", "reorder")):
                    if props.get(field):
                        args += [flag, str(props[field]) + "%"]
                if props.get("rateKbit"):
                    args += ["rate", str(props["rateKbit"]) + "kbit"]
                args += ["seed", str(profile["seed"])]
                self.run(args, role)

    def set_udp_blackout(self, enabled):
        """Toggle UDP loss on the owned A router; retain NAT and TCP state."""
        if type(enabled) is not bool:
            raise ValueError("UDP_BLACKOUT_BOOLEAN_REQUIRED")
        existing = self.run(["nft", "list", "chain", "ip", "rrlab", "path_fault"], "na", check=False)
        if existing.returncode != 0:
            self.run(["nft", "add", "chain", "ip", "rrlab", "path_fault",
                      "{", "type", "filter", "hook", "forward", "priority", "-5;", "policy", "accept;", "}"], "na")
        self.run(["nft", "flush", "chain", "ip", "rrlab", "path_fault"], "na")
        if enabled:
            self.run(["nft", "add", "rule", "ip", "rrlab", "path_fault",
                      "ip", "protocol", "udp", "counter", "drop"], "na")

    def observe_udp_endpoint(self, role, source_ip, source_port, destination_port):
        """Read one exact owned outbound mapping; never infer a public port."""
        sources = {"na": ("10.231.1.2", "198.18.10.2"), "nb": ("10.231.2.2", PUBLIC_B)}
        if self.profile["nat"] == "double":
            sources["xa"] = ("198.18.10.2", "198.18.10.3")
        if role not in sources or source_ip != sources[role][0]:
            raise ValueError("OBSERVED_MAPPING_SOURCE_SCOPE")
        if any(type(port) is not int or not 1024 <= port <= 65535 for port in (source_port, destination_port)):
            raise ValueError("OBSERVED_MAPPING_NUMERIC_BOUND")
        self.assert_owned(role)
        raw = self.run(["conntrack", "-L", "-p", "udp", "-o", "extended"], role).stdout
        matches = []
        for line in raw.splitlines():
            pairs = re.findall(r"\b(src|dst|sport|dport)=([0-9.]+)", line)
            if [key for key, _ in pairs] != ["src", "dst", "sport", "dport"] * 2:
                continue
            original, reverse = dict(pairs[:4]), dict(pairs[4:])
            outbound = {"src": source_ip, "dst": WAN, "sport": str(source_port), "dport": str(destination_port)}
            if original == outbound:
                matches.append((reverse, line))
            elif reverse == outbound and original["src"] == WAN and original["sport"] == str(destination_port):
                # An observed EIM lease can admit the real relay packet before
                # the peer refreshes its bind. Conntrack then records the same
                # tuple in the opposite original direction. Read its public
                # endpoint from that actual tuple, never from the local port.
                matches.append(({"dst": original["dst"], "dport": original["dport"]}, line))
        if len(matches) != 1:
            raise RuntimeError("EXACT_OUTBOUND_UDP_MAPPING_REQUIRED")
        reverse, line = matches[0]
        public, mapped_port = reverse["dst"], int(reverse["dport"])
        if public != sources[role][1] or not 1024 <= mapped_port <= 65535 or mapped_port == UDP_PORT:
            raise RuntimeError("OBSERVED_MAPPING_PUBLIC_SCOPE")
        return {"role": role, "sourceIP": source_ip, "sourcePort": source_port, "mappedIP": public,
                "mappedPort": mapped_port, "actualConntrack": line}

    def admit_observed_udp_endpoint(self, role, source_ip, source_port, destination_port, lifetime=60):
        """Install a timed EIM simulation lease, not a standing port forward."""
        if type(lifetime) is not int or not 5 <= lifetime <= 120:
            raise ValueError("OBSERVED_MAPPING_LIFETIME_BOUND")
        observed = self.observe_udp_endpoint(role, source_ip, source_port, destination_port)
        public, mapped_port = observed["mappedIP"], observed["mappedPort"]
        if role not in self.endpoint_maps:
            for name in ("observed_udp", "observed_udp_out"):
                self.run(["nft", "add", "map", "ip", "rrlab", name,
                          "{", "type", "inet_service", ":", "ipv4_addr", ".", "inet_service;",
                          "flags", "timeout;", "timeout", str(lifetime) + "s;", "}"], role)
            self.run(["nft", "add", "rule", "ip", "rrlab", "pre", "iifname", "uplink", "ip", "daddr", public,
                      "ip", "protocol", "udp", "counter", "dnat", "ip", "addr", ".", "port", "to",
                      "udp", "dport", "map", "@observed_udp"], role)
            self.run(["nft", "insert", "rule", "ip", "rrlab", "post", "iifname", "lan", "oifname", "uplink",
                      "ip", "saddr", source_ip, "ip", "protocol", "udp", "counter", "snat", "ip", "addr", ".",
                      "port", "to", "udp", "sport", "map", "@observed_udp_out"], role)
            self.endpoint_maps[role] = set()
        ports = self.endpoint_maps[role]
        if len(ports) >= 16 and mapped_port not in ports:
            raise RuntimeError("OBSERVED_ENDPOINT_MAP_COUNT_BOUND")
        if mapped_port in ports:
            retired = self.run(["nft", "delete", "element", "ip", "rrlab", "observed_udp", "{", str(mapped_port), "}"], role, check=False)
            if retired.returncode and "No such file or directory" not in retired.stderr:
                raise RuntimeError("OBSERVED_ENDPOINT_RETIREMENT_FAILED")
        retired_out = self.run(["nft", "delete", "element", "ip", "rrlab", "observed_udp_out", "{", str(source_port), "}"], role, check=False)
        if retired_out.returncode and "No such file or directory" not in retired_out.stderr:
            raise RuntimeError("OBSERVED_OUTBOUND_ENDPOINT_RETIREMENT_FAILED")
        self.run(["nft", "add", "element", "ip", "rrlab", "observed_udp", "{", str(mapped_port), "timeout",
                  str(lifetime) + "s", ":", source_ip, ".", str(source_port), "}"], role)
        self.run(["nft", "add", "element", "ip", "rrlab", "observed_udp_out", "{", str(source_port), "timeout",
                  str(lifetime) + "s", ":", public, ".", str(mapped_port), "}"], role)
        ports.add(mapped_port)
        # Existing destination-dependent tuples must not survive an explicit
        # model change. These router namespaces belong exclusively to this lab.
        self.run(["conntrack", "-F"], role)
        return {**observed, "lifetimeSeconds": lifetime,
                "oldOwnedConntrackRetired": True,
                "kernelMap": json.loads(self.run(["nft", "-j", "list", "map", "ip", "rrlab", "observed_udp"], role).stdout),
                "kernelOutboundMap": json.loads(self.run(["nft", "-j", "list", "map", "ip", "rrlab", "observed_udp_out"], role).stdout)}

    def clear_observed_udp_endpoints(self, role):
        self.assert_owned(role)
        if role in self.endpoint_maps:
            for name in ("observed_udp", "observed_udp_out"):
                self.run(["nft", "flush", "map", "ip", "rrlab", name], role)
            self.endpoint_maps[role].clear()

    def spawn(self, role, argv, name):
        self.assert_owned(role)
        log = self.output / (name + ".log")
        handle = log.open("x", encoding="utf-8")
        child = subprocess.Popen(["ip", "netns", "exec", self.names[role], *map(str, argv)],
                                 cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        record = {"identity": process_identity(child.pid), "role": role, "argv": list(map(str, argv)), "log": str(log)}
        if record["identity"] is None:
            handle.close()
            raise RuntimeError("OWNED_CHILD_EXITED_BEFORE_IDENTITY_CAPTURE")
        self.children.append((child, handle, record))
        self.checkpoint()
        return child, log

    def probe(self, profile, mode, label):
        launch = time.monotonic()
        child, log = self.spawn("a", [sys.executable, "-B", SOURCE, "node", "--mode", mode,
                                     "--profile-json", json.dumps(profile, separators=(",", ":"))], label)
        events = []
        if mode == "udp" and profile.get("event"):
            time.sleep(0.4)
            event = profile["event"]
            if event == "link-flap":
                before = self.route_state()
                self.run(["ip", "link", "set", "uplink", "down"], "na")
                events.append({"event": "link-down", "controllerOffsetMS": round((time.monotonic() - launch) * 1000, 3),
                               "routesBefore": before, "routesAfter": self.route_state()})
                time.sleep(0.6)
                self.run(["ip", "link", "set", "uplink", "up"], "na")
                before_restore = self.route_state()
                self.restore_routes()
                events.append({"event": "link-up-and-declared-routes-restored",
                               "controllerOffsetMS": round((time.monotonic() - launch) * 1000, 3),
                               "routesBeforeRestore": before_restore, "routesAfter": self.route_state()})
            elif event == "conntrack-clear":
                for role in ("na", "xa", "nb"):
                    self.run(["conntrack", "-F"], role)
                events.append({"event": event, "controllerOffsetMS": round((time.monotonic() - launch) * 1000, 3)})
            else:
                # Insert a UDP-specific mapping ahead of the existing general
                # SNAT rule. TCP keeps its original mapping and reachability.
                rule = self.run(["nft", "-a", "list", "chain", "ip", "rrlab", "post"], "na").stdout
                handles = re.findall(r"snat to 198\.18\.10\.2.*# handle (\d+)", rule)
                if len(handles) != 1:
                    raise RuntimeError("EXACT_SNAT_RULE_NOT_FOUND")
                self.run(["nft", "insert", "rule", "ip", "rrlab", "post",
                          "oifname", "uplink", "ip", "saddr", "10.231.1.0/24", "ip", "protocol", "udp",
                          "snat", "to", "198.18.10.2:41551"], "na")
                self.run(["conntrack", "-F"], "na")
                events.append({"event": event, "controllerOffsetMS": round((time.monotonic() - launch) * 1000, 3), "sourcePort": 41551})
        child.wait(timeout=profile["packets"] * profile["intervalMS"] / 1000 + profile["receiveWindowMS"] / 1000 + 5)
        if child.returncode:
            raise RuntimeError("PROBE_CHILD_FAILED:" + log.read_text()[-1200:])
        result = json.loads(log.read_text())
        result["events"] = events
        return result

    def route_state(self):
        return {role: {"routes": json.loads(self.run(["ip", "-j", "route", "show"], role).stdout),
                       "links": json.loads(self.run(["ip", "-j", "link", "show"], role).stdout)}
                for role in self.owned}

    def snapshot(self):
        result = {}
        for role in ("na", "xa", "w", "nb"):
            nft = json.loads(self.run(["nft", "-j", "list", "table", "ip", "rrlab"], role).stdout)
            ct = self.run(["conntrack", "-L", "-o", "extended"], role).stdout
            tc = json.loads(self.run(["tc", "-s", "-j", "qdisc", "show"], role).stdout)
            result[role] = {"nft": nft, "conntrack": ct, "qdisc": tc}
        return result

    def close(self):
        errors = []
        for child, handle, record in reversed(self.children):
            try:
                if child.poll() is None:
                    if process_identity(child.pid) != record["identity"]:
                        raise RuntimeError("CHILD_IDENTITY_CHANGED")
                    child.terminate()
                child.wait(timeout=3)
                self.cleanup.append({"child": record, "exitCode": child.returncode})
            except BaseException as exc:
                errors.append(str(exc))
            finally:
                handle.close()
        for role in reversed(list(self.owned)):
            try:
                self.assert_owned(role)
                pids = self.run(["ip", "netns", "pids", self.names[role]]).stdout.strip()
                if pids:
                    raise RuntimeError("NAMESPACE_HAS_LIVE_PROCESS:" + role)
                self.run(["ip", "netns", "del", self.names[role]])
                self.cleanup.append({"namespace": self.names[role], "retired": True})
            except BaseException as exc:
                errors.append(str(exc))
        remaining = self.run(["ip", "netns", "list"]).stdout
        if any(name in remaining.split() for name in self.names.values()):
            errors.append("OWNED_NAMESPACE_REMAINS")
        persist(self.ledger, {"operationId": self.operation, "phase": "CLEANED" if not errors else "CLEANUP_REQUIRES_REVIEW",
                              "bootId": self.boot, "owner": self.owner, "cleanup": self.cleanup, "errors": errors})
        self.lock.close()
        return errors


def node(args):
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    if args.mode in ("echo-udp", "echo-tcp"):
        udp = args.mode == "echo-udp"
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        conn.bind(("0.0.0.0" if udp else WAN, UDP_PORT if udp else TCP_PORT))
        if not udp:
            conn.listen(8)
        conn.settimeout(0.1)
        received, byte_count = 0, 0
        print(json.dumps({"phase": "READY", "endpoint": conn.getsockname()}), flush=True)
        try:
            while not stop[0] and received < 16384 and byte_count < 16 * 1024 * 1024:
                try:
                    if udp:
                        data, peer = conn.recvfrom(4097)
                        if len(data) > 4096:
                            raise RuntimeError("ECHO_DATAGRAM_BOUND")
                        conn.sendto(data, peer)
                    else:
                        peer_conn, peer = conn.accept()
                        with peer_conn:
                            peer_conn.settimeout(1)
                            data = peer_conn.recv(1024)
                            peer_conn.sendall(data)
                    received += 1
                    byte_count += len(data)
                except socket.timeout:
                    pass
        finally:
            conn.close()
        print(json.dumps({"phase": "STOPPED", "received": received, "bytes": byte_count}), flush=True)
        return 0
    p = json.loads(args.profile_json)
    if args.mode == "tcp":
        started = time.monotonic()
        try:
            with socket.create_connection((WAN, TCP_PORT), timeout=3) as conn:
                conn.sendall(b"RR-NETLAB-CONTROL")
                good = conn.recv(64) == b"RR-NETLAB-CONTROL"
            result = {"connected": good, "elapsedMS": round((time.monotonic() - started) * 1000, 3)}
        except OSError as exc:
            result = {"connected": False, "error": type(exc).__name__, "errno": exc.errno}
        print(json.dumps(result))
        return 0
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.bind(("10.231.1.2", 0))
    conn.setblocking(False)
    nonce = os.urandom(16)
    count, size = p["packets"], p["payloadBytes"]
    frames = [b"RRNL" + nonce + struct.pack("!I", index) + bytes([index % 251]) * (size - 24) for index in range(count)]
    sent_at, got, order, errors, duplicates, invalid = {}, {}, [], [], 0, 0
    start = time.monotonic()
    end = start + (count - 1) * p["intervalMS"] / 1000 + p["receiveWindowMS"] / 1000
    index = 0
    while time.monotonic() < end:
        now = time.monotonic()
        if index < count and now >= start + index * p["intervalMS"] / 1000:
            try:
                written = conn.sendto(frames[index], (PUBLIC_B, UDP_PORT))
                if written == len(frames[index]):
                    sent_at[index] = now
                else:
                    errors.append({"sequence": index, "shortWriteBytes": written})
            except OSError as exc:
                errors.append({"sequence": index, "errno": exc.errno})
            index += 1
        ready, _, _ = select.select([conn], [], [], 0.005)
        if ready:
            data, peer = conn.recvfrom(4097)
            sequence = struct.unpack("!I", data[20:24])[0] if len(data) >= 24 else count
            if peer != (PUBLIC_B, UDP_PORT) or sequence >= count or data != frames[sequence] or sequence not in sent_at:
                invalid += 1
            elif sequence in got:
                duplicates += 1
            else:
                got[sequence] = round((time.monotonic() - sent_at[sequence]) * 1000, 3)
                order.append(sequence)
    local = conn.getsockname()
    conn.close()
    values = sorted(got.values())
    print(json.dumps({"socket": local, "target": [PUBLIC_B, UDP_PORT], "attempted": index,
                      "sent": len(sent_at), "received": len(got),
                      "missing": len(sent_at) - len(got), "duplicates": duplicates, "invalid": invalid,
                      "outOfOrder": sum(b < a for a, b in zip(order, order[1:])), "socketErrors": errors,
                      "firstReceived": min(got) if got else None, "lastReceived": max(got) if got else None,
                      "rttMS": {"min": min(values), "median": statistics.median(values),
                                "p95": values[math.ceil(len(values) * .95) - 1], "max": max(values)} if values else None}))
    return 0


def blocked_packets(snapshot):
    total = 0
    for state in snapshot.values():
        for item in state["nft"]["nftables"]:
            rule = item.get("rule", {})
            if rule.get("comment", "").startswith("blocked_"):
                total += sum(part.get("counter", {}).get("packets", 0) for part in rule.get("expr", []))
    return total


def validate_probe(profile, udp, tcp, snapshot):
    failures = []
    expectation = profile["expect"]
    if udp["invalid"] or not tcp["connected"] or udp["attempted"] != profile["packets"]:
        failures.append("BODY_CONTROL_OR_SEND_COUNT")
    if expectation in ("healthy", "delay", "reorder", "duplicate") and udp["socketErrors"]:
        failures.append("UNEXPECTED_SOCKET_ERROR")
    if expectation in ("healthy", "delay", "reorder", "duplicate") and udp["missing"]:
        failures.append("UNEXPECTED_PACKET_LOSS")
    if expectation == "blocked":
        if udp["received"] or blocked_packets(snapshot) == 0:
            failures.append("BLOCK_NOT_OBSERVED")
    elif udp["received"] == 0:
        failures.append("NO_POSITIVE_DELIVERY")
    if expectation == "delay" and udp["rttMS"] and udp["rttMS"]["min"] < 120:
        failures.append("DELAY_NOT_OBSERVED")
    if expectation == "loss" and udp["missing"] == 0:
        failures.append("LOSS_NOT_OBSERVED")
    if expectation == "duplicate" and udp["duplicates"] == 0:
        failures.append("DUPLICATION_NOT_OBSERVED")
    if expectation == "reorder" and udp["outOfOrder"] == 0:
        failures.append("REORDER_NOT_OBSERVED")
    if expectation == "recovery" and (udp["firstReceived"] is None or udp["firstReceived"] >= 15 or udp["lastReceived"] < profile["packets"] - 10):
        failures.append("SAME_SOCKET_RECOVERY_NOT_OBSERVED")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    listing = subs.add_parser("profiles")
    listing.add_argument("--file", type=Path, default=PROFILES)
    run = subs.add_parser("smoke")
    run.add_argument("--operation", required=True)
    run.add_argument("--profiles", default="all")
    run.add_argument("--file", type=Path, default=PROFILES)
    n = subs.add_parser("node")
    n.add_argument("--mode", choices=("echo-udp", "echo-tcp", "udp", "tcp"), required=True)
    n.add_argument("--profile-json", default="{}")
    args = parser.parse_args()
    if args.command == "node":
        return node(args)
    profiles = load_profiles(args.file)
    if args.command == "profiles":
        print(json.dumps({name: profile["description"] for name, profile in profiles.items()}, ensure_ascii=False, indent=2))
        return 0
    if not re.fullmatch(r"[a-z0-9-]{1,80}", args.operation):
        raise ValueError("OPERATION_ID")
    chosen = list(profiles) if args.profiles == "all" else args.profiles.split(",")
    if not chosen or len(chosen) != len(set(chosen)) or any(name not in profiles for name in chosen):
        raise ValueError("SELECTED_PROFILES")
    output = EVIDENCE / args.operation
    if output.exists():
        raise RuntimeError("EXISTING_OPERATION_INSPECT_RECEIPT_DO_NOT_REPLAY")
    output.mkdir(parents=True)
    record = {"schema": "RR_KERNEL_NETWORK_SMOKE_V1", "operationId": args.operation, "phase": "STARTED",
              "source": {"path": str(SOURCE), "sha256": sha(SOURCE)},
              "profileFile": {"path": str(args.file.resolve()), "sha256": sha(args.file)},
              "kernel": os.uname().release, "results": [], "gameCopies": 0, "VMsCopied": 0,
              "externalNetworkLinked": False, "productAcceptance": False, "physicalWANAcceptance": False}
    receipt = output / "receipt.json"
    persist(receipt, record)
    lab = None
    try:
        lab = Lab(args.operation, output)
        record["topology"] = lab.create()
        record["namespaces"] = lab.names
        for role, mode in (("b", "echo-udp"), ("w", "echo-tcp")):
            child, log = lab.spawn(role, [sys.executable, "-B", SOURCE, "node", "--mode", mode], mode)
            end = time.monotonic() + 3
            while time.monotonic() < end and "READY" not in log.read_text():
                if child.poll() is not None:
                    raise RuntimeError("ECHO_START_FAILED")
                time.sleep(.02)
            if "READY" not in log.read_text():
                raise RuntimeError("ECHO_NOT_READY")
        for name in chosen:
            profile = profiles[name]
            lab.configure(profile)
            udp = lab.probe(profile, "udp", name + "-udp")
            tcp = lab.probe(profile, "tcp", name + "-tcp")
            snapshot = lab.snapshot()
            failures = validate_probe(profile, udp, tcp, snapshot)
            result = {"name": name, "profile": profile, "udp": udp, "tcp": tcp, "kernelState": snapshot,
                      "blockedPackets": blocked_packets(snapshot), "failures": failures, "passed": not failures}
            record["results"].append(result)
            persist(receipt, record)
            print(json.dumps({"profile": name, "passed": not failures, "sent": udp["sent"],
                              "received": udp["received"], "duplicates": udp["duplicates"], "outOfOrder": udp["outOfOrder"],
                              "tcp": tcp["connected"], "failures": failures}), flush=True)
        record["phase"] = "SMOKE_PASSED" if all(r["passed"] for r in record["results"]) else "SMOKE_FAILED_REVIEW_REQUIRED"
    except BaseException as exc:
        record.update(phase="FAILED_REVIEW_REQUIRED", error=type(exc).__name__, message=str(exc))
        raise
    finally:
        if lab is not None:
            record["cleanupErrors"] = lab.close()
            record["commands"] = lab.commands
            record["cleanup"] = lab.cleanup
        record["sourceAfter"] = sha(SOURCE)
        record["profileAfter"] = sha(args.file)
        record["inputsUnchanged"] = record["sourceAfter"] == record["source"]["sha256"] and record["profileAfter"] == record["profileFile"]["sha256"]
        persist(receipt, record)
    if record.get("cleanupErrors") or not record["inputsUnchanged"]:
        raise RuntimeError("CLEANUP_OR_INPUT_CHANGED_REVIEW_REQUIRED")
    return 0 if record["phase"] == "SMOKE_PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
