"""WF17 switch contracts through the registered FastMCP tools, without a JVM."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
if len(sys.argv) != 2:
    raise SystemExit("usage: test_switches.py <runtime/ghidra/python-packages>")
sys.path.append(str(Path(sys.argv[1]).resolve()))

from fastmcp import FastMCP
from re_mcp_ghidra.exceptions import GhidraError


_SOURCE = Path(__file__).resolve().parents[1] / "re_mcp_ghidra" / "tools" / "switches.py"
_SPEC = importlib.util.spec_from_file_location("rr_wf17_switches", _SOURCE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load canonical switches overlay")
switches = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = switches
_SPEC.loader.exec_module(switches)


class AddressSpace:
    def __init__(self, name="ram"):
        self.name = name

    def getName(self):
        return self.name


class Address:
    def __init__(self, offset, space="ram", memory=True):
        self.offset = offset
        self.space = AddressSpace(space)
        self.memory = memory

    def getOffset(self):
        return self.offset

    def getAddressSpace(self):
        return self.space

    def isMemoryAddress(self):
        return self.memory


class Flow:
    def __init__(self, *, jump=False, computed=False):
        self.jump = jump
        self.computed = computed

    def isJump(self):
        return self.jump

    def isComputed(self):
        return self.computed


class Reference:
    def __init__(self, offset, *, jump=True, memory=True, target_memory=True, space="ram"):
        self.target = Address(offset, space=space, memory=target_memory)
        self.flow = Flow(jump=jump)
        self.memory = memory

    def isMemoryReference(self):
        return self.memory

    def getReferenceType(self):
        return self.flow

    def getToAddress(self):
        return self.target


class JavaIterator:
    def __init__(self, values):
        self.values = iter(values)
        self.ready = False
        self.value = None

    def hasNext(self):
        if not self.ready:
            try:
                self.value = next(self.values)
            except StopIteration:
                return False
            self.ready = True
        return True

    def next(self):
        if not self.hasNext():
            raise StopIteration
        self.ready = False
        return self.value


class Instruction:
    def __init__(self, offset, *, jump=True, computed=True):
        self.address = Address(offset)
        self.flow = Flow(jump=jump, computed=computed)

    def getAddress(self):
        return self.address

    def getFlowType(self):
        return self.flow


class Function:
    def __init__(self, name, instructions):
        self.name = name
        self.instructions = instructions

    def getName(self):
        return self.name

    def getBody(self):
        return self.instructions


class Program:
    def __init__(self, references=None, functions=None):
        self.references = references or {}
        self.functions = functions if functions is not None else [Function("Dispatch", [Instruction(0x401000)])]
        self.instructions = {
            insn.address.offset: insn
            for func in self.functions
            for insn in func.instructions
        }
        self.references_yielded = 0

    def getListing(self):
        return self

    def getInstructionAt(self, address):
        return self.instructions.get(address.offset)

    def getInstructions(self, body, forward):
        if forward is not True:
            raise AssertionError("fixture expects forward instruction iteration")
        return JavaIterator(body)

    def getReferenceManager(self):
        return self

    def getReferencesFrom(self, address):
        for ref in self.references.get(address.offset, ()):
            self.references_yielded += 1
            yield ref

    def getFunctionManager(self):
        return self

    def getFunctions(self, forward):
        if forward is not True:
            raise AssertionError("fixture expects forward function iteration")
        return JavaIterator(self.functions)


class SwitchContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.program = Program()
        self.stack = []
        for target, name, value in (
            (switches.session, "_program", self.program),
            (switches.session, "_current_path", "fixture-only.exe"),
            (switches, "resolve_address", lambda value: Address(int(value, 0))),
        ):
            current = patch.object(target, name, value)
            current.start()
            self.stack.append(current)
        self.server = FastMCP("WF17 switch fixture")
        switches.register(self.server)
        self.tools = {name: await self.server.get_tool(name) for name in ("get_switch_info", "list_switches")}
        self.assertTrue(all(self.tools.values()), "actual registration must expose both original tools")

    async def asyncTearDown(self):
        for current in reversed(self.stack):
            current.stop()

    async def invoke(self, name="get_switch_info", **arguments):
        if name == "get_switch_info" and not arguments:
            arguments = {"address": "0x401000"}
        result = await self.tools[name].run(arguments)
        self.assertFalse(result.is_error)
        self.assertIsInstance(result.structured_content, dict)
        # Check the wire representation, not an unvalidated collector return.
        return json.loads(json.dumps(result.structured_content))

    def assert_unknown(self, value):
        self.assertIsNone(value["num_cases"])
        self.assertIsNone(value["default_targets"])
        self.assertEqual(value["labels_status"], "unavailable")
        self.assertEqual(value["default_status"], "unavailable")
        self.assertEqual(value["provenance"], "ghidra-reference-manager")
        self.assertIs(value["coverage_complete"], False)
        self.assertIs(value["references_complete"], True)

    async def test_original_tools_are_read_only_and_schema_preserves_null(self):
        self.assertEqual(sorted(tool.name for tool in await self.server.list_tools()), ["get_switch_info", "list_switches"])
        for tool in self.tools.values():
            self.assertIs(tool.annotations.readOnlyHint, True)
        schema = self.tools["get_switch_info"].output_schema
        for name in ("num_cases", "default_targets"):
            self.assertEqual(schema["properties"][name]["type"], "null")

    async def test_only_typed_memory_jumps_are_stable_unique_targets(self):
        # Independent oracle: two jump destinations; DATA/READ, CALL and nonmemory
        # references are not source-level cases, regardless of their byte offset.
        self.program.references[0x401000] = [
            Reference(0x405200), Reference(0x405100), Reference(0x405200),
            Reference(0x406000, jump=False), Reference(0x407000, jump=False),
            Reference(0x405300, memory=False), Reference(0x405400, target_memory=False),
        ]
        result = await self.invoke()
        self.assertEqual(result["cases"], [
            {"case_values": None, "target": "0x405100", "address_space": "ram"},
            {"case_values": None, "target": "0x405200", "address_space": "ram"},
        ])
        self.assertEqual(result["num_targets"], 2)
        self.assertEqual(result["references_examined"], 7)
        self.assertEqual(result["references_ignored"], 4)
        self.assert_unknown(result)
        self.program.references[0x401000].reverse()
        self.assertEqual(await self.invoke(), result)

    async def test_address_spaces_are_not_collapsed_by_equal_offsets(self):
        self.program.references[0x401000] = [Reference(0x405100), Reference(0x405100, space="overlay")]
        result = await self.invoke()
        self.assertEqual(result["num_targets"], 2)
        self.assertEqual([row["address_space"] for row in result["cases"]], ["overlay", "ram"])

    async def test_empty_references_remain_unknown(self):
        result = await self.invoke()
        self.assertEqual(result["cases"], [])
        self.assertEqual(result["num_targets"], 0)
        self.assertEqual(result["references_examined"], 0)
        self.assert_unknown(result)
        page = await self.invoke("list_switches")
        self.assertEqual(page["items"][0]["num_targets"], 0)
        self.assert_unknown(page["items"][0])
        self.assertIs(page["coverage_complete"], False)

    async def test_list_uses_identical_target_semantics_and_original_paging(self):
        self.program.references[0x401000] = [Reference(0x405200), Reference(0x405200), Reference(0x406000, jump=False)]
        detail = await self.invoke()
        page = await self.invoke("list_switches", offset=0, limit=1)
        self.assertEqual(page["total"], 1)
        self.assertFalse(page["has_more"])
        row = page["items"][0]
        for name in ("num_targets", "num_cases", "default_targets", "references_examined", "references_ignored"):
            self.assertEqual(row[name], detail[name])
        self.assertEqual(row["function"], "Dispatch")
        self.assert_unknown(row)
        empty_page = await self.invoke("list_switches", offset=1, limit=1)
        self.assertEqual(empty_page["items"], [])
        self.assertIs(empty_page["coverage_complete"], False)

    async def test_only_computed_jump_instructions_are_listed(self):
        self.program.functions = [Function("Mixed", [
            Instruction(0x401000), Instruction(0x401010, computed=False),
            Instruction(0x401020, jump=False),
        ])]
        page = await self.invoke("list_switches")
        self.assertEqual([row["address"] for row in page["items"]], ["0x401000"])

    async def test_noninstruction_is_rejected(self):
        with self.assertRaises(GhidraError) as caught:
            await self.invoke(address="0x401001")
        self.assertEqual(caught.exception.error_type, "NotFound")
        self.assertIn("No instruction", str(caught.exception))

    async def test_direct_jump_is_rejected(self):
        self.program.instructions[0x401000] = Instruction(0x401000, computed=False)
        with self.assertRaises(GhidraError) as caught:
            await self.invoke()
        self.assertEqual(caught.exception.error_type, "NotFound")
        self.assertIn("not a computed jump", str(caught.exception))

    async def test_indirect_call_is_rejected(self):
        self.program.instructions[0x401000] = Instruction(0x401000, jump=False)
        with self.assertRaises(GhidraError) as caught:
            await self.invoke()
        self.assertEqual(caught.exception.error_type, "NotFound")

    async def test_original_database_guard_is_preserved(self):
        switches.session._current_path = None
        for name in self.tools:
            with self.assertRaises(GhidraError) as caught:
                await self.invoke(name)
            self.assertEqual(caught.exception.error_type, "NoDatabase")

    async def test_reference_budget_includes_duplicates_and_accepts_boundary(self):
        self.program.references[0x401000] = [Reference(0x405100)] * 8192
        result = await self.invoke()
        self.assertEqual(result["num_targets"], 1)
        self.assertEqual(result["references_examined"], 8192)
        self.assert_unknown(result)

    async def test_reference_budget_rejects_instead_of_truncating(self):
        self.program.references[0x401000] = [Reference(0x405100, jump=False)] * 9000
        with self.assertRaises(GhidraError) as caught:
            await self.invoke()
        self.assertEqual(caught.exception.error_type, "ResourceLimit")
        self.assertEqual(caught.exception.details["reference_limit"], 8192)
        self.assertEqual(self.program.references_yielded, 8193)
        self.assertIs(caught.exception.details["coverage_complete"], False)

    async def test_target_budget_accepts_boundary(self):
        self.program.references[0x401000] = [Reference(0x500000 + i * 4) for i in range(512)]
        result = await self.invoke()
        self.assertEqual(result["num_targets"], 512)
        self.assertEqual(result["cases"][0]["target"], "0x500000")
        self.assertEqual(result["cases"][-1]["target"], "0x5007FC")
        self.assertTrue(all(row["case_values"] is None for row in result["cases"]))
        self.assert_unknown(result)

    async def test_target_budget_rejects_in_both_registered_tools(self):
        self.program.references[0x401000] = [Reference(0x500000 + i * 4) for i in range(513)]
        for name in self.tools:
            with self.assertRaises(GhidraError) as caught:
                await self.invoke(name)
            self.assertEqual(caught.exception.error_type, "ResourceLimit")
            self.assertEqual(caught.exception.details["targets_observed"], 513)
            self.assertEqual(caught.exception.details["target_limit"], 512)

    async def test_provider_failure_cannot_become_empty_success(self):
        class BrokenReference(Reference):
            def getReferenceType(self):
                raise RuntimeError("independent fixture read failure")

        self.program.references[0x401000] = [BrokenReference(0x405100)]
        with self.assertRaisesRegex(RuntimeError, "independent fixture read failure"):
            await self.invoke()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
