# 本地网络仿真工具集

Windows 入口是项目根目录的 `一键网络仿真.bat`。只使用一份 WSL2 Debian，磁盘在 `runtime/network-lab/debian`；没有游戏副本、Docker或第三方Windows抓包驱动。WSL核心由微软官方安装器管理。

双击运行全部场景。也可以在 ReverseResearch 根目录运行：

```powershell
.\一键网络仿真.bat -ListProfiles
.\一键网络仿真.bat -Operation my-network-test-01 -Profiles latency,udp-blocked,double-nat
```

同一个 operation 不重复执行；已有结果在 `evidence/network-lab/<operation>/receipt.json`。失败时先查看该收据及 `state/network-lab/active.json`，不要换个编号重新运行仍未结束的测试。异常遗留的网络空间不会被下一轮盲目删除，也不会结束其他进程。

`profiles.json` 是可自定义的配置。每个场景可以设置双方独立的延迟、抖动、丢包、连续丢包模型、重复、乱序、带宽、MTU、固定随机seed，以及链路断续、NAT清表和端口变化事件。字段有数值边界；不接受任意shell规则。一个operation的多个场景共用六个网络空间和同一对echo进程，完成后删除自有网络空间、关闭自有进程。

拓扑为 A → NAT-A → 外层路由器/NAT → 仿真WAN → NAT-B → B。单层模式下外层节点只路由，双层模式下增加一次实际SNAT。所有veth均留在这些网络空间内，没有连接真实网卡。nftables、tc和sysctl只作用于准确匹配的自有namespace；主机防火墙和杀软设置不变。

自检使用独立UDP echo与TCP控制连接。记录实际成功写入/收到的报文、丢失、重复、乱序、RTT、内核qdisc/nft计数和conntrack映射；断网恢复使用同一socket。通用自检端口38552有专用DNAT，仅用来验证仿真流量确实经过规则，**不证明某个产品的打洞或中继能力**。单层SNAT也不自动等于full-cone；以具体规则和实际映射为准。

项目程序应接入 `network_lab.py` 的 `Lab` API，在相同namespace中执行原程序，单独记录产品候选hash、原协议路径和结果。Linux内核实验不能代替Windows/WFP/真实杀软兼容测试、物理路由器和公网跨网验收。普通UDP断网后丢失的数据不会由本工具自动补传。

NAT模式需要明确记录。默认原生Linux SNAT可能在换目标时分配另一个端口，不能把它称作endpoint-independent NAT。`Lab.observe_udp_endpoint`只读取自有真实出站flow；`Lab.admit_observed_udp_endpoint`可据此建立成对、有期限的DNAT/SNAT map，显式模拟不随目标改变的映射。地址和端口必须来自实际conntrack，不预置产品端口转发。接纳新模型时只清理自有router的旧conntrack，清表或端口变化也同时退休两张map；每场景清理自有WAN状态，避免上一场景残留。收据保留模式、原flow、实际内核map及期限。这是可控的实验室模型，物理路由器和完整自动NAT行为仍需另验。

H3Net的适配器留在H3源码仓库的 `H3Net/research/complete4-network-20261007/run_agent_kernel_network.py`；复用同一实验室和一份测试程序，不在此工具集复制游戏或产品模块。

安装脚本为 `setup_wsl_lab.py`，只经微软WSL安装器安装核心/单一Debian，并通过Windows注册表准确绑定Debian路径及WSL2版本。只装Python、iproute2、nftables、conntrack和ping等必要依赖。安装与执行有独立收据，不自动重启。

参考原文：[Microsoft WSL](https://learn.microsoft.com/en-us/windows/wsl/install)、[ip-netns](https://www.man7.org/linux/man-pages/man8/ip-netns.8.html)、[netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html)、[nftables](https://netfilter.org/projects/nftables/manpage.html)。clumsy/WinDivert可另用于Windows实际程序故障；其[原手册](https://jagt.github.io/clumsy/manual.html)明确说明不能按进程过滤，回环还可能重复处理，因此本工具没有安装该驱动。
