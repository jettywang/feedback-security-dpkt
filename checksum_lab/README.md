# dpkt 被动流量完整性校验和实验

面向被动抓包场景的校验和验证实验。所有判定都针对 **pcap 中的原始抓包字节**，
独立参考实现作为唯一判据，并验证验证过程不修改报文对象与原字节。

## 为什么不能先序列化

dpkt 的序列化器会“补算”校验和，直接销毁取证证据：

- `dpkt/ip.py` 的 `IP.__bytes__`：当 `ip.sum == 0` 时重算 IPv4 头校验和，
  并在非分片、`data.sum == 0` 时连带重算 TCP/UDP 校验和（UDP 计算为 0 时
  按 RFC 768 写成 `0xffff`）。
- `dpkt/ip6.py` 的 `IP6.__bytes__`：IPv6 无头校验和，因此只要 L4 `sum == 0`
  就无条件重算 TCP/UDP/ICMPv6 校验和。

因此本实验在调用 `verify_packet()` 的路径上**从不调用** `bytes(pkt)`、
`pkt.pack_hdr()` 等。`test_verifier_does_not_call_serializer` 用 monkeypatch
把两个 `__bytes__` 替换为抛错，强制保证这一点。
`python -m checksum_lab.offload_demo` 直观展示一个双零 TSO 帧在 `bytes()`
前后从“无校验和”变成伪造的 `valid`。

## 模块

- `reference.py`：独立 RFC 1071 实现，只用标准库 `struct`，与 dpkt 无共享代码；
  含 IPv4/IPv6 伪首部构造与奇数长度尾部字节的高位填充。
- `verifier.py`：只读验证器。用 `struct` 从原始切片读取长度/偏移/校验和字段，
  dpkt 仅用于协议分派与对象快照比对；返回分层 `ChecksumVerdict`。
- `corpus.py`：确定性语料，手工 `struct` 组包、用参考实现算校验和，写 pcap。
- `run_experiment.py`：pcap → 原始帧 → 剥以太网 → 验证 → 断言 → JSON/表格报告。
- `alerting.py`：告警后端分类策略。
- `offload_demo.py`：序列化伪造校验和的反例演示。
- `test_checksum_lab.py`：41 个 pytest 用例。

## 复跑方式

```bash
# 端到端实验，生成 pcap + JSON + 控制台表格，失败时退出码非 0
python -m checksum_lab.run_experiment

# 序列化陷阱演示
python -m checksum_lab.offload_demo

# 测试（仓库 setup.cfg 带了未安装的 --cov 选项，故覆盖 addopts）
python -m pytest checksum_lab/ -o addopts="" -q
```

产物：`checksum_lab/output/checksum_corpus.pcap`、
`checksum_lab/output/checksum_report.json`。

## 判定语义（四层，互斥）

| verdict | 含义 | 字节依据 | 后端处置 |
|---|---|---|---|
| `valid` | 完整字节齐备，独立重算值 == 线上存储值 | 全部覆盖字节在场 | pass（唯一可作正向证据）|
| `mismatch` | 完整字节齐备，但重算值 != 存储值 | 全部覆盖字节在场 | high / alert |
| `inconclusive` | 抓包截断、字段不全、声明长度 > 实际捕获长度 | 字节不足 | info / 隔离证据，**不得**告警也不得放行 |
| `not_present` | 校验和字段为 0：发送方禁用或卸载，未产生校验和 | 字段在场但无校验值 | info / 无完整性声明 |

关键纪律：`not_present`、零值、`inconclusive` 永远不会并入“通过”。
`valid` 必须同时满足 `stored == computed`、`computed is not None`、
`truncated is False` 且校验和覆盖的每个字节都在抓包中。

## 哪些能判不匹配，哪些只能证据不足

**能明确判 `mismatch`（字节完整）**

- 任意 TCP/UDP 负载或首部单字节损坏：传输层校验和失配。
- IPv4 首部字节损坏（如 TTL）：IPv4 头校验和失配，传输层可能仍 valid。
- IPv6 地址损坏：IPv6 无头校验和，但伪首部使 TCP/UDP 校验和失配。
- 前提是 IP 长度字段声明的全部字节都在抓包里。

**只能判 `inconclusive`（证据不足）**

- snap 截断落在 TCP/UDP 首部，校验和字段本身缺失。
- 截断落在负载区：首部完整，但 IP 总长度/IPv6 净荷长度 > 实际捕获长度；
  此时若拿“残缺段的实际长度”去凑伪首部会错误地报 mismatch，本验证器
  按声明长度识别为字节不足。
- 数据报无法解析（版本/IHL/data offset 非法）。

**判 `not_present`（无完整性声明，而非通过）**

- IPv4/UDP 校验和为 0：RFC 768 允许发送方禁用，属于“无校验和”，不是通过。
- TCP 校验和为 0，或 IPv6/UDP 校验和为 0（RFC 8200 本应禁止，常见于卸载）。
- IPv4 头校验和为 0（合法头校验和若算得 0 应存 `0xffff`，故 0 只能表示未计算）。

## 校验和卸载的影响（单独说明）

抓包点决定现象，必须区分两种线上形态：

1. **仅 L4 校验和为 0（NIC L4 卸载）**：IPv4 头校验和仍真实有效。
   样本 `offload_l4zero_tcp_v4` → `ipv4=valid, tcp=not_present`，
   后端为 `partial_pass`（仅头层有证据，不能宣称端到端完整）。
2. **IPv4 头与 L4 校验和双零（本机 TSO/GSO 分段抓包）**：
   样本 `offload_tso_tcp_v4` / `offload_tso_udp_v4` → 两层均 `not_present`，
   后端 `no_evidence`。
   dpkt 仅在这种 `ip.sum==0` 形态下才会连带重算 L4；IPv6 因无头校验和，
   对任何零 L4 校验和都会重算。

运营含义：

- 这些帧在网卡出线缆前会被硬件填入正确校验和，被动看到的 0 不代表线上损坏，
  因此不能告 `mismatch`；但它们同样没有任何完整性证据，不能计 `valid`。
- 若同一捕获点大量出现零校验和，应作为“捕获点位于卸载上游/主机本地”的
  拓扑信号，而不是入侵信号；可在后端按来源接口打标并排除出完整性 SLA。
- 想对这类流量获得完整性保证，需要在卸载**下游**（线缆侧、镜像口、对端主机）采集。

## 语料覆盖（24 个构造样本，23 个唯一 pcap 帧）

- IPv4/IPv6 × TCP/UDP × 偶数/奇数长度合法样本（8 个，全部 valid）。
- 单字节损坏 6 个（负载、IPv4 TTL、IPv6 源地址），全部 mismatch。
- 缺尾截断 3 个（TCP 首部内、IPv6 负载内、IPv4 负载内），全部 inconclusive。
- IPv4/UDP 零校验和 1 个（RFC 768 禁用）。
- 卸载形态 5 个 + 序列化陷阱对照 1 个。

每个样本带 `expect`/`expect_layers` 预期，`run_experiment` 会逐帧断言，
任一不符即以非零退出码失败。
