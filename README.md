# OSPF 仿真器

基于 RFC 2328 的 OSPF 协议仿真实现。

## OSPF邻居协商与LSA交换流程

### 一、邻居状态机

```
        +---------------------------+      +-----------------------------+
        |       Neighbor State      |      |        neighbor state       |
        +---------------------------+      +-----------------------------+
        |   Down                    | <-- | 这是初始状态，未收到Hello   |
        |   Attempt                 |     | 手动配置邻居 (NBMA网络)     |
        |   Init                    | <-- | 收到Hello，但未看到自己    |
        |   2-Way                   | <-- | Hello中看到自己，邻居建立   |
        |   ExStart                 | <-- | 协商Master/Slave，开始DD   |
        |   Exchange                | <-- | 交换DD报文                 |
        |   Loading                 | <-- | LSR请求 + LSU响应          |
        |   Full                    | <-- | LSA同步完成，邻接形成       |
        +---------------------------+      +-----------------------------+
```

### 二、完整协商流程

```
Router A                              Router B
  |                                     |
  |------- Hello (224.0.0.5) -------->|  1. Down -> Init
  |<------ Hello (224.0.0.5) ---------|  2. 收到Hello，看到A
  |                                     |
  |<------ Hello (包含B的neighbor) ----|  3. Init -> 2-Way
  |------- Hello (包含B的neighbor) -->|  4. 双向确认，2-Way
  |                                     |
  |------- DD (I=1,M=1,MS=1) -------->|  5. ExStart: 初始DD
  |<------ DD (I=1,M=1,MS=1) ---------|  6. 双方MS=1，选举Master
  |                                     |
  |<------ DD (MS=0, seq=X) ----------|  7. Exchange: Master确定
  |------- DD (MS=1, seq=X) --------->|  8. Slave使用Master的seq
  |       (继续交换DD)                 |
  |                                     |
  |------- LSR (请求LSA) ------------->|  9. Loading: 请求缺失LSA
  |<------ LSU (包含LSA) --------------|  10. 响应LSR
  |------- LSAck (确认) -------------->|  11. 确认收到LSU
  |                                     |
  |<------ LSR (请求LSA) --------------|
  |------- LSU (包含LSA) -------------->|
  |<------ LSAck (确认) ---------------|
  |                                     |
  |====== LSDB同步完成 ================>|  12. Full: 邻接建立
  |====== 路由计算 ===================>|  13. SPF计算生成路由
```

### 三、报文类型与作用

| 类型 | 名称 | 作用 |
|------|------|------|
| 1 | Hello | 发现邻居，保持邻居关系，选举DR/BDR |
| 2 | DD (Database Description) | 描述LSDB摘要，协商主从 |
| 3 | LSR (Link State Request) | 请求特定LSA |
| 4 | LSU (Link State Update) | 发送LSA副本 |
| 5 | LSAck (Link State Ack) | 确认收到LSU |

### 四、关键机制

1. **DD协商 (ExStart -> Exchange)**
   - 初始DD: I=1(首个), M=1(更多), MS=1(声称Master)
   - Router ID大的成为Master，序列号由Master控制

2. **LSA扩散 (Flooding)**
   - LSU发送LSA
   - 收到LSU后更新LSDB，回复LSAck
   - LSA有序列号、age、checksum防重复

3. **邻接形成条件**
   - 2-Way后交换DD
   - DD/LSR/LSU/LSAck交互完成
   - LSDB同步后进入Full状态

## 运行测试

```bash
cd /code/ospf-simulator
python3 tests/test_ospf.py
python3 tests/test_ospf_rfc_flow.py
```
