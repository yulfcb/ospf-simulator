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

---

## OSPF 报文格式详解 (RFC 2328)

### 一、OSPF头部 (24字节，所有报文共用)

| 字段 | 长度 | 说明 |
|------|------|------|
| Version | 1 | OSPF版本 (2) |
| Type | 1 | 报文类型 (1-5) |
| Packet Length | 2 | 报文总长度 |
| Router ID | 4 | 路由器ID |
| Area ID | 4 | 区域ID |
| Checksum | 2 | 校验和 |
| Auth Type | 2 | 认证类型 |
| Authentication | 8 | 认证数据 |

### 二、Hello报文 (Type=1) - 20字节 + N*4

| 字段 | 长度 | 说明 |
|------|------|------|
| Network Mask | 4 | 网络掩码 |
| Hello Interval | 2 | Hello间隔 (10秒) |
| Options | 1 | 选项 |
| Priority | 1 | 路由器优先级 |
| Dead Interval | 4 | 邻居失效时间 |
| DR | 4 | 指定路由器 |
| BDR | 4 | 备份指定路由器 |
| Neighbor List | N*4 | 邻居列表 (每个4字节) |

### 三、DD报文 (Database Description, Type=2) - 8字节 + N*20

| 字段 | 长度 | 说明 |
|------|------|------|
| Interface MTU | 2 | 接口MTU |
| Options | 1 | 选项 |
| Flags | 1 | 标志位 |
| DD Sequence | 4 | DD序列号 |
| LSA Headers | N*20 | LSA头部列表 |

**Flags 位含义：**
- I (Initial): 首个DD (bit 3 = 0x04)
- M (More): 还有更多 (bit 2 = 0x02)
- MS (Master/Slave): 主从 (bit 1 = 0x01)

### 四、LSR报文 (Link State Request, Type=3) - 12字节

| 字段 | 长度 | 说明 |
|------|------|------|
| LS Type | 4 | LSA类型 |
| Link State ID | 4 | LSA ID |
| Advertising Router | 4 | 通告路由器 |

### 五、LSU报文 (Link State Update, Type=4) - 4字节 + N*可变

| 字段 | 长度 | 说明 |
|------|------|------|
| # LSAs | 4 | LSA数量 |
| LSA #1 | 可变 | LSA (头部20字节 + 身体) |
| LSA #2 | 可变 | ... |

**LSA头部 (每个LSA前20字节)：**
| 字段 | 长度 | 说明 |
|------|------|------|
| LS Age | 2 | LSA年龄 |
| Options | 1 | 选项 |
| LS Type | 1 | LSA类型 |
| Link State ID | 4 | LSA ID |
| Adv Router | 4 | 通告路由器 |
| LS Sequence | 4 | 序列号 |
| Checksum | 2 | 校验和 |
| Length | 2 | 长度 |

### 六、LSAck报文 (Link State Acknowledge, Type=5) - N*20

| 字段 | 长度 | 说明 |
|------|------|------|
| LSA Headers | N*20 | LSA头部列表 |

