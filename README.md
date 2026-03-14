# OSPFv2 Simulator

OSPFv2 模拟器，支持完整的 LSA 类型包括外部 LSA (Type-5 AS-External-LSA)

## 功能特性

- **Router-LSA (Type-1)**: 路由器链路状态广告
- **Network-LSA (Type-2)**: 网络链路状态广告
- **Summary-LSA (Type-3)**: 汇总链路状态广告
- **ASBR-Summary-LSA (Type-4)**: ASBR 汇总链路状态广告
- **AS-External-LSA (Type-5)**: 外部路由广告

## 运行

```bash
python3 ospfv2_sim.py
```

## Type-5 LSA 说明

AS-External-LSA (Type-5) 由 AS Border Router (ASBR) 生成，用于向 OSPF 域内广告外部路由。

- **Metric Type 1 (E1)**: 总成本 = 外部成本 + 内部成本
- **Metric Type 2 (E2)**: 总成本 = 外部成本（默认）

## 示例输出

```
[OSPF] Router 1.1.1.1 added to simulation
[OSPF] Router 1.1.1.1 is an AS Border Router (ASBR)
[OSPF] ASBR Router 1.1.1.1 advertising external network 192.168.100.0/24

--- LSA Type 5 ---
  AS-External-LSA (Type-5): 192.168.100.0
    Mask: 255.255.255.0
    Metric: 20 (Type-2)
    Advertising Router: 1.1.1.1
```
