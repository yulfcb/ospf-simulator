#!/usr/bin/env python3
"""
自验证测试: 确保批量生成静态路由在不同网段

测试目标:
1. 生成的10条路由必须在不同网段（不同network地址）
2. 生成的路由不能都在同一网段（如 10.0.x.x 或 192.168.x.x）
"""

import sys
import os

# 添加 src 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ospf_core import OSPFRouter


def get_network_prefix_16(network: str) -> str:
    """获取 /16 网段前缀 (如 10.0.0.0 -> 10.0)"""
    parts = network.split('.')
    return f"{parts[0]}.{parts[1]}"


def test_generate_routes_different_networks():
    """测试: 批量生成的路由必须在不同网段"""
    router = OSPFRouter("1.1.1.1", "0.0.0.0")
    
    # 生成 10 条路由
    routes = router.generate_diverse_routes("10.0.0.0", 10, 24)
    
    print(f"生成的路由数量: {len(routes)}")
    print(f"路由列表: {routes}")
    
    # 验证1: 生成的路由数量正确
    assert len(routes) == 10, f"期望生成10条路由，实际生成{len(routes)}条"
    
    # 验证2: 所有路由的网络地址必须不同
    network_addrs = set()
    for route in routes:
        # 解析 network/24 格式
        network = route.split('/')[0]
        network_addrs.add(network)
    
    print(f"\n网络地址集合: {network_addrs}")
    assert len(network_addrs) == 10, f"期望10个不同的网络地址，实际{len(network_addrs)}个"
    
    # 验证3: 路由不能在同一个/16网段
    prefixes_16 = set()
    for route in routes:
        network = route.split('/')[0]
        prefix_16 = get_network_prefix_16(network)
        prefixes_16.add(prefix_16)
    
    print(f"/16 网段前缀集合: {prefixes_16}")
    print(f"跨越的/16网段数量: {len(prefixes_16)}")
    
    # 10条路由应该跨越多个/16网段（至少5个）
    assert len(prefixes_16) >= 5, f"路由应跨越至少5个/16网段，实际跨越{len(prefixes_16)}个"
    
    print("\n✓ 所有测试通过!")
    return True


def test_route_not_in_same_subnet():
    """测试: 验证路由不会生成在同一/16下的不同/24"""
    router = OSPFRouter("2.2.2.2", "0.0.0.0")
    
    # 生成路由
    routes = router.generate_diverse_routes("10.0.0.0", 10, 24)
    
    # 检查不应该出现像 10.0.0.0/24 和 10.0.1.0/24 这样的组合
    # （同一/16下的不同/24）
    prefixes_16_map = {}
    for route in routes:
        network = route.split('/')[0]
        prefix_16 = get_network_prefix_16(network)
        if prefix_16 not in prefixes_16_map:
            prefixes_16_map[prefix_16] = []
        prefixes_16_map[prefix_16].append(network)
    
    # 检查每个/16前缀下不应该有多个/24
    for prefix, networks in prefixes_16_map.items():
        assert len(networks) <= 1, f"网段 {prefix} 下有多个/24子网: {networks}"
    
    print("✓ 路由不在同一/16网段下的多个/24子网")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("自验证测试: 确保批量生成静态路由在不同网段")
    print("=" * 60)
    
    test_generate_routes_different_networks()
    print()
    test_route_not_in_same_subnet()
    
    print("\n" + "=" * 60)
    print("所有验证测试通过!")
    print("=" * 60)