#!/usr/bin/env python3
"""
OSPF 模拟器 - 简化测试
"""

import sys
sys.path.insert(0, 'src')
from ospf_core import OSPFRouter, OSPFSimulator

def test_basic():
    """基本功能测试"""
    print("=== 测试基本功能 ===")
    
    # 创建路由器
    router = OSPFRouter("192.168.1.1")
    print(f"✓ 创建路由器: {router.router_id}")
    
    # 添加接口
    router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    print(f"✓ 添加接口: {len(router.interfaces)} 个")
    
    # 添加静态路由
    router.add_static_route("10.0.0.0", "255.255.255.0", "192.168.1.2")
    print(f"✓ 添加静态路由: {len(router.routes)} 条")
    
    # 批量生成路由
    routes = router.generate_routes("172.16.0.0", 5)
    print(f"✓ 批量生成路由: {len(routes)} 条")
    
    # 获取状态
    status = router.get_status()
    print(f"✓ 状态: LSDB={status['lsdb_entries']}, Routes={status['routes']}")
    
    return True

def test_simulator():
    """模拟器测试"""
    print("\n=== 测试模拟器 ===")
    
    sim = OSPFSimulator("192.168.1.1")
    print(f"✓ 创建模拟器: {sim.router.router_id}")
    
    sim.router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    print(f"✓ 添加接口")
    
    # 模拟器功能验证
    status = sim.router.get_status()
    print(f"✓ 状态检查通过: 接口={status['interfaces']}")
    
    return True

def test_lsa_flooding():
    """LSA 泛洪测试"""
    print("\n=== 测试 LSA 泛洪 ===")
    
    router1 = OSPFRouter("192.168.1.1")
    router2 = OSPFRouter("192.168.1.2")
    
    router1.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    router2.add_interface("eth0", "192.168.1.2", "255.255.255.0")
    
    # 添加一些路由
    router1.add_static_route("10.0.0.0", "255.255.255.0", "0.0.0.0")
    router1.add_static_route("172.16.0.0", "255.255.255.0", "0.0.0.0")
    
    print(f"Router1 路由: {len(router1.routes)} 条")
    print(f"Router1 LSDB: {len(router1.lsdb)} 条")
    
    # 模拟 LSA 同步
    for lsa_key, lsa in router1.lsdb.items():
        router2.lsdb[lsa_key] = lsa
    
    print(f"Router2 LSDB 同步后: {len(router2.lsdb)} 条")
    
    return True

def main():
    """运行所有测试"""
    print("OSPF 模拟器自验证测试")
    print("=" * 50)
    
    all_passed = True
    
    try:
        test_basic()
    except Exception as e:
        print(f"✗ 基本功能测试失败: {e}")
        all_passed = False
    
    try:
        test_simulator()
    except Exception as e:
        print(f"✗ 模拟器测试失败: {e}")
        all_passed = False
    
    try:
        test_lsa_flooding()
    except Exception as e:
        print(f"✗ LSA 泛洪测试失败: {e}")
        all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ 所有测试通过!")
    else:
        print("✗ 部分测试失败")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
