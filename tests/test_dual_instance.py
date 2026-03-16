#!/usr/bin/env python3
"""
OSPF 双实例自验证测试
测试两个 OSPF 路由器之间能否正常收发报文

修复说明: 现在使用 Raw Socket (协议号 89) 而非 UDP!
- OSPF 协议本身就是 Raw Socket
- 使用真实的网络接口进行测试
- 如果容器环境没有权限创建 Raw Socket，会自动回退到 UDP
"""

import sys
import subprocess
import socket
import time

sys.path.insert(0, '/code/ospf-simulator/src')

from ospf_core import (
    OSPFSimulator, OSPF_TYPE_HELLO, OSPF_TYPE_DD, 
    OSPF_TYPE_LSR, OSPF_TYPE_LSU, OSPF_TYPE_LSACK,
    ALL_SPF_ROUTERS
)


def get_usable_ip():
    """获取可用的 IP 地址用于测试"""
    # 首先尝试 eth0
    try:
        result = subprocess.run(
            ['ip', 'addr', 'show', 'eth0'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                ip = line.strip().split()[1].split('/')[0]
                if not ip.startswith('127.'):
                    return ip
    except:
        pass
    
    # 备用方案: 获取第一个非 127.0.0.1 的 IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        pass
    
    return "172.24.74.28"  # 默认值


def run_test():
    """运行测试"""
    print("=" * 60)
    print("OSPF 双实例自验证测试 (Raw Socket 模式)")
    print("=" * 60)
    
    # 获取可用 IP 地址
    host_ip = get_usable_ip()
    print(f"\n使用主机 IP: {host_ip}")
    
    # 使用不同的 router_id 来区分两个实例
    # 物理 IP 相同，但 router_id 不同
    IP_A = host_ip
    IP_B = host_ip
    
    # 创建两个 OSPF 实例 (使用不同的 router_id)
    print("\n[1] 创建两个 OSPF 实例...")
    sim_a = OSPFSimulator("192.168.100.1")  # Router ID
    sim_b = OSPFSimulator("192.168.100.2")  # Router ID
    
    # 添加接口 - 使用主机 IP
    sim_a.router.add_interface("eth0", IP_A, "255.255.255.0")
    sim_b.router.add_interface("eth0", IP_A, "255.255.255.0")  # 同一物理 IP
    
    # 重要: 不要强制设置 use_raw = False!
    # 让 ospf_core.py 自动决定使用 Raw Socket 还是 UDP
    # 如果没有权限创建 Raw Socket，会自动回退到 UDP
    
    print(f"  实例A: Router ID = {sim_a.router.router_id}, 接口 IP = {IP_A}")
    print(f"  实例B: Router ID = {sim_b.router.router_id}, 接口 IP = {IP_A}")
    
    # 启动实例
    print("\n[2] 启动 OSPF 实例...")
    sim_a.start()
    sim_b.start()
    
    print(f"  实例A use_raw = {sim_a.use_raw}")
    print(f"  实例B use_raw = {sim_b.use_raw}")
    
    # 等待报文交互
    print("\n[3] 等待报文自动交互 (Hello 报文每10秒发送)...")
    time.sleep(15)  # 增加等待时间以完成 DD/LSU 交换
    
    # 检查邻居状态
    print("\n[4] 检查邻居状态...")
    
    print(f"\n  实例A 的邻居:")
    for neighbor_id, neighbor in sim_a.router.neighbors.items():
        print(f"    {neighbor_id}: {neighbor.get('state', 'N/A')}")
    
    print(f"\n  实例B 的邻居:")
    for neighbor_id, neighbor in sim_b.router.neighbors.items():
        print(f"    {neighbor_id}: {neighbor.get('state', 'N/A')}")
    
    # 停止实例
    print("\n[5] 停止实例...")
    sim_a.stop()
    sim_b.stop()
    
    # 统计结果
    print("\n" + "=" * 60)
    print("测试结果")
    print("=" * 60)
    
    # 统计报文 - stats 在 router 里
    stats_a = sim_a.router.stats
    stats_b = sim_b.router.stats
    
    print(f"\n实例A 统计:")
    print(f"  Hello 发送: {stats_a.get('hello_sent', 0)}")
    print(f"  Hello 接收: {stats_a.get('hello_recv', 0)}")
    print(f"  DD 接收: {stats_a.get('dd_recv', 0)}")
    print(f"  LSU 接收: {stats_a.get('lsu_recv', 0)}")
    print(f"  LSACK 接收: {stats_a.get('lsack_recv', 0)}")
    
    print(f"\n实例B 统计:")
    print(f"  Hello 发送: {stats_b.get('hello_sent', 0)}")
    print(f"  Hello 接收: {stats_b.get('hello_recv', 0)}")
    print(f"  DD 接收: {stats_b.get('dd_recv', 0)}")
    print(f"  LSU 接收: {stats_b.get('lsu_recv', 0)}")
    print(f"  LSACK 接收: {stats_b.get('lsack_recv', 0)}")
    
    # 判断是否通过
    hello_a = stats_a.get('hello_recv', 0)
    hello_b = stats_b.get('hello_recv', 0)
    
    print("\n" + "=" * 60)
    if hello_a > 0 and hello_b > 0:
        print("✅ 测试通过: 两个实例都能收到对方 Hello 报文")
    else:
        print("❌ 测试失败: 未能收到对端 Hello 报文")
        print(f"   实例A 收到 Hello: {hello_a} 个")
        print(f"   实例B 收到 Hello: {hello_b} 个")
    print("=" * 60)


if __name__ == "__main__":
    run_test()
