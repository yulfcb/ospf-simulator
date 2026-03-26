#!/usr/bin/env python3
"""
OSPF 模拟器 - 测试套件
"""

import unittest
import sys
import struct
import socket
import threading
import time

sys.path.insert(0, '/work/ospf_sim/src')
from ospf_core import (
    OSPFHeader, HelloPacket, DDPacket, LSRPacket, LSUPacket,
    OSPFRouter, OSPFSimulator, NeighborState,
    OSPF_TYPE_HELLO, OSPF_TYPE_DD, OSPF_TYPE_LSR, OSPF_TYPE_LSU, OSPF_TYPE_LSACK
)


class TestOSPFHeader(unittest.TestCase):
    """测试 OSPF 头部"""
    
    def test_pack_unpack(self):
        """测试打包解包"""
        header = OSPFHeader(
            version=2,
            type=1,
            length=48,
            router_id="192.168.1.1",
            area_id="0.0.0.0"
        )
        
        packed = header.pack()
        self.assertEqual(len(packed), 24)
        
        unpacked = OSPFHeader.unpack(packed)
        self.assertEqual(unpacked.version, 2)
        self.assertEqual(unpacked.type, 1)
        self.assertEqual(unpacked.router_id, "192.168.1.1")


class TestHelloPacket(unittest.TestCase):
    """测试 Hello 报文"""
    
    def test_pack_unpack(self):
        """测试 Hello 报文打包解包"""
        hello = HelloPacket(
            network_mask="255.255.255.0",
            hello_interval=10,
            router_priority=1,
            dead_interval=40
        )
        
        packed = hello.pack()
        self.assertGreater(len(packed), 0)
        
        unpacked = HelloPacket.unpack(packed)
        self.assertEqual(unpacked.network_mask, "255.255.255.0")
        self.assertEqual(unpacked.hello_interval, 10)


class TestOSPFRouter(unittest.TestCase):
    """测试 OSPF 路由器"""
    
    def setUp(self):
        """设置测试"""
        self.router = OSPFRouter("192.168.1.1", "0.0.0.0")
    
    def test_add_interface(self):
        """测试添加接口"""
        self.router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
        self.assertIn("eth0", self.router.interfaces)
        self.assertEqual(self.router.interfaces["eth0"]["ip"], "192.168.1.1")
    
    def test_add_static_route(self):
        """测试添加静态路由"""
        self.router.add_static_route("10.0.0.0", "255.255.255.0", "192.168.1.2")
        self.assertIn("10.0.0.0-255.255.255.0", self.router.routes)
    
    def test_generate_routes(self):
        """测试批量生成路由"""
        routes = self.router.generate_routes("10.0.0.0", 5)
        self.assertEqual(len(routes), 5)
        self.assertGreater(len(self.router.routes), 0)
    
    def test_generate_routes_different_networks(self):
        """测试批量生成路由生成不同网段"""
        routes = self.router.generate_routes("10.0.0.0", 5)
        
        # 验证生成的路由是不同网段
        # 应该是: 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24, 10.0.4.0/24
        network_parts = [r.split('/')[0] for r in routes]
        expected_networks = ["10.0.0.0", "10.0.1.0", "10.0.2.0", "10.0.3.0", "10.0.4.0"]
        
        for expected in expected_networks:
            self.assertIn(expected, network_parts, f"Expected network {expected} not found")
        
        # 验证所有网络都是唯一的
        self.assertEqual(len(set(network_parts)), 5, "Generated networks should be unique")
    
    def test_remove_static_route(self):
        """测试删除静态路由"""
        # 先添加路由
        self.router.add_static_route("10.0.0.0", "255.255.255.0", "192.168.1.2")
        self.assertIn("10.0.0.0-255.255.255.0", self.router.routes)
        
        # 删除路由
        self.router.remove_static_route("10.0.0.0", "255.255.255.0")
        
        # 验证路由已删除
        self.assertNotIn("10.0.0.0-255.255.255.0", self.router.routes)
    
    def test_remove_nonexistent_route(self):
        """测试删除不存在的路由"""
        # 不应该报错
        self.router.remove_static_route("192.168.100.0", "255.255.255.0")
        # 验证没有添加任何路由
        self.assertEqual(len(self.router.routes), 0)
    
    def test_get_status(self):
        """测试获取状态"""
        status = self.router.get_status()
        self.assertEqual(status['router_id'], "192.168.1.1")
        self.assertEqual(status['area_id'], "0.0.0.0")
        self.assertEqual(status['interfaces'], 0)


class TestOSPFSimulator(unittest.TestCase):
    """测试 OSPF 模拟器"""
    
    def setUp(self):
        """设置测试"""
        self.sim = OSPFSimulator("192.168.1.1")
    
    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.sim.router.router_id, "192.168.1.1")
        self.assertIsNone(self.sim.sock)
        self.assertFalse(self.sim.running)


class TestPacketProcessing(unittest.TestCase):
    """测试报文处理"""
    
    def setUp(self):
        """设置测试"""
        self.router = OSPFRouter("192.168.1.1")
        self.router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    
    def test_hello_processing(self):
        """测试 Hello 报文处理"""
        hello = HelloPacket(
            network_mask="255.255.255.0"
        )
        
        header = OSPFHeader(
            type=OSPF_TYPE_HELLO,
            length=24 + len(hello.pack()),
            router_id="192.168.1.2",  # 使用不同的 router_id
            area_id="0.0.0.0"
        )
        
        packet = header.pack() + hello.pack()
        self.router.process_packet(packet, "192.168.1.2")
        
        # 检查邻居是否建立
        self.assertIn("192.168.1.2", self.router.neighbors)


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def test_two_routers(self):
        """测试两台路由器"""
        # 创建两台路由器
        router1 = OSPFRouter("192.168.1.1")
        router2 = OSPFRouter("192.168.1.2")
        
        router1.add_interface("eth0", "192.168.1.1", "255.255.255.0")
        router2.add_interface("eth0", "192.168.1.2", "255.255.255.0")
        
        # 模拟 Hello 报文交换
        hello = HelloPacket(network_mask="255.255.255.0")
        header = OSPFHeader(type=OSPF_TYPE_HELLO, length=24+len(hello.pack()), router_id="192.168.1.1")
        
        router2.process_packet(header.pack() + hello.pack(), "192.168.1.1")
        
        # 检查邻居
        self.assertIn("192.168.1.1", router2.neighbors)


def run_tests():
    """运行测试"""
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加测试
    suite.addTests(loader.loadTestsFromTestCase(TestOSPFHeader))
    suite.addTests(loader.loadTestsFromTestCase(TestHelloPacket))
    suite.addTests(loader.loadTestsFromTestCase(TestOSPFRouter))
    suite.addTests(loader.loadTestsFromTestCase(TestOSPFSimulator))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketProcessing))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
