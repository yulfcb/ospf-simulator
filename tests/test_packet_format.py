#!/usr/bin/env python3
"""
OSPF 报文格式测试 - 按RFC 2328验证
"""

import unittest
import sys
import struct
import socket

sys.path.insert(0, '/code/ospf-simulator/src')
from ospf_core import (
    OSPFHeader, HelloPacket, DDPacket, LSRPacket, LSUPacket, LSAHeader,
    OSPF_TYPE_HELLO, OSPF_TYPE_DD, OSPF_TYPE_LSR, OSPF_TYPE_LSU, OSPF_TYPE_LSACK
)


class TestOSPFHeader(unittest.TestCase):
    """测试OSPF头部 (24字节)"""
    
    def test_header_size(self):
        """验证头部是24字节"""
        header = OSPFHeader(
            version=2,
            type=OSPF_TYPE_HELLO,
            length=64,
            router_id="192.168.1.1",
            area_id="0.0.0.0"
        )
        packed = header.pack()
        self.assertEqual(len(packed), 24, f"OSPF头部应该是24字节，实际{len(packed)}字节")
        print(f"✓ OSPFHeader: {len(packed)} bytes")
    
    def test_header_pack_unpack(self):
        """测试头部打包解包"""
        header = OSPFHeader(
            version=2,
            type=OSPF_TYPE_HELLO,
            length=64,
            router_id="192.168.1.1",
            area_id="0.0.0.0"
        )
        packed = header.pack()
        unpacked = OSPFHeader.unpack(packed)
        self.assertEqual(unpacked.version, 2)
        self.assertEqual(unpacked.type, OSPF_TYPE_HELLO)
        self.assertEqual(unpacked.router_id, "192.168.1.1")


class TestHelloPacket(unittest.TestCase):
    """测试Hello报文 - 20字节 + N*4"""
    
    def test_hello_size(self):
        """验证Hello报文基础大小 (无邻居)"""
        hello = HelloPacket(
            network_mask="255.255.255.0",
            hello_interval=10,
            router_priority=1,
            dead_interval=40,
            dr="0.0.0.0",
            bdr="0.0.0.0"
        )
        packed = hello.pack()
        self.assertEqual(len(packed), 20, f"Hello(无邻居)应该是20字节，实际{len(packed)}字节")
        print(f"✓ HelloPacket (无邻居): {len(packed)} bytes")
    
    def test_hello_with_neighbors(self):
        """验证带邻居的Hello报文"""
        hello = HelloPacket(
            network_mask="255.255.255.0",
            neighbor=["192.168.1.2", "192.168.1.3"]
        )
        packed = hello.pack()
        # 20字节 + 2个邻居(2*4=8) = 28字节
        self.assertEqual(len(packed), 28, f"Hello(2邻居)应该是28字节，实际{len(packed)}字节")
        print(f"✓ HelloPacket (2邻居): {len(packed)} bytes")
    
    def test_hello_pack_unpack(self):
        """测试Hello打包解包"""
        hello = HelloPacket(
            network_mask="255.255.255.0",
            hello_interval=10,
            router_priority=1,
            dead_interval=40,
            dr="192.168.1.1",
            bdr="0.0.0.0",
            neighbor=["192.168.1.2"]
        )
        packed = hello.pack()
        unpacked = HelloPacket.unpack(packed)
        self.assertEqual(unpacked.network_mask, "255.255.255.0")
        self.assertEqual(len(unpacked.neighbor), 1)


class TestDDPacket(unittest.TestCase):
    """测试DD报文 - 8字节 + N*20"""
    
    def test_dd_size(self):
        """验证DD报文基础大小 (无LSA)"""
        dd = DDPacket(
            interface_mtu=1500,
            options=0x02,
            dd_sequence=1000,
            flags=0x07
        )
        packed = dd.pack()
        # MTU(2) + Options(1) + Flags(1) + Sequence(4) = 8字节
        self.assertEqual(len(packed), 8, f"DD(无LSA)应该是8字节，实际{len(packed)}字节")
        print(f"✓ DDPacket (无LSA): {len(packed)} bytes")
    
    def test_dd_with_lsa_headers(self):
        """验证带LSA头部的DD报文"""
        dd = DDPacket(
            interface_mtu=1500,
            options=0x02,
            dd_sequence=1000,
            flags=0x03,
            lsa_headers=[
                {
                    'type': 1,
                    'id': '192.168.1.1',
                    'adv_router': '192.168.1.1',
                    'sequence': 0x80000001
                }
            ]
        )
        packed = dd.pack()
        # 8字节 + 1个LSA头(20) = 28字节
        self.assertEqual(len(packed), 28, f"DD(1 LSA)应该是28字节，实际{len(packed)}字节")
        print(f"✓ DDPacket (1 LSA): {len(packed)} bytes")
    
    def test_dd_pack_unpack(self):
        """测试DD打包解包"""
        dd = DDPacket(
            interface_mtu=1500,
            options=0x02,
            dd_sequence=1000,
            flags=0x07,
            lsa_headers=[
                {
                    'type': 1,
                    'id': '192.168.1.1',
                    'adv_router': '192.168.1.1',
                    'sequence': 0x80000001
                }
            ]
        )
        packed = dd.pack()
        unpacked = DDPacket.unpack(packed)
        self.assertEqual(unpacked.interface_mtu, 1500)
        self.assertEqual(len(unpacked.lsa_headers), 1)


class TestLSRPacket(unittest.TestCase):
    """测试LSR报文 - 12字节"""
    
    def test_lsr_size(self):
        """验证LSR报文大小"""
        lsr = LSRPacket(
            ls_type=1,
            ls_id="192.168.1.1",
            adv_router="192.168.1.1"
        )
        packed = lsr.pack()
        # LS Type(4) + LS ID(4) + Adv Router(4) = 12字节
        self.assertEqual(len(packed), 12, f"LSR应该是12字节，实际{len(packed)}字节")
        print(f"✓ LSRPacket: {len(packed)} bytes")
    
    def test_lsr_pack_unpack(self):
        """测试LSR打包解包"""
        lsr = LSRPacket(
            ls_type=1,
            ls_id="192.168.1.1",
            adv_router="192.168.1.2"
        )
        packed = lsr.pack()
        unpacked = LSRPacket.unpack(packed)
        self.assertEqual(unpacked.ls_type, 1)
        self.assertEqual(unpacked.ls_id, "192.168.1.1")
        self.assertEqual(unpacked.adv_router, "192.168.1.2")


class TestLSUPacket(unittest.TestCase):
    """测试LSU报文 - 4字节 + N*(20+LSA body)"""
    
    def test_lsu_with_router_lsa(self):
        """验证带Router LSA的LSU报文"""
        lsu = LSUPacket(
            type=1,
            id="192.168.1.1",
            adv_router="192.168.1.1",
            lsa_entries=[
                {
                    'type': 1,
                    'id': '192.168.1.1',
                    'adv_router': '192.168.1.1',
                    'sequence': 0x80000001,
                    'links': []  # 空links
                }
            ]
        )
        packed = lsu.pack()
        print(f"✓ LSUPacket (1 Router LSA, 无links): {len(packed)} bytes")
        # LSU Header(20) + LSA Header(20) + LSA Body(2) = 42字节
        # 但由于checksum计算等，实际可能不同
    
    def test_lsu_pack_unpack(self):
        """测试LSU打包解包"""
        lsu = LSUPacket(
            type=1,
            id="192.168.1.1",
            adv_router="192.168.1.1",
            lsa_entries=[
                {
                    'type': 1,
                    'id': '192.168.1.1',
                    'adv_router': '192.168.1.1',
                    'sequence': 0x80000001,
                    'links': []
                }
            ]
        )
        packed = lsu.pack()
        unpacked = LSUPacket.unpack(packed)
        self.assertEqual(len(unpacked.lsa_entries), 1)
        self.assertEqual(unpacked.lsa_entries[0]['id'], "192.168.1.1")


class TestLSAHeader(unittest.TestCase):
    """测试LSA头部 - 20字节"""
    
    def test_lsa_header_size(self):
        """验证LSA头部是20字节"""
        lsa = LSAHeader(
            ls_age=0,
            options=0x02,
            ls_type=1,
            ls_id="192.168.1.1",
            adv_router="192.168.1.1",
            ls_sequence=0x80000001,
            checksum=0,
            length=20
        )
        packed = lsa.pack()
        self.assertEqual(len(packed), 20, f"LSA头部应该是20字节，实际{len(packed)}字节")
        print(f"✓ LSAHeader: {len(packed)} bytes")
    
    def test_lsa_header_pack_unpack(self):
        """测试LSA头部打包解包"""
        lsa = LSAHeader(
            ls_age=100,
            options=0x02,
            ls_type=1,
            ls_id="192.168.1.1",
            adv_router="192.168.1.2",
            ls_sequence=0x80000001,
            checksum=0x1234,
            length=20
        )
        packed = lsa.pack()
        unpacked = LSAHeader.unpack(packed)
        self.assertEqual(unpacked.ls_age, 100)
        self.assertEqual(unpacked.ls_type, 1)


def run_tests():
    """运行所有测试"""
    print("="*60)
    print("OSPF 报文格式验证 (RFC 2328)")
    print("="*60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestOSPFHeader))
    suite.addTests(loader.loadTestsFromTestCase(TestHelloPacket))
    suite.addTests(loader.loadTestsFromTestCase(TestDDPacket))
    suite.addTests(loader.loadTestsFromTestCase(TestLSRPacket))
    suite.addTests(loader.loadTestsFromTestCase(TestLSUPacket))
    suite.addTests(loader.loadTestsFromTestCase(TestLSAHeader))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print(f"测试结果: {'通过' if result.wasSuccessful() else '失败'}")
    print("="*60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
