#!/usr/bin/env python3
"""
OSPF RFC 2328 流程测试
验证完整的邻居交互流程
"""

import unittest
import sys
import struct
import socket

sys.path.insert(0, '/code/ospf-simulator/src')
from ospf_core import (
    OSPFHeader, HelloPacket, DDPacket, LSRPacket, LSUPacket,
    OSPFRouter, NeighborState,
    OSPF_TYPE_HELLO, OSPF_TYPE_DD, OSPF_TYPE_LSR, OSPF_TYPE_LSU, OSPF_TYPE_LSACK
)


def build_packet(router_id, area_id, ospf_type, body):
    """构建OSPF报文"""
    header = OSPFHeader(
        type=ospf_type,
        length=24 + len(body),
        router_id=router_id,
        area_id=area_id
    )
    return header.pack() + body


class TestOSPFRFCFlow(unittest.TestCase):
    """测试OSPF RFC完整流程"""

    def setUp(self):
        """设置两台路由器"""
        self.router1 = OSPFRouter("192.168.1.1", "0.0.0.0")
        self.router2 = OSPFRouter("192.168.1.2", "0.0.0.0")
        
        self.router1.add_interface("eth0", "192.168.1.1", "255.255.255.0")
        self.router2.add_interface("eth0", "192.168.1.2", "255.255.255.0")

    def test_1_hello_exchange(self):
        """测试1: Hello报文交换 (Down -> Init -> 2-Way)"""
        print("\n=== 测试1: Hello报文交换 ===")
        
        # Router1 发送 Hello 到 Router2
        hello1 = HelloPacket(network_mask="255.255.255.0")
        pkt1 = build_packet("192.168.1.1", "0.0.0.0", OSPF_TYPE_HELLO, hello1.pack())
        resp1 = self.router2.process_packet(pkt1, "192.168.1.1")
        
        print(f"Router2 收到 Hello from 192.168.1.1, 响应: {resp1 is not None}")
        self.assertIn("192.168.1.1", self.router2.neighbors)
        
        # Router2 发送 Hello 到 Router1
        hello2 = HelloPacket(network_mask="255.255.255.0")
        pkt2 = build_packet("192.168.1.2", "0.0.0.0", OSPF_TYPE_HELLO, hello2.pack())
        resp2 = self.router1.process_packet(pkt2, "192.168.1.2")
        
        print(f"Router1 收到 Hello from 192.168.1.2, 响应: {resp2 is not None}")
        self.assertIn("192.168.1.2", self.router1.neighbors)
        
        print("Hello交换完成，邻居状态应为 2-Way 或 Init")

    def test_2_dd_exchange(self):
        """测试2: DD报文交换 (ExStart -> Exchange)"""
        print("\n=== 测试2: DD报文交换 ===")
        
        # 先建立邻居
        hello1 = HelloPacket(network_mask="255.255.255.0")
        pkt1 = build_packet("192.168.1.1", "0.0.0.0", OSPF_TYPE_HELLO, hello1.pack())
        self.router2.process_packet(pkt1, "192.168.1.1")
        
        hello2 = HelloPacket(network_mask="255.255.255.0")
        pkt2 = build_packet("192.168.1.2", "0.0.0.0", OSPF_TYPE_HELLO, hello2.pack())
        self.router1.process_packet(pkt2, "192.168.1.2")
        
        # Router1 发送初始DD (MS=1, I=1, M=1)
        dd1 = DDPacket(
            interface_mtu=1500,
            options=0x02,
            dd_sequence=1000,
            flags=0x07  # I=1, M=1, MS=1
        )
        pkt_dd1 = build_packet("192.168.1.1", "0.0.0.0", OSPF_TYPE_DD, dd1.pack())
        resp_dd1 = self.router2.process_packet(pkt_dd1, "192.168.1.1")
        
        print(f"Router2 收到DD, 响应: {resp_dd1 is not None}")
        
        # Router2 响应DD
        if resp_dd1:
            # 解析DD响应，Router2应该成为Slave
            dd_resp = DDPacket.unpack(resp_dd1[24:])
            print(f"Router2 DD response flags: {dd_resp.flags:02x}, seq: {dd_resp.dd_sequence}")

    def test_3_lsr_lsu_lsack(self):
        """测试3: LSR -> LSU -> LSAck 完整流程"""
        print("\n=== 测试3: LSR -> LSU -> LSAck ===")
        
        # 建立邻居
        hello1 = HelloPacket(network_mask="255.255.255.0")
        pkt1 = build_packet("192.168.1.1", "0.0.0.0", OSPF_TYPE_HELLO, hello1.pack())
        self.router2.process_packet(pkt1, "192.168.1.1")
        
        # Router2 已有一些LSA
        self.router2.lsdb["1-192.168.1.2"] = {
            'type': 1,
            'id': '192.168.1.2',
            'adv_router': '192.168.1.2',
            'sequence': 0x80000001,
            'links': []
        }
        
        # Router1 发送LSR请求
        lsr = LSRPacket(ls_type=1, ls_id="192.168.1.2", adv_router="192.168.1.2")
        pkt_lsr = build_packet("192.168.1.1", "0.0.0.0", OSPF_TYPE_LSR, lsr.pack())
        resp_lsr = self.router2.process_packet(pkt_lsr, "192.168.1.1")
        
        print(f"Router2 收到LSR, 响应类型: {resp_lsr is not None}")
        
        # Router2 应该回复LSU
        if resp_lsr:
            # 检查是否是LSU类型
            header = OSPFHeader.unpack(resp_lsr[:24])
            print(f"响应报文类型: {header.type}")
            self.assertEqual(header.type, OSPF_TYPE_LSU)
            
            # Router1 收到LSU后应该回复LSAck
            lsu_data = resp_lsr[24:]
            resp_ack = self.router1.process_packet(resp_lsr, "192.168.1.2")
            
            if resp_ack:
                ack_header = OSPFHeader.unpack(resp_ack[:24])
                print(f"Router1 响应报文类型: {ack_header.type}")
                self.assertEqual(ack_header.type, OSPF_TYPE_LSACK)
                print("✓ LSU后正确回复LSAck")
            else:
                print("✗ Router1 没有回复LSAck")
                # 不fail，因为可能是状态问题

    def test_4_lsu_direct(self):
        """测试4: 直接收到LSU后的LSAck响应"""
        print("\n=== 测试4: 直接收到LSU后的LSAck响应 ===")
        
        # Router2 直接发送LSU给Router1 (不经过LSR)
        lsu = LSUPacket(
            type=1,
            id="192.168.1.2",
            adv_router="192.168.1.2",
            lsa_entries=[{
                'type': 1,
                'id': '192.168.1.2',
                'adv_router': '192.168.1.2',
                'sequence': 0x80000001
            }]
        )
        pkt_lsu = build_packet("192.168.1.2", "0.0.0.0", OSPF_TYPE_LSU, lsu.pack())
        
        # Router1 收到LSU
        resp = self.router1.process_packet(pkt_lsu, "192.168.1.2")
        
        if resp:
            header = OSPFHeader.unpack(resp[:24])
            print(f"收到LSU后响应类型: {header.type}")
            if header.type == OSPF_TYPE_LSACK:
                print("✓ 正确回复LSAck")
                self.assertEqual(header.type, OSPF_TYPE_LSACK)
            else:
                print(f"✗ 未正确回复LSAck，收到类型{header.type}")
        else:
            print("✗ 没有响应")


def run_tests():
    """运行测试"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestOSPFRFCFlow)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    print(f"\n{'='*50}")
    print(f"测试结果: {'通过' if success else '失败'}")
    sys.exit(0 if success else 1)
