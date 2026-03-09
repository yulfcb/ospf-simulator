#!/usr/bin/env python3
"""
OSPFv2 模拟器 - 核心协议实现
支持: Hello, DD, LSR, LSU, LSAck 报文处理
"""

import struct
import socket
import random
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# OSPF 协议常量
OSPF_VERSION = 2
OSPF_TYPE_HELLO = 1
OSPF_TYPE_DD = 2
OSPF_TYPE_LSR = 3
OSPF_TYPE_LSU = 4
OSPF_TYPE_LSACK = 5

OSPF_AREA_BACKBONE = "0.0.0.0"
ALL_SPF_ROUTERS = "224.0.0.5"
ALL_DROUTERS = "224.0.0.6"

# OSPF 网络类型
class OSPFNetworkType(Enum):
    POINT_TO_POINT = 1
    BROADCAST = 2
    NBMA = 3
    POINT_TO_MULTIPOINT = 4

# OSPF 邻居状态
class NeighborState(Enum):
    DOWN = 1
    ATTEMPT = 2
    INIT = 3
    TWOWAY = 4
    EXSTART = 5
    EXCHANGE = 6
    LOADING = 7
    FULL = 8

@dataclass
class OSPFHeader:
    version: int = OSPF_VERSION
    type: int = 1
    length: int = 0
    router_id: str = "0.0.0.0"
    area_id: str = "0.0.0.0"
    checksum: int = 0
    auth_type: int = 0
    auth: int = 0
    
    def pack(self) -> bytes:
        """打包 OSPF 头部"""
        header = struct.pack("!BBH4s4sHIH",
            self.version,
            self.type,
            self.length,
            socket.inet_aton(self.router_id),
            socket.inet_aton(self.area_id),
            self.checksum,
            self.auth_type,
            self.auth
        )
        return header
    
    @classmethod
    def unpack(cls, data: bytes) -> 'OSPFHeader':
        """解包 OSPF 头部"""
        header = struct.unpack("!BBH4s4sHIH", data[:24])
        return cls(
            version=header[0],
            type=header[1],
            length=header[2],
            router_id=socket.inet_ntoa(header[3]),
            area_id=socket.inet_ntoa(header[4]),
            checksum=header[5],
            auth_type=header[6],
            auth=header[7]
        )

@dataclass
class HelloPacket:
    network_mask: str = "0.0.0.0"
    hello_interval: int = 10
    options: int = 0x02
    router_priority: int = 1
    dead_interval: int = 40
    dr: str = "0.0.0.0"
    bdr: str = "0.0.0.0"
    neighbor: List[str] = field(default_factory=list)
    
    def pack(self) -> bytes:
        """打包 Hello 报文"""
        # 格式: 4s H B B I I 4s 4s = 4+2+1+1+4+4+4+4 = 24字节 (加一个reserved)
        data = struct.pack("!4sHBBIII4s4s",
            socket.inet_aton(self.network_mask),
            self.hello_interval,
            self.options,
            self.router_priority,
            self.dead_interval,
            0,  # reserved
            socket.inet_aton(self.dr),
            socket.inet_aton(self.bdr)
        )
        # 添加邻居列表
        for neighbor_id in self.neighbor:
            data += socket.inet_aton(neighbor_id)
        return data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'HelloPacket':
        """解包 Hello 报文"""
        header = struct.unpack("!4sHBBII4s4s", data[:24])
        neighbors = []
        offset = 24
        while offset + 4 <= len(data):
            neighbor_id = socket.inet_ntoa(data[offset:offset+4])
            neighbors.append(neighbor_id)
            offset += 4
        return cls(
            network_mask=socket.inet_ntoa(header[0]),
            hello_interval=header[1],
            options=header[2],
            router_priority=header[3],
            dead_interval=header[4],
            dr=socket.inet_ntoa(header[5]),
            bdr=socket.inet_ntoa(header[6]),
            neighbor=neighbors
        )

@dataclass
class DDPacket:
    options: int = 0x02
    dd_sequence: int = 0
    flags: int = 0x07  # I, M, MS
    ls_age: int = 0
    ls_type: int = 1
    ls_id: str = "0.0.0.0"
    adv_router: str = "0.0.0.0"
    ls_sequence: int = 0x80000001
    checksum: int = 0
    length: int = 0
    
    def pack(self) -> bytes:
        """打包 DD 报文"""
        dd_header = struct.pack("!BBIII",
            self.options,
            self.dd_sequence,
            self.flags,
            0,  # reserved
            0   # LSA length (placeholder)
        )
        return dd_header
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DDPacket':
        header = struct.unpack("!BBIII", data[:16])
        return cls(
            options=header[0],
            dd_sequence=header[1],
            flags=header[2]
        )

@dataclass
class LSRPacket:
    ls_type: int = 1
    ls_id: str = "0.0.0.0"
    adv_router: str = "0.0.0.0"
    
    def pack(self) -> bytes:
        return struct.pack("!I4s4s",
            self.ls_type,
            socket.inet_aton(self.ls_id),
            socket.inet_aton(self.adv_router)
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSRPacket':
        header = struct.unpack("!I4s4s", data[:12])
        return cls(
            ls_type=header[0],
            ls_id=socket.inet_ntoa(header[1]),
            adv_router=socket.inet_ntoa(header[2])
        )

@dataclass
class LSUPacket:
    age: int = 0
    type: int = 1
    id: str = "0.0.0.0"
    adv_router: str = "0.0.0.0"
    sequence: int = 0x80000001
    checksum: int = 0
    length: int = 0
    lsa_entries: List[dict] = field(default_factory=list)
    
    def pack(self) -> bytes:
        """打包 LSU 报文 (含 LSA)"""
        lsa_data = b''
        for entry in self.lsa_entries:
            lsa = struct.pack("!IH4s4sIIIHH",
                0,  # LSA age
                entry.get('type', 1),
                socket.inet_aton(entry.get('id', '0.0.0.0')),
                socket.inet_aton(entry.get('adv_router', '0.0.0.0')),
                entry.get('sequence', 0x80000001),
                0,  # checksum
                entry.get('length', 36),
                0,  # network mask
                0   # attached router
            )
            lsa_data += lsa
        return struct.pack("!IH4s4sIIIH",
            self.age,
            self.type,
            socket.inet_aton(self.id),
            socket.inet_aton(self.adv_router),
            self.sequence,
            self.checksum,
            self.length
        ) + lsa_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSUPacket':
        header = struct.unpack("!IH4s4sIIIH", data[:24])
        entries = []
        offset = 24
        while offset + 20 <= len(data):
            entry = struct.unpack("!IH4s4sIIIHH", data[offset:offset+24])
            entries.append({
                'age': entry[0],
                'type': entry[1],
                'id': socket.inet_ntoa(entry[2]),
                'adv_router': socket.inet_ntoa(entry[3]),
                'sequence': entry[4],
                'checksum': entry[5],
                'length': entry[6]
            })
            offset += 24
        return cls(
            age=header[0],
            type=header[1],
            id=socket.inet_ntoa(header[2]),
            adv_router=socket.inet_ntoa(header[3]),
            sequence=header[4],
            length=header[6],
            lsa_entries=entries
        )

@dataclass
class LSAHeader:
    ls_age: int = 0
    options: int = 0x02
    ls_type: int = 1
    ls_id: str = "0.0.0.0"
    adv_router: str = "0.0.0.0"
    ls_sequence: int = 0x80000001
    checksum: int = 0
    length: int = 0
    
    def pack(self) -> bytes:
        return struct.pack("!HBB4s4sIIIHH",
            self.ls_age,
            self.options,
            self.ls_type,
            socket.inet_aton(self.ls_id),
            socket.inet_aton(self.adv_router),
            self.ls_sequence,
            self.checksum,
            self.length,
            0, 0
        )

class RouterLSA:
    """路由器 LSA (Type 1)"""
    
    def __init__(self, router_id: str, area_id: str):
        self.header = LSAHeader(ls_type=1, adv_router=router_id, ls_id=router_id)
        self.links = []
    
    def add_link(self, link_id: str, link_data: str, type: int, metric: int):
        """添加链路信息"""
        self.links.append({
            'link_id': link_id,
            'link_data': link_data,
            'type': type,
            'metric': metric
        })
    
    def pack(self) -> bytes:
        # 链路数据
        links_data = b''
        for link in self.links:
            links_data += struct.pack("!4sIHH",
                socket.inet_aton(link['link_id']),
                link['link_data'] if isinstance(link['link_data'], int) else int(link['link_data'].split('.')[0]) if link['link_data'] else 0,
                link['type'],
                link['metric']
            )
        
        # 设置长度
        self.header.length = 20 + len(self.links) * 12
        return self.header.pack() + links_data
    
    @classmethod
    def unpack(cls, data: bytes, router_id: str) -> 'RouterLSA':
        lsa = cls(router_id, "0.0.0.0")
        # 解析链路
        return lsa

class NetworkLSA:
    """网络 LSA (Type 2)"""
    
    def __init__(self, network_id: str, adv_router: str, area_id: str):
        self.header = LSAHeader(ls_type=2, ls_id=network_id, adv_router=adv_router)
        self.network_mask = "0.0.0.0"
        self.attached_routers = []
    
    def pack(self) -> bytes:
        data = struct.pack("!4s", socket.inet_aton(self.network_mask))
        for router in self.attached_routers:
            data += struct.pack("!4s", socket.inet_aton(router))
        self.header.length = 20 + 4 + len(self.attached_routers) * 4
        return self.header.pack() + data

class OSPFRouter:
    """OSPF 路由器"""
    
    def __init__(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE):
        self.router_id = router_id
        self.area_id = area_id
        self.interfaces: Dict[str, dict] = {}
        self.neighbors: Dict[str, dict] = {}
        self.lsdb: Dict[str, dict] = {}  # LSDB
        self.routes: Dict[str, dict] = {}  # 路由表
        self.lock = threading.Lock()
        
        # 统计
        self.stats = {
            'hello_sent': 0,
            'hello_recv': 0,
            'dd_sent': 0,
            'dd_recv': 0,
            'lsr_sent': 0,
            'lsr_recv': 0,
            'lsu_sent': 0,
            'lsu_recv': 0,
            'lsack_sent': 0,
            'lsack_recv': 0
        }
        
        # 初始化 LSA 数据库
        self._init_lsdb()
    
    def _init_lsdb(self):
        """初始化 LSDB"""
        # 添加自身的 Router LSA
        self.lsdb[f"1-{self.router_id}"] = {
            'type': 1,
            'id': self.router_id,
            'adv_router': self.router_id,
            'sequence': 0x80000001,
            'links': []
        }
    
    def add_interface(self, name: str, ip: str, netmask: str, cost: int = 1):
        """添加接口"""
        self.interfaces[name] = {
            'ip': ip,
            'netmask': netmask,
            'cost': cost,
            'network': self._calc_network(ip, netmask),
            'state': 'DR',  # DR, BDR, DROTHER
            'dr': '0.0.0.0',
            'bdr': '0.0.0.0'
        }
        logger.info(f"添加接口 {name}: {ip}/{netmask}")
    
    def _calc_network(self, ip: str, mask: str) -> str:
        """计算网络地址"""
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
        net_int = ip_int & mask_int
        return socket.inet_ntoa(struct.pack("!I", net_int))
    
    def add_static_route(self, network: str, netmask: str, next_hop: str = "0.0.0.0"):
        """添加静态路由"""
        route_key = f"{network}-{netmask}"
        self.routes[route_key] = {
            'network': network,
            'netmask': netmask,
            'next_hop': next_hop,
            'cost': 1,
            'type': 'static'
        }
        # 生成 LSA 并注入
        self._inject_route_to_lsa(network, netmask, next_hop)
        logger.info(f"添加静态路由: {network}/{netmask} -> {next_hop}")
    
    def _inject_route_to_lsa(self, network: str, netmask: str, next_hop: str):
        """将路由注入 LSA"""
        # 更新 Router LSA
        lsa_key = f"1-{self.router_id}"
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
            self.lsdb[lsa_key]['links'].append({
                'link_id': network,
                'link_data': next_hop if next_hop != "0.0.0.0" else "0.0.0.1",
                'type': 3,  # stub network
                'metric': 1
            })
    
    def generate_routes(self, base_network: str, count: int, prefix: int = 24):
        """批量生成静态路由"""
        base_ip = list(map(int, base_network.split('.')))
        generated = []
        for i in range(count):
            network = f"{base_ip[0]}.{base_ip[1]}.{(base_ip[2] + i // 256) % 256}.{i % 256}"
            netmask = f"255.255.255.0"
            self.add_static_route(network, netmask)
            generated.append(f"{network}/24")
        return generated
    
    def send_hello(self, sock: socket.socket, target: str = ALL_SPF_ROUTERS):
        """发送 Hello 报文"""
        for iface_name, iface in self.interfaces.items():
            hello = HelloPacket(
                network_mask=iface['netmask'],
                
                hello_interval=10,
                router_priority=1,
                dr=iface['dr'],
                bdr=iface['bdr']
            )
            
            msg = OSPFHeader(
                type=OSPF_TYPE_HELLO,
                length=24 + len(hello.pack()),
                
                area_id=self.area_id
            )
            
            packet = msg.pack() + hello.pack()
            
            try:
                sock.sendto(packet, (target, 89))
                self.stats['hello_sent'] += 1
                logger.debug(f"发送 Hello 到 {target} 从接口 {iface_name}")
            except Exception as e:
                logger.error(f"发送 Hello 失败: {e}")
    
    def process_packet(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理收到的 OSPF 报文"""
        try:
            header = OSPFHeader.unpack(data)
            logger.debug(f"收到 OSPF 报文: type={header.type} from {src_addr}")
            
            if header.type == OSPF_TYPE_HELLO:
                self.stats['hello_recv'] += 1
                return self._process_hello(data[24:], src_addr)
            elif header.type == OSPF_TYPE_DD:
                self.stats['dd_recv'] += 1
                return self._process_dd(data[24:], src_addr)
            elif header.type == OSPF_TYPE_LSR:
                self.stats['lsr_recv'] += 1
                return self._process_lsr(data[24:], src_addr)
            elif header.type == OSPF_TYPE_LSU:
                self.stats['lsu_recv'] += 1
                return self._process_lsu(data[24:], src_addr)
            elif header.type == OSPF_TYPE_LSACK:
                self.stats['lsack_recv'] += 1
                return self._process_lsack(data[24:], src_addr)
            
        except Exception as e:
            logger.error(f"处理报文失败: {e}")
        return None
    
    def _process_hello(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理 Hello 报文"""
        hello = HelloPacket.unpack(data)
        
        # 更新邻居
        if src_addr not in self.neighbors:
            self.neighbors[src_addr] = {
                'state': NeighborState.INIT,
                'priority': hello.router_priority,
                'dr': hello.dr,
                'bdr': hello.bdr
            }
        else:
            self.neighbors[src_addr]['state'] = NeighborState.TWOWAY
        
        logger.info(f"收到 Hello from {src_addr}, 邻居状态: {self.neighbors[src_addr]['state']}")
        return None
    
    def _process_dd(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理 DD 报文"""
        self._update_neighbor_state(src_addr, NeighborState.EXCHANGE)
        # 简化的 DD 处理
        return None
    
    def _process_lsr(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理 LSR 报文"""
        lsr = LSRPacket.unpack(data)
        self._update_neighbor_state(src_addr, NeighborState.LOADING)
        
        # 查找并返回 LSA
        lsa_key = f"{lsr.ls_type}-{lsr.ls_id}"
        if lsa_key in self.lsdb:
            return self._build_lsu([self.lsdb[lsa_key]], src_addr)
        return None
    
    def _process_lsu(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理 LSU 报文"""
        lsu = LSUPacket.unpack(data)
        
        # 更新 LSDB
        for entry in lsu.lsa_entries:
            lsa_key = f"{entry['type']}-{entry['id']}"
            self.lsdb[lsa_key] = entry
        
        # 更新路由表
        self._update_routing_table()
        
        self._update_neighbor_state(src_addr, NeighborState.FULL)
        logger.info(f"收到 LSU from {src_addr}, LSDB 条目数: {len(self.lsdb)}")
        
        # 发送 LSAck
        return self._build_lsack(lsu.lsa_entries, src_addr)
    
    def _process_lsack(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理 LSAck 报文"""
        logger.debug(f"收到 LSAck from {src_addr}")
        return None
    
    def _update_neighbor_state(self, neighbor_id: str, state: NeighborState):
        """更新邻居状态"""
        if neighbor_id in self.neighbors:
            self.neighbors[neighbor_id]['state'] = state
        else:
            self.neighbors[neighbor_id] = {'state': state}
    
    def _update_routing_table(self):
        """根据 LSDB 更新路由表"""
        for lsa_key, lsa in self.lsdb.items():
            if lsa['type'] == 1:  # Router LSA
                for link in lsa.get('links', []):
                    if link['type'] == 3:  # Stub network
                        route_key = f"{link['link_id']}-255.255.255.0"
                        if route_key not in self.routes:
                            self.routes[route_key] = {
                                'network': link['link_id'],
                                'netmask': '255.255.255.0',
                                'next_hop': link['link_data'],
                                'cost': link['metric'],
                                'type': 'ospf'
                            }
    
    def _build_lsu(self, lsa_list: List[dict], target: str) -> bytes:
        """构建 LSU 报文"""
        lsu = LSUPacket(
            type=1,
            id=self.router_id,
            adv_router=self.router_id,
            lsa_entries=lsa_list
        )
        
        msg = OSPFHeader(
            type=OSPF_TYPE_LSU,
            length=24 + len(lsu.pack()),
            
            area_id=self.area_id
        )
        
        self.stats['lsu_sent'] += 1
        return msg.pack() + lsu.pack()
    
    def _build_lsack(self, lsa_list: List[dict], target: str) -> bytes:
        """构建 LSAck 报文"""
        ack_data = b''
        for lsa in lsa_list:
            ack_data += LSAHeader(
                ls_type=lsa['type'],
                ls_id=lsa['id'],
                adv_router=lsa['adv_router'],
                ls_sequence=lsa['sequence']
            ).pack()
        
        msg = OSPFHeader(
            type=OSPF_TYPE_LSACK,
            length=24 + len(ack_data),
            
            area_id=self.area_id
        )
        
        self.stats['lsack_sent'] += 1
        return msg.pack() + ack_data
    
    def get_status(self) -> dict:
        """获取状态"""
        return {
            'router_id': self.router_id,
            'area_id': self.area_id,
            'interfaces': len(self.interfaces),
            'neighbors': len(self.neighbors),
            'lsdb_entries': len(self.lsdb),
            'routes': len(self.routes),
            'stats': self.stats
        }
    
    def flood_lsa(self, sock: socket.socket):
        """泛洪 LSA 到所有邻居"""
        for neighbor_id in self.neighbors:
            if self.neighbors[neighbor_id].get('state') == NeighborState.FULL:
                lsa_list = list(self.lsdb.values())
                packet = self._build_lsu(lsa_list, neighbor_id)
                try:
                    sock.sendto(packet, (neighbor_id, 89))
                except Exception as e:
                    logger.error(f"泛洪 LSA 失败: {e}")


class OSPFSimulator:
    """OSPF 模拟器主类"""
    
    def __init__(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE):
        self.router = OSPFRouter(router_id, area_id)
        self.sock = None
        self.running = False
        self.threads: List[threading.Thread] = []
    
    def start(self):
        """启动模拟器"""
        # 创建 UDP 套接字
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_UDP, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 89))
        
        # 加入多播组
        try:
            mreq = struct.pack("4sl", socket.inet_aton(ALL_SPF_ROUTERS), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
            pass
        
        self.running = True
        
        # 启动 Hello 发送线程
        t = threading.Thread(target=self._hello_sender, daemon=True)
        t.start()
        self.threads.append(t)
        
        # 启动报文接收线程
        t = threading.Thread(target=self._packet_receiver, daemon=True)
        t.start()
        self.threads.append(t)
        
        logger.info(f"OSPF 模拟器启动, Router ID: {self.router.router_id}")
    
    def stop(self):
        """停止模拟器"""
        self.running = False
        if self.sock:
            self.sock.close()
        for t in self.threads:
            t.join(timeout=1)
        logger.info("OSPF 模拟器已停止")
    
    def _hello_sender(self):
        """Hello 报文发送线程"""
        while self.running:
            self.router.send_hello(self.sock)
            time.sleep(10)
    
    def _packet_receiver(self):
        """报文接收线程"""
        self.sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    self.router.process_packet(data, addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"接收报文错误: {e}")
    
    def get_status(self) -> dict:
        """获取状态"""
        return self.router.get_status()


if __name__ == "__main__":
    # 测试
    sim = OSPFSimulator("192.168.1.1")
    sim.router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    sim.start()
    
    print("OSPF 模拟器运行中...")
    time.sleep(5)
    print(sim.get_status())
    
    sim.stop()
