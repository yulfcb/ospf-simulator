#!/usr/bin/env python3
"""
OSPFv2 模拟器 - 核心协议实现
支持: Hello, DD, LSR, LSU, LSAck 报文处理
支持多实例: 同一物理接口上运行多个OSPF实例，每个实例有独立的Router ID和源IP
"""

import struct
import socket
import random
import logging
import threading
import time
import subprocess
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json

# 系统网络接口检测
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False


# RFC 1071 checksum calculation (used for OSPF packet header, NOT for LSA)
def calc_checksum(data: bytes) -> int:
    """Calculate RFC 1071 checksum for OSPF packet headers (not LSA)"""
    if len(data) % 2 == 1:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF


def fletcher_checksum(data: bytes, offset: int = 0) -> int:
    """
    Calculate Fletcher-16 checksum (RFC 2328 Appendix B)
    This is used for LSA checksum calculation, not for OSPF packet headers.
    """
    if len(data) == 0:
        return 0
    
    words = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        words.append(word)
    
    c0 = 0
    c1 = 0
    
    for word in words:
        c0 = (c0 + word) & 0xFF
        c1 = (c1 + c0) & 0xFF
    
    return ((c1 << 8) | c0) & 0xFFFF


def calc_lsa_checksum(lsa_header: bytes, lsa_body: bytes) -> int:
    """
    Calculate LSA checksum according to RFC 2328 Appendix B.
    """
    header_with_zero_age = b'\x00\x00' + lsa_header[2:]
    return fletcher_checksum(header_with_zero_age + lsa_body)


def get_system_interfaces() -> Dict[str, dict]:
    """获取系统网络接口列表"""
    interfaces = {}
    
    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            iface_info = {'ip': None, 'netmask': None, 'mac': None}
            
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    iface_info['ip'] = addr.get('addr')
                    iface_info['netmask'] = addr.get('netmask')
                    break
            
            if netifaces.AF_LINK in addrs:
                iface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr')
            
            if iface_info['ip'] and iface != 'lo':
                interfaces[iface] = iface_info
    else:
        system = platform.system()
        try:
            if system == 'Linux':
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                _parse_linux_ip_addr(result.stdout, interfaces)
            elif system == 'Windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                _parse_windows_ipconfig(result.stdout, interfaces)
        except Exception as e:
            logger.warning(f"获取系统接口失败: {e}")
    
    return interfaces


def _parse_linux_ip_addr(output: str, interfaces: dict):
    current_iface = None
    for line in output.split('\n'):
        line = line.strip()
        if line and not line.startswith(' '):
            parts = line.split(':')
            if len(parts) >= 2:
                current_iface = parts[1].strip()
                interfaces[current_iface] = {'ip': None, 'netmask': None, 'mac': None}
        elif 'inet ' in line and current_iface:
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[1].split('/')[0]
                netmask = parts[3] if len(parts) > 3 else '255.255.255.0'
                interfaces[current_iface]['ip'] = ip
                interfaces[current_iface]['netmask'] = netmask
        elif 'link/ether' in line and current_iface:
            parts = line.split()
            if len(parts) >= 2:
                interfaces[current_iface]['mac'] = parts[1]
    
    for iface in list(interfaces.keys()):
        if not interfaces[iface]['ip'] or iface == 'lo':
            del interfaces[iface]


def _parse_windows_ipconfig(output: str, interfaces: dict):
    current_iface = None
    for line in output.split('\n'):
        line = line.strip()
        if '适配器' in line or 'Adapter' in line:
            parts = line.split()
            if parts:
                current_iface = parts[-1].rstrip(':')
                interfaces[current_iface] = {'ip': None, 'netmask': None, 'mac': None}
        elif 'IPv4' in line and current_iface:
            parts = line.split(':')
            if len(parts) >= 2:
                interfaces[current_iface]['ip'] = parts[1].strip()
        elif '子网掩码' in line or 'Mask' in line:
            parts = line.split(':')
            if len(parts) >= 2 and current_iface:
                interfaces[current_iface]['netmask'] = parts[1].strip()
    
    for iface in list(interfaces.keys()):
        if not interfaces[iface]['ip']:
            del interfaces[iface]


def cidr_to_netmask(cidr: str) -> str:
    """将 CIDR 转换为点分十进制子网掩码"""
    if '/' not in cidr:
        return cidr
    
    ip, prefix = cidr.split('/')
    prefix = int(prefix)
    
    mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return socket.inet_ntoa(struct.pack('!I', mask))


def netmask_to_cidr(netmask: str) -> int:
    """将点分十进制子网掩码转换为 CIDR 前缀长度"""
    mask = socket.inet_aton(netmask)
    return bin(struct.unpack('!I', mask)[0]).count('1')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OSPF_VERSION = 2
OSPF_TYPE_HELLO = 1
OSPF_TYPE_DD = 2
OSPF_TYPE_LSR = 3
OSPF_TYPE_LSU = 4
OSPF_TYPE_LSACK = 5

OSPF_AREA_BACKBONE = "0.0.0.0"
ALL_SPF_ROUTERS = "224.0.0.5"
ALL_DROUTERS = "224.0.0.6"


class OSPFNetworkType(Enum):
    POINT_TO_POINT = 1
    BROADCAST = 2
    NBMA = 3
    POINT_TO_MULTIPOINT = 4


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
    
    def pack(self, body: bytes = b'') -> bytes:
        header = struct.pack("!BBH4s4sHH8s",
            self.version,
            self.type,
            self.length,
            socket.inet_aton(self.router_id),
            socket.inet_aton(self.area_id),
            0,
            self.auth_type,
            self.auth.to_bytes(8, 'big') if isinstance(self.auth, int) else self.auth
        )
        full_packet = header + body
        checksum = calc_checksum(full_packet)
        header = header[:12] + struct.pack("!H", checksum) + header[14:]
        return header + body
    
    @classmethod
    def unpack(cls, data: bytes) -> 'OSPFHeader':
        header = struct.unpack("!BBH4s4sHH8s", data[:24])
        auth_bytes = header[7]
        if isinstance(auth_bytes, bytes):
            auth_val = int.from_bytes(auth_bytes, 'big')
        else:
            auth_val = auth_bytes
        return cls(
            version=header[0],
            type=header[1],
            length=header[2],
            router_id=socket.inet_ntoa(header[3]),
            area_id=socket.inet_ntoa(header[4]),
            checksum=header[5],
            auth_type=header[6],
            auth=auth_val
        )


@dataclass
class HelloPacket:
    network_mask: str = "0.0.0.0"
    hello_interval: int = 10
    ls_age: int = 0
    options: int = 0x02
    router_priority: int = 1
    dead_interval: int = 40
    dr: str = "0.0.0.0"
    bdr: str = "0.0.0.0"
    neighbor: List[str] = field(default_factory=list)
    
    def pack(self) -> bytes:
        data = struct.pack("!4sHBB I 4s 4s".replace(" ", ""),
            socket.inet_aton(self.network_mask),
            self.hello_interval,
            self.options,
            self.router_priority,
            self.dead_interval,
            socket.inet_aton(self.dr),
            socket.inet_aton(self.bdr)
        )
        for neighbor_id in self.neighbor:
            data += socket.inet_aton(neighbor_id)
        return data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'HelloPacket':
        if len(data) < 20:
            return cls()
        header = struct.unpack("!4sHBB I 4s 4s".replace(" ", ""), data[:20])
        neighbors = []
        offset = 20
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
    ls_age: int = 0
    options: int = 0x02
    dd_sequence: int = 0
    flags: int = 0
    interface_mtu: int = 1500
    lsa_headers: List[dict] = field(default_factory=list)
    
    def pack(self) -> bytes:
        dd_header = struct.pack("!HBB I",
            self.interface_mtu,
            self.options,
            self.flags,
            self.dd_sequence
        )
        lsa_data = b''
        for lsa in self.lsa_headers:
            lsa_header = struct.pack("!HBB4s4sIHH",
                lsa.get('ls_age', 0),
                lsa.get('options', 0x02),
                lsa.get('ls_type', 1),
                socket.inet_aton(lsa.get('ls_id', '0.0.0.0')),
                socket.inet_aton(lsa.get('adv_router', '0.0.0.0')),
                lsa.get('ls_sequence', 0x80000001),
                lsa.get('checksum', 0),
                lsa.get('length', 20)
            )
            lsa_data += lsa_header
        return dd_header + lsa_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DDPacket':
        if len(data) < 8:
            return cls()
        mtu, opts, flags, seq = struct.unpack("!HBB I", data[:8])
        lsa_headers = []
        offset = 8
        while offset + 20 <= len(data):
            lsa = struct.unpack("!HBB4s4sIHH", data[offset:offset+20])
            lsa_headers.append({
                'ls_age': lsa[0],
                'options': lsa[1],
                'ls_type': lsa[2],
                'ls_id': socket.inet_ntoa(lsa[3]),
                'adv_router': socket.inet_ntoa(lsa[4]),
                'ls_sequence': lsa[5],
                'checksum': lsa[6],
                'length': lsa[7]
            })
            offset += 20
        return cls(
            interface_mtu=mtu,
            options=opts,
            dd_sequence=seq,
            flags=flags,
            lsa_headers=lsa_headers
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
        lsa_data = b''
        for entry in self.lsa_entries:
            lsa_type = entry.get('type', 1)
            lsa_body = b''
            
            if lsa_type == 1:
                links = entry.get('links', [])
                lsa_body = struct.pack("!H", len(links))
                for link in links:
                    link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                    link_data = socket.inet_aton(link.get('link_data', '0.0.0.0'))
                    link_type = link.get('type', 3)
                    metric = link.get('metric', 1)
                    lsa_body += struct.pack("!B4s4sBH", link_type, link_id, link_data, 0, metric)
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 2:
                routers = entry.get('attached_routers', [])
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                lsa_body = network_mask
                for r in routers:
                    lsa_body += socket.inet_aton(r)
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 3:
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                metric = struct.pack('!I', entry.get('metric', 1))
                lsa_body = network_mask + metric
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 4:
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                metric = struct.pack('!I', entry.get('metric', 1))
                lsa_body = network_mask + metric
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 5:
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                e_bit = entry.get('e_bit', 0)
                metric = struct.pack('!I', entry.get('metric', 1))
                forwarding = socket.inet_aton(entry.get('forwarding_address', '0.0.0.0'))
                external_tag = struct.pack('!I', entry.get('external_route_tag', 0))
                lsa_body = network_mask + bytes([e_bit << 7]) + metric + forwarding + external_tag
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 7:
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                p_bit = entry.get('p_bit', 0)
                metric = struct.pack('!I', entry.get('metric', 1))
                forwarding = socket.inet_aton(entry.get('forwarding_address', '0.0.0.0'))
                external_tag = struct.pack('!I', entry.get('external_route_tag', 0))
                lsa_body = network_mask + bytes([p_bit << 7]) + metric + forwarding + external_tag
                lsa_length = 20 + len(lsa_body)
            else:
                lsa_body = b''
                lsa_length = 20
            
            lsa_header_for_calc = struct.pack("!HBB4s4sIHH",
                entry.get('age', 0),
                entry.get('options', 0x02),
                lsa_type,
                socket.inet_aton(entry.get('id', '0.0.0.0')),
                socket.inet_aton(entry.get('adv_router', '0.0.0.0')),
                entry.get('sequence', 0x80000001),
                0,
                lsa_length
            )
            lsa_checksum = calc_lsa_checksum(lsa_header_for_calc, lsa_body)
            
            lsa_header = struct.pack("!HBB4s4sIHH",
                entry.get('age', 0),
                entry.get('options', 0x02),
                lsa_type,
                socket.inet_aton(entry.get('id', '0.0.0.0')),
                socket.inet_aton(entry.get('adv_router', '0.0.0.0')),
                entry.get('sequence', 0x80000001),
                lsa_checksum,
                lsa_length
            )
            lsa_data += lsa_header + lsa_body
        
        return struct.pack("!I", len(self.lsa_entries)) + lsa_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSUPacket':
        if len(data) < 24:
            return cls()
        num_lsas = struct.unpack("!I", data[:4])[0]
        entries = []
        offset = 4
        for _ in range(num_lsas):
            if offset + 20 > len(data):
                break
            header = struct.unpack("!HBB4s4sIHH", data[offset:offset+20])
            lsa_type = header[2]
            lsa_length = header[7]
            
            body_offset = offset + 20
            body = data[body_offset:body_offset + lsa_length - 20] if lsa_length > 20 else b''
            
            entry_data = {
                'age': header[0],
                'options': header[1],
                'type': lsa_type,
                'id': socket.inet_ntoa(header[3]),
                'adv_router': socket.inet_ntoa(header[4]),
                'sequence': header[5],
                'checksum': header[6],
                'length': lsa_length
            }
            
            if lsa_type == 1 and len(body) >= 2:
                num_links = struct.unpack("!H", body[:2])[0]
                links = []
                link_offset = 2
                for i in range(num_links):
                    if link_offset + 12 <= len(body):
                        link = struct.unpack("!B4s4sBH", body[link_offset:link_offset+12])
                        links.append({
                            'type': link[0],
                            'link_id': socket.inet_ntoa(link[1]),
                            'link_data': socket.inet_ntoa(link[2]),
                            'metric': link[4]
                        })
                        link_offset += 12
                entry_data['links'] = links
            elif lsa_type == 2 and len(body) >= 4:
                entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                routers = []
                offset_r = 4
                while offset_r + 4 <= len(body):
                    routers.append(socket.inet_ntoa(body[offset_r:offset_r+4]))
                    offset_r += 4
                entry_data['attached_routers'] = routers
            elif lsa_type == 3:
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 8:
                    entry_data['metric'] = struct.unpack("!I", body[4:8])[0]
            elif lsa_type == 4:
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 8:
                    entry_data['metric'] = struct.unpack("!I", body[4:8])[0]
            elif lsa_type == 5:
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 5:
                    entry_data['e_bit'] = (body[4] & 0x80) >> 7
                if len(body) >= 9:
                    entry_data['metric'] = struct.unpack("!I", body[5:9])[0]
                if len(body) >= 13:
                    fa = body[9:13]
                    entry_data['forwarding_address'] = socket.inet_ntoa(fa) if fa != b'\x00\x00\x00\x00' else '0.0.0.0'
                if len(body) >= 17:
                    entry_data['external_route_tag'] = struct.unpack("!I", body[13:17])[0]
            elif lsa_type == 7:
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 5:
                    entry_data['p_bit'] = (body[4] & 0x80) >> 7
                if len(body) >= 9:
                    entry_data['metric'] = struct.unpack("!I", body[5:9])[0]
                if len(body) >= 17:
                    entry_data['forwarding_address'] = socket.inet_ntoa(body[13:17])
                if len(body) >= 21:
                    entry_data['external_route_tag'] = struct.unpack("!I", body[17:21])[0]
            
            entries.append(entry_data)
            offset += lsa_length
        
        return cls(
            age=0, type=1, id="0.0.0.0", adv_router="0.0.0.0",
            sequence=0, checksum=0,
            length=4 + sum(e['length'] for e in entries),
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
        return struct.pack("!HBB4s4sIHH",
            self.ls_age, self.options, self.ls_type,
            socket.inet_aton(self.ls_id),
            socket.inet_aton(self.adv_router),
            self.ls_sequence, self.checksum, self.length
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSAHeader':
        if len(data) < 20:
            return cls()
        fields = struct.unpack("!HBB4s4sIHH", data[:20])
        return cls(
            ls_age=fields[0], options=fields[1], ls_type=fields[2],
            ls_id=socket.inet_ntoa(fields[3]),
            adv_router=socket.inet_ntoa(fields[4]),
            ls_sequence=fields[5], checksum=fields[6], length=fields[7]
        )


class OSPFInstance:
    """
    OSPF 实例类 - 表示一个独立的 OSPF 进程
    
    支持在同一物理接口上运行多个实例，每个实例有：
    - 独立的 Router ID
    - 独立的源 IP（在同一物理接口上）
    - 独立的 LSDB 和邻居关系
    - 独立的统计信息
    """
    
    instance_counter = 0  # 类级别计数器
    
    def __init__(self, instance_id: int, router_id: str, area_id: str = OSPF_AREA_BACKBONE,
                 source_ip: str = None, priority: int = 1):
        """
        初始化 OSPF 实例
        
        Args:
            instance_id: 实例唯一标识
            router_id: Router ID (格式 x.x.x.x)
            area_id: Area ID (格式 x.x.x.x)
            source_ip: 源 IP 地址（物理接口上的 IP）
            priority: DD 优先级
        """
        self.instance_id = instance_id
        self.router_id = router_id
        self.area_id = area_id
        self.source_ip = source_ip  # 源 IP，用于发送 OSPF 报文
        self.router_priority = priority
        
        self.interfaces: Dict[str, dict] = {}
        self.neighbors: Dict[str, dict] = {}
        self.lsdb: Dict[str, dict] = {}
        self.routes: Dict[str, dict] = {}
        self.lock = threading.Lock()
        
        # 统计
        self.stats = {
            'hello_sent': 0, 'hello_recv': 0,
            'dd_sent': 0, 'dd_recv': 0,
            'lsr_sent': 0, 'lsr_recv': 0,
            'lsu_sent': 0, 'lsu_recv': 0,
            'lsack_sent': 0, 'lsack_recv': 0
        }
        
        self._init_lsdb()
        logger.info(f"OSPF Instance {instance_id}: Router ID={router_id}, Area={area_id}, Source IP={source_ip}")
    
    def _init_lsdb(self):
        """初始化 LSDB"""
        self.lsdb[f"1-{self.router_id}"] = {
            'type': 1, 'id': self.router_id,
            'adv_router': self.router_id, 'sequence': 0x80000001,
            'links': []
        }
    
    def add_interface(self, name: str, ip: str, netmask: str, cost: int = 1, mtu: int = 1500):
        """添加接口"""
        self.interfaces[name] = {
            'ip': ip, 'netmask': netmask, 'cost': cost, 'mtu': mtu,
            'network': self._calc_network(ip, netmask),
            'state': 'DR', 'dr': '0.0.0.0', 'bdr': '0.0.0.0'
        }
        
        network = self._calc_network(ip, netmask)
        lsa_key = f"1-{self.router_id}"
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['links'].append({
                'link_id': network, 'link_data': ip, 'type': 3, 'metric': cost
            })
        
        logger.info(f"Instance {self.instance_id} 添加接口 {name}: {ip}/{netmask}")
    
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
            'network': network, 'netmask': netmask,
            'next_hop': next_hop, 'cost': 1, 'type': 'static'
        }
        self._inject_route_to_lsa(network, netmask, next_hop)
        logger.info(f"Instance {self.instance_id} 添加静态路由: {network}/{netmask}")
    
    def _inject_route_to_lsa(self, network: str, netmask: str, next_hop: str):
        """将静态路由注入 AS External LSA (Type 5)"""
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"5-{network_addr}"
        
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 5, 'id': network_addr, 'adv_router': self.router_id,
                'sequence': 0x80000001, 'checksum': 0, 'age': 0, 'options': 0x02,
                'network': network_addr, 'netmask': netmask, 'metric': 1, 'e_bit': 1,
                'forwarding': next_hop if next_hop != "0.0.0.0" else "0.0.0.0",
                'external_route_tag': 0
            }
        
        self.lsdb[lsa_key]['network_mask'] = netmask
        self.lsdb[lsa_key]['forwarding_address'] = next_hop if next_hop != "0.0.0.0" else "0.0.0.0"
        self.lsdb[lsa_key]['e_bit'] = 1
    
    def remove_static_route(self, network: str, netmask: str = "255.255.255.0",
                           sock=None, use_raw=True, add_ip_header_func=None):
        """删除静态路由"""
        route_key = f"{network}-{netmask}"
        found = False
        
        if route_key in self.routes:
            del self.routes[route_key]
            logger.info(f"Instance {self.instance_id} 删除静态路由: {network}/{netmask}")
            found = True
        
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"5-{network_addr}"
        
        if lsa_key in self.lsdb:
            if sock is not None:
                maxage_lsa = {
                    'type': 5, 'id': network_addr, 'adv_router': self.router_id,
                    'sequence': 0x7FFFFFFF, 'checksum': 0, 'age': 3600, 'options': 0x02,
                    'network_mask': netmask, 'metric': 0xFFFFFF, 'e_bit': 1,
                    'forwarding_address': '0.0.0.0', 'external_route_tag': 0
                }
                
                lsu = LSUPacket(age=3600, type=5, id=network_addr, adv_router=self.router_id,
                               sequence=0x7FFFFFFF, lsa_entries=[maxage_lsa])
                
                msg = OSPFHeader(type=OSPF_TYPE_LSU, length=24 + len(lsu.pack()),
                               router_id=self.router_id, area_id=self.area_id)
                
                packet = msg.pack(lsu.pack())
                
                for neighbor_id, neighbor_info in self.neighbors.items():
                    if neighbor_info.get('state') == NeighborState.FULL:
                        send_packet = packet
                        if use_raw and add_ip_header_func:
                            send_packet = add_ip_header_func(send_packet, neighbor_id)
                        try:
                            sock.sendto(send_packet, (neighbor_id, 89))
                            self.stats['lsu_sent'] += 1
                        except Exception as e:
                            logger.error(f"发送 MaxAge LSA 失败: {e}")
            
            del self.lsdb[lsa_key]
        
        return found
    
    def send_hello(self, sock: socket.socket, target: str = ALL_SPF_ROUTERS):
        """发送 Hello 报文"""
        options = 0x02
        
        for iface_name, iface in self.interfaces.items():
            neighbor_list = list(self.neighbors.keys())
            
            hello = HelloPacket(
                network_mask=iface['netmask'], hello_interval=10, options=options,
                router_priority=1, dr=iface['dr'], bdr=iface['bdr'], neighbor=neighbor_list
            )
            
            msg = OSPFHeader(type=OSPF_TYPE_HELLO, length=24 + len(hello.pack()),
                           router_id=self.router_id, area_id=self.area_id)
            
            packet = msg.pack(hello.pack())
            
            if hasattr(self, 'use_raw') and self.use_raw:
                packet = self._add_ip_header(packet, target)
            
            try:
                sock.sendto(packet, (target, 89))
                self.stats['hello_sent'] += 1
            except Exception as e:
                logger.error(f"发送 Hello 失败: {e}")
    
    def _build_ip_header(self, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
        """构建 IP 头部"""
        version_ihl, tos, total_len = 0x45, 0, 20 + payload_len
        packet_id, flags_fragment, ttl, protocol = 0, 0, 64, 89
        checksum = 0
        
        src_ip_int = socket.inet_aton(src_ip)
        dst_ip_int = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        checksum = self._ip_checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        
        return ip_header
    
    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        checksum = 0
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                word = (header[i] << 8) + header[i + 1]
            else:
                word = header[i] << 8
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF
    
    def _add_ip_header(self, packet: bytes, dst_ip: str) -> bytes:
        """为 OSPF 报文添加 IP 头部"""
        src_ip = self.source_ip if self.source_ip else "0.0.0.0"
        for iface in self.interfaces.values():
            src_ip = iface['ip']
            break
        ip_header = self._build_ip_header(len(packet), src_ip, dst_ip)
        return ip_header + packet
    
    def process_packet(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理收到的 OSPF 报文"""
        try:
            if src_addr == self.router_id:
                return None
            
            my_ips = [iface['ip'] for iface in self.interfaces.values()]
            if src_addr in my_ips:
                return None
            
            header = OSPFHeader.unpack(data)
            
            logger.debug(f"Instance {self.instance_id} 收到 OSPF 报文: type={header.type} from {src_addr}")
            
            if header.type == OSPF_TYPE_HELLO:
                self.stats['hello_recv'] += 1
                return self._process_hello(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_DD:
                self.stats['dd_recv'] += 1
                return self._process_dd(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSR:
                self.stats['lsr_recv'] += 1
                return self._process_lsr(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSU:
                self.stats['lsu_recv'] += 1
                return self._process_lsu(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSACK:
                self.stats['lsack_recv'] += 1
                return self._process_lsack(data[24:], src_addr, header.router_id)
        except Exception as e:
            logger.error(f"Instance {self.instance_id} 处理报文失败: {e}")
        return None
    
    def _process_hello(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 Hello 报文"""
        hello = HelloPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        my_ips = [iface['ip'] for iface in self.interfaces.values()]
        is_2way = any(ip in hello.neighbor for ip in my_ips)
        
        if is_2way:
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.TWOWAY, 'priority': hello.router_priority,
                    'dr': hello.dr, 'bdr': hello.bdr
                }
            else:
                self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
            self._start_dd_exchange(neighbor_id)
        else:
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.INIT, 'priority': hello.router_priority,
                    'dr': hello.dr, 'bdr': hello.bdr
                }
            else:
                if self.neighbors[neighbor_id]['state'] == NeighborState.INIT:
                    self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
                    self._start_dd_exchange(neighbor_id)
        
        logger.info(f"Instance {self.instance_id} 收到 Hello from {neighbor_id}, 状态: {self.neighbors.get(neighbor_id, {}).get('state')}")
        return None
    
    def _start_dd_exchange(self, neighbor_id: str):
        """开始 DD 交换"""
        if neighbor_id not in self.neighbors:
            return
        
        state = self.neighbors[neighbor_id].get('state')
        if state != NeighborState.TWOWAY:
            return
        
        self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
        if 'dd_sequence' not in self.neighbors[neighbor_id]:
            self.neighbors[neighbor_id]['dd_sequence'] = random.randint(1, 0x7FFFFFFF)
        
        self.neighbors[neighbor_id]['sent_initial_dd'] = True
        
        dd = DDPacket(interface_mtu=1500, options=0x02,
                     dd_sequence=self.neighbors[neighbor_id]['dd_sequence'], flags=0x07)
        
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        
        self.stats['dd_sent'] += 1
        return msg.pack(dd.pack())
    
    def _process_dd(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 DD 报文"""
        dd = DDPacket.unpack(data)
        if not dd:
            return None
        
        neighbor_id = peer_router_id if peer_router_id else src_addr
        if neighbor_id not in self.neighbors:
            self.neighbors[neighbor_id] = {'state': NeighborState.INIT, 'priority': 1}
        
        state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
        if state == NeighborState.EXSTART:
            return self._handle_dd_exstart(neighbor_id, dd)
        elif state == NeighborState.EXCHANGE:
            return self._handle_dd_exchange(neighbor_id, dd)
        else:
            self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
            return self._handle_dd_exstart(neighbor_id, dd)
    
    def _handle_dd_exstart(self, neighbor_id: str, dd: DDPacket) -> Optional[bytes]:
        """处理 ExStart 状态的 DD"""
        i_bit = (dd.flags & 0x04) != 0
        
        peer_router_id = dd.lsa_headers[0]['adv_router'] if dd.lsa_headers else neighbor_id
        
        my_id_int = int.from_bytes(socket.inet_aton(self.router_id), 'big')
        peer_id_int = int.from_bytes(socket.inet_aton(peer_router_id), 'big')
        
        if i_bit:
            if my_id_int > peer_id_int:
                self.neighbors[neighbor_id]['is_master'] = True
                self.neighbors[neighbor_id]['dd_sequence'] = int(time.time()) & 0xFFFFFFFF
                return self._send_initial_dd(neighbor_id)
            else:
                self.neighbors[neighbor_id]['is_master'] = False
                self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
                self.neighbors[neighbor_id]['state'] = NeighborState.EXCHANGE
                return self._send_dd_with_lsa(neighbor_id)
        else:
            self.neighbors[neighbor_id]['state'] = NeighborState.EXCHANGE
            return self._send_dd_with_lsa(neighbor_id)
    
    def _handle_dd_exchange(self, neighbor_id: str, dd: DDPacket) -> Optional[bytes]:
        """处理 Exchange 状态的 DD"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        m_bit = (dd.flags & 0x02) != 0
        
        if is_master:
            self.neighbors[neighbor_id]['dd_sequence'] += 1
        else:
            self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence + 1
        
        if not m_bit:
            self.neighbors[neighbor_id]['peer_dd_done'] = True
        
        if self.neighbors[neighbor_id].get('peer_dd_done') and not self.lsdb:
            self.neighbors[neighbor_id]['state'] = NeighborState.LOADING
            return self._send_lsr(neighbor_id)
        
        return self._send_dd_response(neighbor_id)
    
    def _send_initial_dd(self, neighbor_id: str) -> bytes:
        """发送初始 DD"""
        seq = self.neighbors[neighbor_id]['dd_sequence']
        flags = 0x07
        
        dd = DDPacket(interface_mtu=1500, options=0x02, dd_sequence=seq, flags=flags)
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['dd_sent'] += 1
        return msg.pack(dd.pack())
    
    def _send_dd_with_lsa(self, neighbor_id: str) -> bytes:
        """发送带 LSA 摘要的 DD"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        m_bit = 1 if lsa_headers else 0
        flags = (m_bit << 1) | (1 if is_master else 0)
        
        dd = DDPacket(interface_mtu=1500, options=0x02, dd_sequence=seq, flags=flags, lsa_headers=lsa_headers)
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['dd_sent'] += 1
        return msg.pack(dd.pack())
    
    def _send_dd_response(self, neighbor_id: str) -> bytes:
        """发送 DD 响应"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        flags = 0x02 | (1 if is_master else 0)
        
        dd = DDPacket(interface_mtu=1500, options=0x02, dd_sequence=seq, flags=flags, lsa_headers=lsa_headers)
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['dd_sent'] += 1
        return msg.pack(dd.pack())
    
    def _build_lsa_headers(self) -> list:
        """构建 LSA 头部列表"""
        headers = []
        for lsa_key, lsa in self.lsdb.items():
            checksum, length = self._calculate_lsa_checksum_and_length(lsa)
            headers.append({
                'ls_age': lsa.get('age', 0), 'ls_type': lsa.get('type', 1),
                'ls_id': lsa.get('id', '0.0.0.0'), 'adv_router': lsa.get('adv_router', self.router_id),
                'ls_sequence': lsa.get('sequence', 0x80000001), 'checksum': checksum, 'length': length
            })
        return headers
    
    def _calculate_lsa_checksum_and_length(self, lsa: dict) -> Tuple[int, int]:
        """计算 LSA 的 checksum 和 length"""
        lsa_type = lsa.get('type', 1)
        lsa_body = b''
        
        if lsa_type == 1:
            links = lsa.get('links', [])
            lsa_body = struct.pack("!H", len(links))
            for link in links:
                link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                link_data_val = link.get('link_data')
                if isinstance(link_data_val, str):
                    link_data = socket.inet_aton(link_data_val)
                else:
                    link_data = struct.pack("!I", link_data_val if link_data_val else 0)
                link_type = link.get('type', 3)
                metric = link.get('metric', 1)
                lsa_body += struct.pack("!B4s4sBH", link_type, link_id, link_data, 0, metric)
        elif lsa_type == 2:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            lsa_body = network_mask
            for router_id in lsa.get('attached_routers', []):
                lsa_body += socket.inet_aton(router_id)
        elif lsa_type == 3:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        elif lsa_type == 4:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        elif lsa_type == 5:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            e_bit = lsa.get('e_bit', 0)
            metric = struct.pack("!I", lsa.get('metric', 1))
            forwarding = socket.inet_aton(lsa.get('forwarding_address', '0.0.0.0'))
            external_tag = struct.pack("!I", lsa.get('external_route_tag', 0))
            lsa_body = network_mask + bytes([e_bit << 7]) + metric + forwarding + external_tag
        
        lsa_length = 20 + len(lsa_body)
        
        # RFC 2328 Appendix B: LSA checksum is calculated with LS Age set to 0
        lsa_header_with_age = struct.pack("!HBB4s4sIHH",
            lsa.get('age', 0),
            lsa.get('options', 0x02), lsa_type,
            socket.inet_aton(lsa.get('id', '0.0.0.0')),
            socket.inet_aton(lsa.get('adv_router', self.router_id)),
            lsa.get('sequence', 0x80000001), 0, lsa_length
        )
        
        # Use Fletcher-16 checksum (RFC 2328) for LSA, not RFC 1071
        lsa_checksum = calc_lsa_checksum(lsa_header_with_age, lsa_body)
        return lsa_checksum, lsa_length
    
    def _send_lsr(self, neighbor_id: str) -> None:
        """发送 LSR"""
        return None
    
    def _process_lsr(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 LSR"""
        lsr = LSRPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        self.neighbors[neighbor_id]['state'] = NeighborState.LOADING
        
        lsa_key = f"{lsr.ls_type}-{lsr.ls_id}"
        if lsa_key in self.lsdb:
            return self._build_lsu([self.lsdb[lsa_key]], neighbor_id)
        return None
    
    def _process_lsu(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 LSU"""
        lsu = LSUPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        current_state = NeighborState.INIT
        if neighbor_id in self.neighbors:
            current_state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
        if current_state not in (NeighborState.EXCHANGE, NeighborState.LOADING, NeighborState.FULL):
            return None
        
        for entry in lsu.lsa_entries:
            lsa_key = f"{entry['type']}-{entry['id']}"
            self.lsdb[lsa_key] = entry
        
        self._update_routing_table()
        self.neighbors[neighbor_id]['state'] = NeighborState.FULL
        logger.info(f"Instance {self.instance_id} 收到 LSU from {neighbor_id}, LSDB 条目: {len(self.lsdb)}")
        
        return self._build_lsack(lsu.lsa_entries, neighbor_id)
    
    def _process_lsack(self, data: bytes, src_addr: str, peer_router_id: str = None) -> None:
        """处理 LSAck"""
        return None
    
    def _update_routing_table(self):
        """根据 LSDB 更新路由表"""
        for lsa_key, lsa in self.lsdb.items():
            if lsa['type'] == 1:
                for link in lsa.get('links', []):
                    if link['type'] == 3:
                        route_key = f"{link['link_id']}-255.255.255.0"
                        if route_key not in self.routes:
                            self.routes[route_key] = {
                                'network': link['link_id'], 'netmask': '255.255.255.0',
                                'next_hop': link['link_data'], 'cost': link['metric'], 'type': 'ospf'
                            }
    
    def _build_lsu(self, lsa_list: List[dict], target: str) -> bytes:
        """构建 LSU"""
        lsu = LSUPacket(type=1, id=self.router_id, adv_router=self.router_id, lsa_entries=lsa_list)
        msg = OSPFHeader(type=OSPF_TYPE_LSU, length=24 + len(lsu.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['lsu_sent'] += 1
        return msg.pack(lsu.pack())
    
    def _build_lsack(self, lsa_list: List[dict], target: str) -> bytes:
        """构建 LSAck"""
        ack_data = b''
        for lsa in lsa_list:
            ack_data += LSAHeader(
                ls_age=lsa.get('age', 0), options=lsa.get('options', 0x02), ls_type=lsa['type'],
                ls_id=lsa['id'], adv_router=lsa['adv_router'],
                ls_sequence=lsa['sequence'], checksum=lsa.get('checksum', 0), length=20
            ).pack()
        
        msg = OSPFHeader(type=OSPF_TYPE_LSACK, length=24 + len(ack_data),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['lsack_sent'] += 1
        return msg.pack(ack_data)
    
    def flood_lsa(self, sock: socket.socket, use_raw: bool = True, add_ip_header_func=None):
        """泛洪 LSA 到所有邻居"""
        for neighbor_id in self.neighbors:
            if self.neighbors[neighbor_id].get('state') == NeighborState.FULL:
                lsa_list = list(self.lsdb.values())
                packet = self._build_lsu(lsa_list, neighbor_id)
                if use_raw and add_ip_header_func:
                    packet = add_ip_header_func(packet, neighbor_id)
                try:
                    sock.sendto(packet, (neighbor_id, 89))
                except Exception as e:
                    logger.error(f"泛洪 LSA 失败: {e}")
    
    def get_status(self) -> dict:
        """获取状态"""
        return {
            'instance_id': self.instance_id,
            'router_id': self.router_id,
            'area_id': self.area_id,
            'source_ip': self.source_ip,
            'interfaces': len(self.interfaces),
            'neighbors': len(self.neighbors),
            'lsdb_entries': len(self.lsdb),
            'routes': len(self.routes),
            'stats': self.stats.copy()
        }


class OSPFRouter:
    """OSPF 路由器 - 保持向后兼容"""
    
    def __init__(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE, priority: int = 1):
        self.router_id = router_id
        self.area_id = area_id
        self.router_priority = priority
        self.interfaces: Dict[str, dict] = {}
        self.neighbors: Dict[str, dict] = {}
        self.lsdb: Dict[str, dict] = {}
        self.routes: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self.use_raw = True
        
        self.stats = {
            'hello_sent': 0, 'hello_recv': 0,
            'dd_sent': 0, 'dd_recv': 0,
            'lsr_sent': 0, 'lsr_recv': 0,
            'lsu_sent': 0, 'lsu_recv': 0,
            'lsack_sent': 0, 'lsack_recv': 0
        }
        
        self._init_lsdb()
    
    def _init_lsdb(self):
        self.lsdb[f"1-{self.router_id}"] = {
            'type': 1, 'id': self.router_id, 'adv_router': self.router_id,
            'sequence': 0x80000001, 'links': []
        }
    
    def add_interface(self, name: str, ip: str, netmask: str, cost: int = 1, mtu: int = 1500):
        self.interfaces[name] = {
            'ip': ip, 'netmask': netmask, 'cost': cost, 'mtu': mtu,
            'network': self._calc_network(ip, netmask),
            'state': 'DR', 'dr': '0.0.0.0', 'bdr': '0.0.0.0'
        }
        
        network = self._calc_network(ip, netmask)
        lsa_key = f"1-{self.router_id}"
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['links'].append({
                'link_id': network, 'link_data': ip, 'type': 3, 'metric': cost
            })
        
        logger.info(f"添加接口 {name}: {ip}/{netmask}, MTU={mtu}")
    
    def _calc_network(self, ip: str, mask: str) -> str:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
        net_int = ip_int & mask_int
        return socket.inet_ntoa(struct.pack("!I", net_int))
    
    def add_static_route(self, network: str, netmask: str, next_hop: str = "0.0.0.0"):
        route_key = f"{network}-{netmask}"
        self.routes[route_key] = {
            'network': network, 'netmask': netmask, 'next_hop': next_hop, 'cost': 1, 'type': 'static'
        }
        self._inject_route_to_lsa(network, netmask, next_hop)
        logger.info(f"添加静态路由: {network}/{netmask} -> {next_hop}")
    
    def _inject_route_to_lsa(self, network: str, netmask: str, next_hop: str):
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"5-{network_addr}"
        
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 5, 'id': network_addr, 'adv_router': self.router_id,
                'sequence': 0x80000001, 'checksum': 0, 'age': 0, 'options': 0x02,
                'network': network_addr, 'netmask': netmask, 'metric': 1, 'e_bit': 1,
                'forwarding': next_hop if next_hop != "0.0.0.0" else "0.0.0.0",
                'external_route_tag': 0
            }
        
        self.lsdb[lsa_key]['network_mask'] = netmask
        self.lsdb[lsa_key]['forwarding_address'] = next_hop if next_hop != "0.0.0.0" else "0.0.0.0"
        self.lsdb[lsa_key]['e_bit'] = 1
        
        logger.info(f"注入 AS External LSA (Type 5): {network_addr}/{netmask} -> {next_hop}")
    
    def add_summary_route(self, network: str, netmask: str, metric: int = 1, adv_router: str = None):
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"3-{network_addr}"
        advertiser = adv_router if adv_router else self.router_id
        
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 3, 'id': network_addr, 'adv_router': advertiser,
                'sequence': 0x80000001, 'checksum': 0, 'age': 0, 'options': 0x02,
                'network_mask': netmask, 'metric': metric
            }
        
        logger.info(f"注入 Summary LSA (Type 3): {network_addr}/{netmask} metric={metric}")
    
    def add_asbr_summary(self, asbr_router_id: str, metric: int = 1, adv_router: str = None):
        lsa_key = f"4-{asbr_router_id}"
        advertiser = adv_router if adv_router else self.router_id
        
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 4, 'id': asbr_router_id, 'adv_router': advertiser,
                'sequence': 0x80000001, 'checksum': 0, 'age': 0, 'options': 0x02,
                'network_mask': '0.0.0.0', 'metric': metric
            }
        
        logger.info(f"注入 ASBR Summary LSA (Type 4): ASBR={asbr_router_id} metric={metric}")
    
    def generate_routes(self, base_network: str, count: int, prefix: int = 24):
        """
        Generate sequential routes starting from base_network.
        
        Args:
            base_network: Base network address (e.g. "10.0.0.0")
            count: Number of routes to generate
            prefix: CIDR prefix length (default 24)
        
        Returns:
            List of generated network strings (e.g. ["10.0.0.0/24", "10.0.1.0/24", ...])
        """
        parts = base_network.split('.')
        start_third = int(parts[2])
        
        generated = []
        for i in range(count):
            third_octet = (start_third + i) & 0xFF
            network_addr = f"{parts[0]}.{parts[1]}.{third_octet}.0"
            network = f"{network_addr}/{prefix}"
            generated.append(network)
            
            netmask = self._prefix_to_netmask(prefix)
            route_key = f"{network_addr}-{netmask}"
            self.routes[route_key] = {
                'network': network_addr, 'netmask': netmask,
                'next_hop': '0.0.0.0', 'cost': 1, 'type': 'static'
            }
            self._inject_route_to_lsa(network_addr, netmask, '0.0.0.0')
        
        return generated

    def generate_diverse_routes(self, base_network: str, count: int, prefix: int = 24):
        """
        Generate routes distributed across different /16 networks.

        Args:
            base_network: Base network address (used only for first route)
            count: Number of routes to generate
            prefix: CIDR prefix length (default 24)

        Returns:
            List of generated network strings spanning multiple /16 prefixes
        """
        network_prefixes = [
            "10.0.0.0", "10.1.0.0", "10.2.0.0", "172.16.0.0", "172.17.0.0",
            "172.18.0.0", "192.168.0.0", "172.19.0.0", "172.20.0.0",
            "172.21.0.0", "172.22.0.0", "172.23.0.0",
        ]

        generated = []
        for i in range(count):
            prefix_idx = i % len(network_prefixes)
            network_base = network_prefixes[prefix_idx]
            parts = network_base.split('.')
            network_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
            network = f"{network_addr}/{prefix}"
            generated.append(network)

            netmask = self._prefix_to_netmask(prefix)
            route_key = f"{network_addr}-{netmask}"
            self.routes[route_key] = {
                'network': network_addr, 'netmask': netmask,
                'next_hop': '0.0.0.0', 'cost': 1, 'type': 'static'
            }
            self._inject_route_to_lsa(network_addr, netmask, '0.0.0.0')

        return generated

    def _prefix_to_netmask(self, prefix: int) -> str:
        """Convert CIDR prefix to netmask string."""
        mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
        return socket.inet_ntoa(struct.pack('!I', mask))
    
    def remove_static_route(self, network: str, netmask: str = "255.255.255.0",
                           sock=None, use_raw=True, add_ip_header_func=None):
        route_key = f"{network}-{netmask}"
        found = False
        
        if route_key in self.routes:
            del self.routes[route_key]
            logger.info(f"删除静态路由: {network}/{netmask}")
            found = True
        
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"5-{network_addr}"
        
        if lsa_key in self.lsdb:
            if sock is not None:
                maxage_lsa = {
                    'type': 5, 'id': network_addr, 'adv_router': self.router_id,
                    'sequence': 0x7FFFFFFF, 'checksum': 0, 'age': 3600, 'options': 0x02,
                    'network_mask': netmask, 'metric': 0xFFFFFF, 'e_bit': 1,
                    'forwarding_address': '0.0.0.0', 'external_route_tag': 0
                }
                
                lsu = LSUPacket(age=3600, type=5, id=network_addr, adv_router=self.router_id,
                               sequence=0x7FFFFFFF, lsa_entries=[maxage_lsa])
                
                msg = OSPFHeader(type=OSPF_TYPE_LSU, length=24 + len(lsu.pack()),
                               router_id=self.router_id, area_id=self.area_id)
                
                packet = msg.pack(lsu.pack())
                
                for neighbor_id, neighbor_info in self.neighbors.items():
                    if neighbor_info.get('state') == NeighborState.FULL:
                        send_packet = packet
                        if use_raw and add_ip_header_func:
                            send_packet = add_ip_header_func(send_packet, neighbor_id)
                        try:
                            sock.sendto(send_packet, (neighbor_id, 89))
                            logger.info(f"发送 MaxAge LSA 到邻居 {neighbor_id}: {network_addr}/{netmask}")
                            self.stats['lsu_sent'] += 1
                        except Exception as e:
                            logger.error(f"发送 MaxAge LSA 失败: {e}")
            
            del self.lsdb[lsa_key]
            logger.info(f"撤销 AS External LSA: {network_addr}/{netmask}")
        
        return found
    
    def send_hello(self, sock: socket.socket, target: str = ALL_SPF_ROUTERS, options: int = None):
        if options is None:
            options = 0x02
            
        for iface_name, iface in self.interfaces.items():
            neighbor_list = list(self.neighbors.keys())
            
            hello = HelloPacket(
                network_mask=iface['netmask'], hello_interval=10, options=options,
                router_priority=1, dr=iface['dr'], bdr=iface['bdr'], neighbor=neighbor_list
            )
            
            msg = OSPFHeader(type=OSPF_TYPE_HELLO, length=24 + len(hello.pack()),
                           router_id=self.router_id, area_id=self.area_id)
            
            packet = msg.pack(hello.pack())
            
            if hasattr(self, 'use_raw') and self.use_raw:
                packet = self._add_ip_header(packet, target)
            
            try:
                sock.sendto(packet, (target, 89))
                self.stats['hello_sent'] += 1
                logger.debug(f"发送 Hello 到 {target} 从接口 {iface_name}")
            except Exception as e:
                logger.error(f"发送 Hello 失败: {e}")
    
    def process_packet(self, data: bytes, src_addr: str) -> Optional[bytes]:
        """处理收到的 OSPF 报文"""
        try:
            if src_addr == self.router_id:
                logger.debug(f"忽略来自自己的报文: {src_addr}")
                return None
            
            my_ips = [iface['ip'] for iface in self.interfaces.values()]
            if src_addr in my_ips:
                logger.debug(f"忽略来自自己接口的报文: {src_addr}")
                return None
            
            header = OSPFHeader.unpack(data)
            
            received_checksum = header.checksum
            calculated_checksum = calc_checksum(data[:12] + b'\x00\x00' + data[14:])
            if received_checksum != calculated_checksum:
                logger.warning(f"Checksum 校验失败: expected={calculated_checksum}, got={received_checksum}")
            
            logger.debug(f"收到 OSPF 报文: type={header.type} from {src_addr}")
            
            if header.type == OSPF_TYPE_HELLO:
                self.stats['hello_recv'] += 1
                return self._process_hello(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_DD:
                self.stats['dd_recv'] += 1
                return self._process_dd(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSR:
                self.stats['lsr_recv'] += 1
                return self._process_lsr(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSU:
                self.stats['lsu_recv'] += 1
                return self._process_lsu(data[24:], src_addr, header.router_id)
            elif header.type == OSPF_TYPE_LSACK:
                self.stats['lsack_recv'] += 1
                return self._process_lsack(data[24:], src_addr, header.router_id)
        except Exception as e:
            logger.error(f"处理报文失败: {e}")
        return None
    
    def _process_hello(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        hello = HelloPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        response = None
        
        my_ips = [iface['ip'] for iface in self.interfaces.values()]
        is_2way = any(ip in hello.neighbor for ip in my_ips)
        
        if is_2way:
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.TWOWAY, 'priority': hello.router_priority,
                    'dr': hello.dr, 'bdr': hello.bdr
                }
            else:
                self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
            response = self._start_dd_exchange(neighbor_id)
        else:
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.INIT, 'priority': hello.router_priority,
                    'dr': hello.dr, 'bdr': hello.bdr
                }
            else:
                if self.neighbors[neighbor_id]['state'] == NeighborState.INIT:
                    self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
                    response = self._start_dd_exchange(neighbor_id)
        
        logger.info(f"收到 Hello from {neighbor_id}, 邻居状态: {self.neighbors[neighbor_id]['state']}")
        return response
    
    def _start_dd_exchange(self, neighbor_id: str):
        if neighbor_id not in self.neighbors:
            return
        
        state = self.neighbors[neighbor_id].get('state')
        if state != NeighborState.TWOWAY:
            return
        
        self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
        if 'dd_sequence' not in self.neighbors[neighbor_id]:
            self.neighbors[neighbor_id]['dd_sequence'] = random.randint(1, 0x7FFFFFFF)
        
        self.neighbors[neighbor_id]['sent_initial_dd'] = True
        
        dd = DDPacket(interface_mtu=1500, options=0x02,
                     dd_sequence=self.neighbors[neighbor_id]['dd_sequence'], flags=0x07)
        
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        
        self.stats['dd_sent'] += 1
        return msg.pack(dd.pack())
    
    def _process_dd(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        dd = DDPacket.unpack(data)
        if not dd:
            return None
        
        neighbor_id = self._get_neighbor_id(peer_router_id, src_addr)
        self._ensure_neighbor_exists(neighbor_id)
        
        current_state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
        if current_state == NeighborState.EXSTART:
            return self._handle_dd_exstart(neighbor_id, dd, src_addr)
        elif current_state == NeighborState.EXCHANGE:
            return self._handle_dd_exchange(neighbor_id, dd, src_addr)
        else:
            return self._handle_dd_other_state(neighbor_id, dd, src_addr)

    def _get_neighbor_id(self, peer_router_id: str, src_addr: str) -> str:
        return peer_router_id if peer_router_id else src_addr

    def _ensure_neighbor_exists(self, neighbor_id: str):
        if neighbor_id not in self.neighbors:
            self.ne

    def _handle_dd_exstart(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        i_bit = self._parse_i_bit(dd.flags)
        peer_router_id = dd.lsa_headers[0]['adv_router'] if dd.lsa_headers else neighbor_id
        
        my_id_int = self._get_router_id_int()
        peer_id_int = self._get_router_id_int(peer_router_id)
        
        if i_bit:
            if my_id_int > peer_id_int:
                logger.info(f"本端 Router ID ({self.router_id}) > 对端 ({peer_router_id}), 重新发送 I=1 初始化 DD")
                self.neighbors[neighbor_id]['is_master'] = True
                self.neighbors[neighbor_id]['dd_sequence'] = self._generate_dd_sequence()
                return self._send_initial_dd(neighbor_id)
            else:
                logger.info(f"本端 Router ID ({self.router_id}) < 对端 ({peer_router_id}), 对端是 Master")
                self.neighbors[neighbor_id]['is_master'] = False
                self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
                self._transition_to_exchange(neighbor_id)
                return self._send_dd_with_lsa(neighbor_id)
        else:
            logger.info(f"收到对端 I=0 的 DD, 进入 exchange 状态")
            self._elect_master_slave(neighbor_id, dd)
            self._transition_to_exchange(neighbor_id)
            return self._send_dd_with_lsa(neighbor_id)

    def _parse_i_bit(self, flags: int) -> bool:
        return (flags & 0x04) != 0

    def _parse_m_bit(self, flags: int) -> bool:
        return (flags & 0x02) != 0

    def _parse_ms_bit(self, flags: int) -> bool:
        return (flags & 0x01) != 0

    def _elect_master_slave(self, neighbor_id: str, dd: DDPacket):
        my_id = self._get_router_id_int()
        peer_id = self._get_router_id_int(neighbor_id)
        
        if peer_id > my_id:
            self.neighbors[neighbor_id]['is_master'] = False
            self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
        else:
            self.neighbors[neighbor_id]['is_master'] = True
            self.neighbors[neighbor_id]['dd_sequence'] = self._generate_dd_sequence()

    def _get_router_id_int(self, router_id: str = None) -> int:
        rid = router_id if router_id else self.router_id
        return int.from_bytes(socket.inet_aton(rid), 'big')

    def _generate_dd_sequence(self) -> int:
        return int(time.time()) & 0xFFFFFFFF

    def _transition_to_exchange(self, neighbor_id: str):
        self.neighbors[neighbor_id]['state'] = NeighborState.EXCHANGE

    def _handle_dd_exchange(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        m_bit = self._parse_m_bit(dd.flags)
        
        self._update_dd_sequence(neighbor_id, dd, is_master)
        if not m_bit:
            self.neighbors[neighbor_id]['peer_dd_done'] = True
        
        if self.neighbors[neighbor_id].get('peer_dd_done') and not self.lsdb:
            self.neighbors[neighbor_id]['state'] = NeighborState.LOADING
            return self._send_lsr(neighbor_id)
        
        return self._send_dd_response(neighbor_id)

    def _update_dd_sequence(self, neighbor_id: str, dd: DDPacket, is_master: bool):
        if is_master:
            self.neighbors[neighbor_id]['dd_sequence'] += 1
        else:
            self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence + 1

    def _handle_dd_other_state(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
        return self._handle_dd_exstart(neighbor_id, dd, src_addr)

    def _send_initial_dd(self, neighbor_id: str) -> Optional[bytes]:
        is_master = self.neighbors[neighbor_id].get('is_master', True)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        flags = 0x07
        logger.debug(f"发送初始 DD: I=1, M=1, MS={'1' if is_master else '0'}, seq={seq}")
        return self._build_dd_packet(neighbor_id, seq, flags, [])
    
    def _send_dd_with_lsa(self, neighbor_id: str) -> Optional[bytes]:
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        m_bit = 1 if lsa_headers else 0
        flags = (m_bit << 1) | (1 if is_master else 0)
        logger.debug(f"发送 DD (带 LSA 摘要): I=0, M={m_bit}, MS={'1' if is_master else '0'}, seq={seq}, lsa_count={len(lsa_headers)}")
        return self._build_dd_packet(neighbor_id, seq, flags, lsa_headers)

    def _send_dd_response(self, neighbor_id: str) -> Optional[bytes]:
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        flags = (1 if len(lsa_headers) else 0) | (1 if is_master else 0)
        return self._build_dd_packet(neighbor_id, seq, flags, lsa_headers)

    def _build_lsa_headers(self) -> list:
        headers = []
        for lsa_key, lsa in self.lsdb.items():
            checksum, length = self._calculate_lsa_checksum_and_length(lsa)
            headers.append({
                'ls_age': lsa.get('age', 0), 'ls_type': lsa.get('type', 1),
                'ls_id': lsa.get('id', '0.0.0.0'), 'adv_router': lsa.get('adv_router', self.router_id),
                'ls_sequence': lsa.get('sequence', 0x80000001), 'checksum': checksum, 'length': length
            })
        return headers

    def _calculate_lsa_checksum_and_length(self, lsa: dict) -> Tuple[int, int]:
        lsa_type = lsa.get('type', 1)
        lsa_body = b''
        
        if lsa_type == 1:
            links = lsa.get('links', [])
            lsa_body = struct.pack("!H", len(links))
            for link in links:
                link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                link_data_val = link.get('link_data')
                if isinstance(link_data_val, str):
                    link_data = socket.inet_aton(link_data_val)
                else:
                    link_data = struct.pack("!I", link_data_val if link_data_val else 0)
                link_type = link.get('type', 3)
                metric = link.get('metric', 1)
                lsa_body += struct.pack("!B4s4sBH", link_type, link_id, link_data, 0, metric)
        elif lsa_type == 2:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            lsa_body = network_mask
            for router_id in lsa.get('attached_routers', []):
                lsa_body += socket.inet_aton(router_id)
        elif lsa_type == 3:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        elif lsa_type == 4:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        elif lsa_type == 5:
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            e_bit = lsa.get('e_bit', 0)
            metric = struct.pack("!I", lsa.get('metric', 1))
            forwarding = socket.inet_aton(lsa.get('forwarding_address', '0.0.0.0'))
            external_tag = struct.pack("!I", lsa.get('external_route_tag', 0))
            lsa_body = network_mask + bytes([e_bit << 7]) + metric + forwarding + external_tag
        
        lsa_length = 20 + len(lsa_body)
        
        # RFC 2328 Appendix B: LSA checksum is calculated with LS Age set to 0
        lsa_header_with_age = struct.pack("!HBB4s4sIHH",
            lsa.get('age', 0),
            lsa.get('options', 0x02), lsa_type,
            socket.inet_aton(lsa.get('id', '0.0.0.0')),
            socket.inet_aton(lsa.get('adv_router', self.router_id)),
            lsa.get('sequence', 0x80000001), 0, lsa_length
        )
        
        # Use Fletcher-16 checksum (RFC 2328) for LSA, not RFC 1071
        lsa_checksum = calc_lsa_checksum(lsa_header_with_age, lsa_body)
        return lsa_checksum, lsa_length

    def _build_dd_packet(self, neighbor_id: str, seq: int, flags: int, lsa_headers: list) -> bytes:
        my_dd = DDPacket(interface_mtu=1500, options=0x02, dd_sequence=seq, flags=flags, lsa_headers=lsa_headers)
        msg = OSPFHeader(type=OSPF_TYPE_DD, length=24 + len(my_dd.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['dd_sent'] += 1
        return msg.pack(my_dd.pack())

    def _send_lsr(self, neighbor_id: str) -> Optional[bytes]:
        return None
    
    def _process_lsr(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        lsr = LSRPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        self._update_neighbor_state(neighbor_id, NeighborState.LOADING)
        
        lsa_key = f"{lsr.ls_type}-{lsr.ls_id}"
        if lsa_key in self.lsdb:
            return self._build_lsu([self.lsdb[lsa_key]], neighbor_id)
        return None
    
    def _process_lsu(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        lsu = LSUPacket.unpack(data)
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        current_state = NeighborState.INIT
        if neighbor_id in self.neighbors:
            current_state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
        if current_state not in (NeighborState.EXCHANGE, NeighborState.LOADING, NeighborState.FULL):
            logger.warning(f"邻居状态 {current_state} < EXCHANGE，忽略LSU")
            return None
        
        for entry in lsu.lsa_entries:
            lsa_key = f"{entry['type']}-{entry['id']}"
            self.lsdb[lsa_key] = entry
        
        self._update_routing_table()
        self._update_neighbor_state(neighbor_id, NeighborState.FULL)
        logger.info(f"收到 LSU from {neighbor_id}, LSDB 条目数: {len(self.lsdb)}")
        
        return self._build_lsack(lsu.lsa_entries, neighbor_id)
    
    def _process_lsack(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        neighbor_id = peer_router_id if peer_router_id else src_addr
        logger.debug(f"收到 LSAck from {neighbor_id}")
        return None
    
    def _update_neighbor_state(self, neighbor_id: str, state: NeighborState):
        if neighbor_id in self.neighbors:
            self.neighbors[neighbor_id]['state'] = state
        else:
            self.neighbors[neighbor_id] = {'state': state}
    
    def _update_routing_table(self):
        for lsa_key, lsa in self.lsdb.items():
            if lsa['type'] == 1:
                for link in lsa.get('links', []):
                    if link['type'] == 3:
                        route_key = f"{link['link_id']}-255.255.255.0"
                        if route_key not in self.routes:
                            self.routes[route_key] = {
                                'network': link['link_id'], 'netmask': '255.255.255.0',
                                'next_hop': link['link_data'], 'cost': link['metric'], 'type': 'ospf'
                            }
    
    def _build_lsu(self, lsa_list: List[dict], target: str) -> bytes:
        lsu = LSUPacket(type=1, id=self.router_id, adv_router=self.router_id, lsa_entries=lsa_list)
        msg = OSPFHeader(type=OSPF_TYPE_LSU, length=24 + len(lsu.pack()),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['lsu_sent'] += 1
        return msg.pack(lsu.pack())
    
    def _build_lsack(self, lsa_list: List[dict], target: str) -> bytes:
        ack_data = b''
        for lsa in lsa_list:
            ack_data += LSAHeader(
                ls_age=lsa.get('age', 0), options=lsa.get('options', 0x02), ls_type=lsa['type'],
                ls_id=lsa['id'], adv_router=lsa['adv_router'],
                ls_sequence=lsa['sequence'], checksum=lsa.get('checksum', 0), length=20
            ).pack()
        
        msg = OSPFHeader(type=OSPF_TYPE_LSACK, length=24 + len(ack_data),
                        router_id=self.router_id, area_id=self.area_id)
        self.stats['lsack_sent'] += 1
        return msg.pack(ack_data)
    
    def get_status(self) -> dict:
        return {
            'router_id': self.router_id, 'area_id': self.area_id,
            'interfaces': len(self.interfaces), 'neighbors': len(self.neighbors),
            'lsdb_entries': len(self.lsdb), 'routes': len(self.routes), 'stats': self.stats
        }
    
    def flood_lsa(self, sock: socket.socket, use_raw: bool = True, add_ip_header_func=None):
        for neighbor_id in self.neighbors:
            if self.neighbors[neighbor_id].get('state') == NeighborState.FULL:
                lsa_list = list(self.lsdb.values())
                packet = self._build_lsu(lsa_list, neighbor_id)
                if use_raw and add_ip_header_func:
                    packet = add_ip_header_func(packet, neighbor_id)
                try:
                    sock.sendto(packet, (neighbor_id, 89))
                except Exception as e:
                    logger.error(f"泛洪 LSA 失败: {e}")
    
    def _build_ip_header(self, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
        version_ihl, tos, total_len = 0x45, 0, 20 + payload_len
        packet_id, flags_fragment, ttl, protocol = 0, 0, 64, 89
        checksum = 0
        
        src_ip_int = socket.inet_aton(src_ip)
        dst_ip_int = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        checksum = self._ip_checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        
        return ip_header
    
    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        checksum = 0
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                word = (header[i] << 8) + header[i + 1]
            else:
                word = header[i] << 8
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF
    
    def _add_ip_header(self, packet: bytes, dst_ip: str) -> bytes:
        src_ip = "0.0.0.0"
        for iface in self.interfaces.values():
            src_ip = iface['ip']
            break
        ip_header = self._build_ip_header(len(packet), src_ip, dst_ip)
        return ip_header + packet


class OSPFSimulator:
    """OSPF 模拟器主类 - 支持多实例"""
    
    def __init__(self, router_id: str = None, area_id: str = OSPF_AREA_BACKBONE, priority: int = 1):
        """
        初始化 OSPF 模拟器
        
        Args:
            router_id: Router ID (可选，兼容旧API)
            area_id: Area ID
            priority: DD 优先级
        """
        self.router = OSPFRouter(router_id or "0.0.0.0", area_id, priority)
        self.sock = None
        self.running = False
        self.threads: List[threading.Thread] = []
        self.use_raw = True
        
        # 多实例支持
        self.instances: Dict[int, OSPFInstance] = {}
        self.next_instance_id = 1
    
    def create_instance(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE,
                       source_ip: str = None, priority: int = 1) -> OSPFInstance:
        """
        创建新的 OSPF 实例
        
        Args:
            router_id: Router ID
            area_id: Area ID
            source_ip: 源 IP (物理接口上的 IP)
            priority: DD 优先级
        
        Returns:
            OSPFInstance: 新创建的实例
        """
        instance_id = self.next_instance_id
        self.next_instance_id += 1
        
        instance = OSPFInstance(
            instance_id=instance_id,
            router_id=router_id,
            area_id=area_id,
            source_ip=source_ip,
            priority=priority
        )
        
        self.instances[instance_id] = instance
        logger.info(f"创建 OSPF 实例 {instance_id}: Router ID={router_id}, Area={area_id}, Source IP={source_ip}")
        
        return instance
    
    def delete_instance(self, instance_id: int) -> bool:
        """
        删除 OSPF 实例
        
        Args:
            instance_id: 实例 ID
        
        Returns:
            bool: 是否成功删除
        """
        if instance_id in self.instances:
            del self.instances[instance_id]
            logger.info(f"删除 OSPF 实例 {instance_id}")
            return True
        return False
    
    def get_instance(self, instance_id: int) -> Optional[OSPFInstance]:
        """获取实例"""
        return self.instances.get(instance_id)
    
    def list_instances(self) -> List[OSPFInstance]:
        """列出所有实例"""
        return list(self.instances.values())
    
    def _build_ip_header(self, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
        version_ihl, tos, total_len = 0x45, 0, 20 + payload_len
        packet_id, flags_fragment, ttl, protocol = 0, 0, 64, 89
        checksum = 0
        
        src_ip_int = socket.inet_aton(src_ip)
        dst_ip_int = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        checksum = self._ip_checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
            version_ihl, tos, total_len, packet_id,
            flags_fragment, ttl, protocol, checksum,
            src_ip_int, dst_ip_int)
        
        return ip_header
    
    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        checksum = 0
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                word = (header[i] << 8) + header[i + 1]
            else:
                word = header[i] << 8
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF
    
    def _add_ip_header(self, packet: bytes, dst_ip: str) -> bytes:
        src_ip = "0.0.0.0"
        for iface in self.router.interfaces.values():
            src_ip = iface['ip']
            break
        ip_header = self._build_ip_header(len(packet), src_ip, dst_ip)
        return ip_header + packet
    
    def start(self):
        """启动模拟器"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
        except PermissionError:
            logger.warning("需要 root 权限使用 Raw Socket，回退到 UDP")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.use_raw = False
        else:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.use_raw = True
        
        self.router.use_raw = self.use_raw
        
        # 设置所有实例的 use_raw
        for instance in self.instances.values():
            instance.use_raw = self.use_raw
        
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 89))
        
        try:
            mreq = struct.pack("4sl", socket.inet_aton(ALL_SPF_ROUTERS), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
            pass
        
        self.running = True
        
        t = threading.Thread(target=self._hello_sender, daemon=True)
        t.start()
        self.threads.append(t)
        
        t = threading.Thread(target=self._packet_receiver, daemon=True)
        t.start()
        self.threads.append(t)
        
        logger.info(f"OSPF 模拟器启动, Router ID: {self.router.router_id}, 多实例数: {len(self.instances)}")
    
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
            # 发送主 router 的 Hello
            self.router.send_hello(self.sock)
            
            # 发送所有实例的 Hello
            for instance in self.instances.values():
                instance.send_hello(self.sock)
            
            time.sleep(10)
    
    def _packet_receiver(self):
        """报文接收线程"""
        self.sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    if self.use_raw and len(data) > 20:
                        ospf_data = data[20:]
                    else:
                        ospf_data = data
                    
                    # 处理主 router 的报文
                    response = self.router.process_packet(ospf_data, addr[0])
                    if response:
                        if self.use_raw:
                            response = self._add_ip_header(response, addr[0])
                        self.sock.sendto(response, (addr[0], 89))
                    
                    # 处理所有实例的报文
                    for instance in self.instances.values():
                        response = instance.process_packet(ospf_data, addr[0])
                        if response:
                            if self.use_raw:
                                response = instance._add_ip_header(response, addr[0])
                            self.sock.sendto(response, (addr[0], 89))
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"接收报文错误: {e}")
    
    def get_status(self) -> dict:
        """获取状态"""
        status = self.router.get_status()
        status['instances'] = len(self.instances)
        status['instance_details'] = [inst.get_status() for inst in self.instances.values()]
        return status


if __name__ == "__main__":
    # 测试
    sim = OSPFSimulator("192.168.1.1")
    sim.router.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    
    # 创建第二个 OSPF 实例
    inst2 = sim.create_instance(router_id="192.168.1.2", area_id="0.0.0.0", source_ip="192.168.1.1")
    inst2.add_interface("eth0", "192.168.1.1", "255.255.255.0")
    
    sim.start()
    
    print("OSPF 模拟器运行中 (多实例)...")
    time.sleep(5)
    print(sim.get_status())
    
    sim.stop()
