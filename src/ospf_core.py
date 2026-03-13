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


# RFC 1071 checksum calculation (used by OSPF)
# Returns 16-bit one's complement of one's complement sum
def calc_checksum(data: bytes) -> int:
    """Calculate RFC 1071 checksum for OSPF packets"""
    if len(data) % 2 == 1:
        data += b'\x00'  # Pad to even length
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    # Add carry bits
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # One's complement
    return (~checksum) & 0xFFFF


def get_system_interfaces() -> Dict[str, dict]:
    """
    获取系统网络接口列表
    
    Returns:
        Dict: {接口名: {'ip': IP地址, 'netmask': 子网掩码, 'mac': MAC地址}}
    """
    interfaces = {}
    
    if HAS_NETIFACES:
        # 使用 netifaces 库
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            iface_info = {'ip': None, 'netmask': None, 'mac': None}
            
            # 获取 IPv4 地址
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    iface_info['ip'] = addr.get('addr')
                    iface_info['netmask'] = addr.get('netmask')
                    break  # 只取第一个 IPv4
            
            # 获取 MAC 地址
            if netifaces.AF_LINK in addrs:
                iface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr')
            
            # 过滤掉回环和未配置的接口
            if iface_info['ip'] and iface != 'lo':
                interfaces[iface] = iface_info
    else:
        # 备用方案: 使用系统命令
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
    """解析 Linux ip addr 输出"""
    current_iface = None
    for line in output.split('\n'):
        line = line.strip()
        if line and not line.startswith(' '):
            # 新接口
            parts = line.split(':')
            if len(parts) >= 2:
                current_iface = parts[1].strip()
                interfaces[current_iface] = {'ip': None, 'netmask': None, 'mac': None}
        elif 'inet ' in line and current_iface:
            # IPv4 地址
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[1].split('/')[0]
                netmask = parts[3] if len(parts) > 3 else '255.255.255.0'
                interfaces[current_iface]['ip'] = ip
                interfaces[current_iface]['netmask'] = netmask
        elif 'link/ether' in line and current_iface:
            # MAC 地址
            parts = line.split()
            if len(parts) >= 2:
                interfaces[current_iface]['mac'] = parts[1]
    
    # 过滤
    for iface in list(interfaces.keys()):
        if not interfaces[iface]['ip'] or iface == 'lo':
            del interfaces[iface]


def _parse_windows_ipconfig(output: str, interfaces: dict):
    """解析 Windows ipconfig 输出"""
    current_iface = None
    for line in output.split('\n'):
        line = line.strip()
        if '适配器' in line or 'Adapter' in line:
            # 新接口
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
    
    # 过滤
    for iface in list(interfaces.keys()):
        if not interfaces[iface]['ip']:
            del interfaces[iface]


def cidr_to_netmask(cidr: str) -> str:
    """
    将 CIDR 转换为点分十进制子网掩码
    例如: 24 -> 255.255.255.0
    """
    if '/' not in cidr:
        return cidr
    
    ip, prefix = cidr.split('/')
    prefix = int(prefix)
    
    mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return socket.inet_ntoa(struct.pack('!I', mask))


def netmask_to_cidr(netmask: str) -> int:
    """
    将点分十进制子网掩码转换为 CIDR 前缀长度
    例如: 255.255.255.0 -> 24
    """
    mask = socket.inet_aton(netmask)
    return bin(struct.unpack('!I', mask)[0]).count('1')

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
    
    def pack(self, body: bytes = b'') -> bytes:
        """打包 OSPF 头部 (含 checksum 计算)
        
        Args:
            body: 报文主体部分 (Hello/DD/LSR/LSU/LSAck 的 pack() 结果)
        """
        # 先用 checksum=0 打包
        header = struct.pack("!BBH4s4sHH8s",
            self.version,
            self.type,
            self.length,
            socket.inet_aton(self.router_id),
            socket.inet_aton(self.area_id),
            0,  # checksum 初始为 0
            self.auth_type,
            self.auth.to_bytes(8, 'big') if isinstance(self.auth, int) else self.auth
        )
        # 计算 checksum - 需要覆盖整个 OSPF 报文 (header + body)
        full_packet = header + body
        checksum = calc_checksum(full_packet)
        # 替换 checksum 字段 (偏移 12 字节处，2 字节)
        header = header[:12] + struct.pack("!H", checksum) + header[14:]
        return header + body
    
    @classmethod
    def unpack(cls, data: bytes) -> 'OSPFHeader':
        """解包 OSPF 头部"""
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
        """打包 Hello 报文"""
        # 格式: NetworkMask(4) HelloInterval(2) Options(1) Priority(1) DeadInterval(4) DR(4) BDR(4) = 20字节
        data = struct.pack("!4sHBB I 4s 4s".replace(" ", ""),
            socket.inet_aton(self.network_mask),
            self.hello_interval,
            self.options,
            self.router_priority,
            self.dead_interval,
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
    flags: int = 0  # R=0, I=0, M=0, MS=0
    interface_mtu: int = 1500  # Interface MTU
    lsa_headers: List[dict] = field(default_factory=list)  # LSA 头部列表
    
    def pack(self) -> bytes:
        """打包 DD 报文 (RFC 2328 Appendix A)"""
        # DD Header: MTU(2) + Options(1) + Flags(1) + DD Sequence(4) = 8 bytes
        dd_header = struct.pack("!HBB I",
            self.interface_mtu,
            self.options,
            self.flags,
            self.dd_sequence
        )
        # 追加 LSA 头部 (每个 20 字节)
        # LSA Header: age(2) + options(1) + type(1) + id(4) + adv_router(4) + seq(4) + checksum(2) + length(2)
        lsa_data = b''
        for lsa in self.lsa_headers:
            lsa_header = struct.pack("!HBB4s4sIHH",
                lsa.get('age', 0),
                lsa.get('options', 0x02),
                lsa.get('type', 1),
                socket.inet_aton(lsa.get('id', '0.0.0.0')),
                socket.inet_aton(lsa.get('adv_router', '0.0.0.0')),
                lsa.get('sequence', 0x80000001),
                lsa.get('checksum', 0),
                lsa.get('length', 20)
            )
            lsa_data += lsa_header
        return dd_header + lsa_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DDPacket':
        if len(data) < 8:
            return cls()
        # 解析 DD Header
        mtu, opts, flags, seq = struct.unpack("!HBB I", data[:8])
        # 解析 LSA Headers (每个 20 字节)
        lsa_headers = []
        offset = 8
        while offset + 20 <= len(data):
            lsa = struct.unpack("!HBB4s4sIHH", data[offset:offset+20])
            lsa_headers.append({
                'age': lsa[0],
                'options': lsa[1],
                'type': lsa[2],
                'id': socket.inet_ntoa(lsa[3]),
                'adv_router': socket.inet_ntoa(lsa[4]),
                'sequence': lsa[5],
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
        """打包 LSU 报文 (RFC 2328)"""
        # LSA 头部列表
        lsa_data = b''
        for entry in self.lsa_entries:
            lsa_type = entry.get('type', 1)
            
            # 构建完整的 LSA 主体 (除 header 外的部分)
            lsa_body = b''
            
            if lsa_type == 1:  # Router LSA
                links = entry.get('links', [])
                # # links (2 bytes)
                lsa_body = struct.pack("!H", len(links))
                for link in links:
                    # RFC 2328: #links(2) + TOS(1) + metric(2) + LinkID(4) + LinkData(4) = 13 bytes
                    link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                    link_data = socket.inet_aton(link.get('link_data', '0.0.0.0'))
                    link_type = link.get('type', 3)
                    metric = link.get('metric', 1)
                    lsa_body += struct.pack("!HHB4s4s", link_type, metric, 0, link_id, link_data)
                
                lsa_length = 20 + len(lsa_body)  # Header + body
            elif lsa_type == 2:  # Network LSA
                routers = entry.get('attached_routers', [])
                # Network Mask (4) + 路由器列表
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                lsa_body = network_mask
                for r in routers:
                    lsa_body += socket.inet_aton(r)
                lsa_length = 20 + len(lsa_body)
            else:
                lsa_length = 20
            
            # LSA Header: age(2) + options(1) + type(1) + id(4) + adv_router(4) + seq(4) + checksum(2) + length(2)
            lsa_header = struct.pack("!HBB4s4sIHH",
                entry.get('age', 0),
                entry.get('options', 0x02),
                lsa_type,
                socket.inet_aton(entry.get('id', '0.0.0.0')),
                socket.inet_aton(entry.get('adv_router', '0.0.0.0')),
                entry.get('sequence', 0x80000001),
                0,  # checksum 初始为 0
                lsa_length
            )
            # 计算整个 LSA 的校验和
            lsa_checksum = calc_checksum(lsa_header + lsa_body)
            
            # 重新打包 header 带正确的 checksum
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
        
        # LSU格式: # LSAs(4) + LSA列表（每个LSA = Header 20 + Body）
        return struct.pack("!I", len(self.lsa_entries)) + lsa_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSUPacket':
        # LSU: # LSAs(4) + LSU Header(20) + LSA列表
        if len(data) < 24:  # 4 + 20
            return cls()
        # 解析LSA数量
        num_lsas = struct.unpack("!I", data[:4])[0]
        # LSU报文格式: # LSAs(4) + LSA列表（每个LSA = Header 20 + Body）
        # 不需要单独的LSU Header
        entries = []
        offset = 4  # 跳过#LSAs后直接是LSA
        # 解析每个LSA (Header 20字节 + Body 可变长度)
        for _ in range(num_lsas):
            if offset + 20 > len(data):
                break
            # 解析LSA Header
            header = struct.unpack("!HBB4s4sIHH", data[offset:offset+20])
            lsa_type = header[2]
            lsa_length = header[7]  # LSA总长度
            
            # 解析LSA Body (根据类型)
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
            
            # 根据LSA类型解析Body
            if lsa_type == 1 and len(body) >= 2:  # Router LSA
                num_links = struct.unpack("!H", body[:2])[0]
                links = []
                link_offset = 2
                for i in range(num_links):
                    if link_offset + 13 <= len(body):
                        link = struct.unpack("!HHB4s4s", body[link_offset:link_offset+13])
                        links.append({
                            'link_id': socket.inet_ntoa(link[3]),
                            'link_data': socket.inet_ntoa(link[4]),
                            'type': link[0],
                            'metric': link[1]
                        })
                        link_offset += 13
                entry_data['links'] = links
                
            elif lsa_type == 2 and len(body) >= 4:  # Network LSA
                network_mask = socket.inet_ntoa(body[:4])
                entry_data['network_mask'] = network_mask
                routers = []
                offset_r = 4
                while offset_r + 4 <= len(body):
                    routers.append(socket.inet_ntoa(body[offset_r:offset_r+4]))
                    offset_r += 4
                entry_data['attached_routers'] = routers
                
            elif lsa_type == 3:  # Network Summary LSA (Summary LSA)
                # Network Mask (4) + metric (4) = 8 bytes
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 8:
                    entry_data['metric'] = struct.unpack("!I", body[4:8])[0]
                    
            elif lsa_type == 4:  # ASBR Summary LSA
                # Network Mask (4) + metric (4) = 8 bytes  
                if len(body) >= 4:
                    entry_data['network_mask'] = socket.inet_ntoa(body[:4])
                if len(body) >= 8:
                    entry_data['metric'] = struct.unpack("!I", body[4:8])[0]
                    
            elif lsa_type == 5:  # AS External LSA (External LSA)
                # Network Mask (4) + E-bit (1) + metric (4) + Forwarding Address (4) + External Route Tag (4) = 17+ bytes
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
                    
            elif lsa_type == 7:  # NSSA External LSA
                # 类似Type 5但用于NSSA区域
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
            # 按LSA总长度跳转
            offset += lsa_length
        # LSU的元数据从类默认值或从第一个LSA获取
        first_lsa = entries[0] if entries else {}
        # LSU元数据使用默认值
        return cls(
            age=0,
            type=1,
            id="0.0.0.0",
            adv_router="0.0.0.0",
            sequence=0,
            checksum=0,
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
        """打包LSA头部 (20字节)"""
        # LSA Header: age(2) + options(1) + type(1) + id(4) + adv_router(4) + seq(4) + checksum(2) + length(2) = 20 bytes
        return struct.pack("!HBB4s4sIHH",
            self.ls_age,
            self.options,
            self.ls_type,
            socket.inet_aton(self.ls_id),
            socket.inet_aton(self.adv_router),
            self.ls_sequence,
            self.checksum,
            self.length
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'LSAHeader':
        """解包LSA头部"""
        if len(data) < 20:
            return cls()
        fields = struct.unpack("!HBB4s4sIHH", data[:20])
        return cls(
            ls_age=fields[0],
            options=fields[1],
            ls_type=fields[2],
            ls_id=socket.inet_ntoa(fields[3]),
            adv_router=socket.inet_ntoa(fields[4]),
            ls_sequence=fields[5],
            checksum=fields[6],
            length=fields[7]
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
        return self.header.pack(links_data)
    
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
        return self.header.pack(data)

class OSPFRouter:
    """OSPF 路由器"""
    
    def __init__(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE, priority: int = 1):
        self.router_id = router_id
        self.area_id = area_id
        self.router_priority = priority  # DD优先级，0表示不想当Master
        self.interfaces: Dict[str, dict] = {}
        self.neighbors: Dict[str, dict] = {}
        self.lsdb: Dict[str, dict] = {}  # LSDB
        self.routes: Dict[str, dict] = {}  # 路由表
        self.lock = threading.Lock()
        self.use_raw = True  # 默认使用 Raw Socket，由 simulator 初始化时设置
        
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
            # 收集所有已知邻居的 router_id
            neighbor_list = list(self.neighbors.keys())
            
            hello = HelloPacket(
                network_mask=iface['netmask'],
                hello_interval=10,
                router_priority=1,
                dr=iface['dr'],
                bdr=iface['bdr'],
                neighbor=neighbor_list
            )
            
            msg = OSPFHeader(
                type=OSPF_TYPE_HELLO,
                length=24 + len(hello.pack()),
                router_id=self.router_id,
                area_id=self.area_id
            )
            
            packet = msg.pack(hello.pack())
            
            # Raw Socket 需要添加 IP 头部
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
            # 过滤掉来自自己的报文
            if src_addr == self.router_id:
                logger.debug(f"忽略来自自己的报文: {src_addr}")
                return None
            
            # 过滤来自自己接口IP的报文
            my_ips = [iface['ip'] for iface in self.interfaces.values()]
            if src_addr in my_ips:
                logger.debug(f"忽略来自自己接口的报文: {src_addr}")
                return None
            
            header = OSPFHeader.unpack(data)
            
            # 验证 checksum (RFC 2328)
            # 需要校验整个 OSPF 报文 (header + body)
            received_checksum = header.checksum
            # 把 header 中的 checksum 字段置零后计算整个报文
            temp_data = data[:12] + b'\x00\x00' + data[14:]
            calculated_checksum = calc_checksum(temp_data)
            if received_checksum != calculated_checksum:
                logger.warning(f"Checksum 校验失败: expected={calculated_checksum}, got={received_checksum}")
                # 注意: OSPF 要求 checksum 校验失败则丢弃报文
                # 但某些实现可能跳过此检查以兼容
            
            logger.debug(f"收到 OSPF 报文: type={header.type} from {src_addr}")
            
            if header.type == OSPF_TYPE_HELLO:
                self.stats['hello_recv'] += 1
                return self._process_hello(data[24:], src_addr)
            elif header.type == OSPF_TYPE_DD:
                self.stats['dd_recv'] += 1
                return self._process_dd(data[24:], src_addr, header.router_id)
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
        
        # 获取发送者的 router_id (从 OSPF 头部的 router_id 字段)
        # 这里 src_addr 可能不是 router_id，所以需要从 packet 中解析
        # 但由于 process_packet 已经处理了 packet，我们用 src_addr 作为邻居标识
        
        response = None
        
        # 检查发送者的 Hello 报文中是否包含我们的接口 IP (2-way 通信确认)
        # 获取我们自己的接口 IP
        my_ips = [iface['ip'] for iface in self.interfaces.values()]
        is_2way = any(ip in hello.neighbor for ip in my_ips)
        
        if is_2way:
            # 对方已经看到了我们的 Hello，达成 2-way 通信
            if src_addr not in self.neighbors:
                self.neighbors[src_addr] = {
                    'state': NeighborState.TWOWAY,
                    'priority': hello.router_priority,
                    'dr': hello.dr,
                    'bdr': hello.bdr
                }
            else:
                self.neighbors[src_addr]['state'] = NeighborState.TWOWAY
            
            # 触发 DD 交换 (从 EXSTART 开始)
            response = self._start_dd_exchange(src_addr)
        else:
            # 更新邻居
            if src_addr not in self.neighbors:
                self.neighbors[src_addr] = {
                    'state': NeighborState.INIT,
                    'priority': hello.router_priority,
                    'dr': hello.dr,
                    'bdr': hello.bdr
                }
                # 如果之前已经收到过对方的 Hello，尝试再次检查
            else:
                # 已经存在，检查是否需要升级到 TWOWAY
                if self.neighbors[src_addr]['state'] == NeighborState.INIT:
                    # 再次检查，可能对方的 Hello 还没有包含我们
                    self.neighbors[src_addr]['state'] = NeighborState.TWOWAY
                    response = self._start_dd_exchange(src_addr)
        
        logger.info(f"收到 Hello from {src_addr}, 邻居状态: {self.neighbors[src_addr]['state']}")
        return response
    
    def _start_dd_exchange(self, neighbor_id: str):
        """开始 DD 交换过程"""
        if neighbor_id not in self.neighbors:
            return
        
        state = self.neighbors[neighbor_id].get('state')
        if state != NeighborState.TWOWAY:
            return
        
        # 转换到 EXSTART 状态
        self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
        # 只在首次生成随机序列号
        if 'dd_sequence' not in self.neighbors[neighbor_id]:
            self.neighbors[neighbor_id]['dd_sequence'] = random.randint(1, 0x7FFFFFFF)
        
        # RFC 2328: 初始 DD，双方都认为自己是 Master (MS=1)
        # 等收到对方的初始 DD 后再选举 Master/Slave
        # 发送初始 DD 报文 (I=1, M=1, MS=1)
        dd = DDPacket(
            interface_mtu=1500,
            options=0x02,
            dd_sequence=self.neighbors[neighbor_id]['dd_sequence'],
            flags=0x07  # I=1, M=1, MS=1 (初始 DD，双方都认为自己是 Master)
        )
        
        msg = OSPFHeader(
            type=OSPF_TYPE_DD,
            length=24 + len(dd.pack()),
            router_id=self.router_id,
            area_id=self.area_id
        )
        
        # 记录 DD 发送统计
        self.stats['dd_sent'] += 1
        
        return msg.pack(dd.pack())
    
    def _process_dd(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 DD 报文 (RFC 2328 Section 10.8)"""
        dd = DDPacket.unpack(data)
        
        i_bit = (dd.flags & 0x04) != 0  # Initial bit (bit 3)
        m_bit = (dd.flags & 0x02) != 0  # More bit (bit 2)
        ms_bit = (dd.flags & 0x01) != 0  # Master/Slave bit (bit 1)
        
        # 使用peer_router_id作为邻居标识（更准确）
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        logger.info(f"收到 DD from {neighbor_id}, I={i_bit}, M={m_bit}, MS={ms_bit}, seq={dd.dd_sequence}")
        
        # 确保邻居存在
        if neighbor_id not in self.neighbors:
            self.neighbors[neighbor_id] = {'state': NeighborState.INIT, 'priority': 1}
        
        current_state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
        # RFC 2328: 收到DD报文，无论当前状态如何，都应该处理
        if current_state not in (NeighborState.EXSTART, NeighborState.EXCHANGE):
            self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
            current_state = NeighborState.EXSTART
            logger.info(f"状态 -> EXSTART")
        
        # EXSTART状态: 选举Master/Slave，协商序列号
        if current_state == NeighborState.EXSTART:
            # 首次收到DD，选举Master
            if 'is_master' not in self.neighbors[neighbor_id]:
                my_id = int.from_bytes(socket.inet_aton(self.router_id), 'big')
                # 使用peer_router_id进行比较
                peer_id = int.from_bytes(socket.inet_aton(peer_router_id or src_addr), 'big')
                
                if peer_id > my_id:
                    self.neighbors[neighbor_id]['is_master'] = False  # 对方是Master
                else:
                    self.neighbors[neighbor_id]['is_master'] = True   # 我是Master
                
                # Master初始化序列号
                if self.neighbors[neighbor_id]['is_master']:
                    import time
                    self.neighbors[neighbor_id]['dd_sequence'] = int(time.time()) & 0xFFFFFFFF
                else:
                    self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
            
            is_master = self.neighbors[neighbor_id]['is_master']
            
            # 收到初始DD(I=1)，进入EXCHANGE
            if i_bit:
                self.neighbors[neighbor_id]['state'] = NeighborState.EXCHANGE
                current_state = NeighborState.EXCHANGE
                
                # Slave: 使用Master的序列号回复
                if not is_master:
                    self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
            
            # 发送DD
            seq = self.neighbors[neighbor_id]['dd_sequence']
            # RFC 2328: 如果双方都声称是Master(I=1, MS=1)，需要继续协商
            # 本端是Master且对端MS=1时，I位保持1
            i_flag = 1 if (is_master and ms_bit) else 0
            flags = (i_flag << 2) | (1 << 1) | (1 if is_master else 0)  # I, M=1, MS
            
            my_dd = DDPacket(
                interface_mtu=1500,
                options=0x02,
                dd_sequence=seq,
                flags=flags
            )
            
            msg = OSPFHeader(
                type=OSPF_TYPE_DD,
                length=24 + len(my_dd.pack()),
                router_id=self.router_id,
                area_id=self.area_id
            )
            self.stats['dd_sent'] += 1
            logger.info(f"发送 DD, I=0, M=1, MS={1 if is_master else 0}, seq={seq}")
            return msg.pack(my_dd.pack())
        
        # EXCHANGE状态: 交换DD摘要
        if current_state == NeighborState.EXCHANGE:
            is_master = self.neighbors[neighbor_id].get('is_master', False)
            
            # 检查重复DD报文（序列号相同）
            last_seq = self.neighbors[neighbor_id].get('last_dd_seq', -1)
            if last_seq == dd.dd_sequence:
                logger.info(f"忽略重复DD报文, seq={dd.dd_sequence}")
                return None
            self.neighbors[neighbor_id]['last_dd_seq'] = dd.dd_sequence
            
            # 检查是否DD交换完成(M=0)
            if not m_bit:
                # 对方发送最后DD
                self.neighbors[neighbor_id]['dd_done'] = True
                
                # 检查双方是否都完成DD交换
                if self.neighbors[neighbor_id].get('dd_done'):
                    # 双方都完成DD交换，进入LOADING
                    self.neighbors[neighbor_id]['state'] = NeighborState.LOADING
                    logger.info(f"双方DD交换完成，进入 LOADING 状态")
                return None
            
            # Master收到Slave的DD后，发送自己的LSA摘要
            if is_master:
                # Master发送LSA摘要
                pass  # 继续发送
            
            seq = self.neighbors[neighbor_id]['dd_sequence']
            flags = 0x03 if is_master else 0x02  # M=1
            
            # 构建DD报文，包含自己的LSA摘要
            lsa_headers = []
            for lsa in self.lsdb.values():
                lsa_headers.append({
                    'type': lsa.get('type', 1),
                    'id': lsa.get('id', '0.0.0.0'),
                    'adv_router': lsa.get('adv_router', '0.0.0.0'),
                    'sequence': lsa.get('sequence', 0x80000001),
                    'age': lsa.get('age', 0),
                    'options': lsa.get('options', 0x02),
                    'length': 20
                })
            
            my_dd = DDPacket(
                interface_mtu=1500,
                options=0x02,
                dd_sequence=seq,
                flags=flags,
                lsa_headers=lsa_headers
            )
            
            msg = OSPFHeader(
                type=OSPF_TYPE_DD,
                length=24 + len(my_dd.pack()),
                router_id=self.router_id,
                area_id=self.area_id
            )
            self.stats['dd_sent'] += 1
            logger.info(f"发送 DD (带LSA摘要), M=1, seq={seq}")
            return msg.pack(my_dd.pack())
        
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
        
        # 检查邻居状态 - 只有在Exchange/Loading/Full状态才处理LSU
        current_state = NeighborState.INIT
        if src_addr in self.neighbors:
            current_state = self.neighbors[src_addr].get('state', NeighborState.INIT)
        
        # RFC 2328: 只有达到Exchange及以上状态才处理LSU
        if current_state not in (NeighborState.EXCHANGE, NeighborState.LOADING, NeighborState.FULL):
            logger.warning(f"邻居状态 {current_state} < EXCHANGE，忽略LSU")
            return None
        
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
            router_id=self.router_id,
            area_id=self.area_id
        )
        
        self.stats['lsu_sent'] += 1
        return msg.pack(lsu.pack())
    
    def _build_lsack(self, lsa_list: List[dict], target: str) -> bytes:
        """构建 LSAck 报文"""
        ack_data = b''
        for lsa in lsa_list:
            ack_data += LSAHeader(
                ls_age=lsa.get('age', 0),
                options=lsa.get('options', 0x02),
                ls_type=lsa['type'],
                ls_id=lsa['id'],
                adv_router=lsa['adv_router'],
                ls_sequence=lsa['sequence'],
                checksum=lsa.get('checksum', 0),
                length=20  # LSA头部长度
            ).pack()
        
        msg = OSPFHeader(
            type=OSPF_TYPE_LSACK,
            length=24 + len(ack_data),
            router_id=self.router_id,
            area_id=self.area_id
        )
        
        self.stats['lsack_sent'] += 1
        return msg.pack(ack_data)
    
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
    
    def flood_lsa(self, sock: socket.socket, use_raw: bool = True, add_ip_header_func=None):
        """泛洪 LSA 到所有邻居"""
        for neighbor_id in self.neighbors:
            if self.neighbors[neighbor_id].get('state') == NeighborState.FULL:
                lsa_list = list(self.lsdb.values())
                packet = self._build_lsu(lsa_list, neighbor_id)
                # Raw Socket 需要添加 IP 头部
                if use_raw and add_ip_header_func:
                    packet = add_ip_header_func(packet, neighbor_id)
                try:
                    sock.sendto(packet, (neighbor_id, 89))
                except Exception as e:
                    logger.error(f"泛洪 LSA 失败: {e}")
    
    def _build_ip_header(self, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
        """构建 IP 头部 (OSPF 使用协议号 89)"""
        version_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
        tos = 0
        total_len = 20 + payload_len
        packet_id = 0
        flags_fragment = 0
        ttl = 64
        protocol = 89  # OSPF
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
        """计算 IP 头部校验和"""
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
        src_ip = "0.0.0.0"
        for iface in self.interfaces.values():
            src_ip = iface['ip']
            break
        ip_header = self._build_ip_header(len(packet), src_ip, dst_ip)
        return ip_header + packet


class OSPFSimulator:
    """OSPF 模拟器主类"""
    
    def __init__(self, router_id: str, area_id: str = OSPF_AREA_BACKBONE, priority: int = 1):
        self.router = OSPFRouter(router_id, area_id, priority)
        self.sock = None
        self.running = False
        self.threads: List[threading.Thread] = []
        self.use_raw = True  # 默认使用 Raw Socket
    
    def _build_ip_header(self, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
        """构建 IP 头部 (OSPF 使用协议号 89)"""
        # IP 头部格式: ver(4) + IHL(4) + TOS(1) + TotalLen(2) + ID(2) + Flags(2) + TTL(1) + Proto(1) + Checksum(2) + Src(4) + Dst(4)
        version_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
        tos = 0
        total_len = 20 + payload_len  # IP header + payload
        packet_id = 0
        flags_fragment = 0
        ttl = 64
        protocol = 89  # OSPF
        checksum = 0
        
        src_ip_int = socket.inet_aton(src_ip)
        dst_ip_int = socket.inet_aton(dst_ip)
        
        # 计算校验和
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
        """计算 IP 头部校验和"""
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
        # 使用第一个接口的 IP 作为源地址
        src_ip = "0.0.0.0"
        for iface in self.router.interfaces.values():
            src_ip = iface['ip']
            break
        ip_header = self._build_ip_header(len(packet), src_ip, dst_ip)
        return ip_header + packet
    
    def start(self):
        """启动模拟器"""
        # 创建 Raw Socket 用于 OSPF (需要 root 权限)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)  # 89 = OSPF
        except PermissionError:
            logger.warning("需要 root 权限使用 Raw Socket，回退到 UDP")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.use_raw = False
        else:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # 手动构造 IP 头部
            self.use_raw = True
        
        # 同步 use_raw 设置到 router
        self.router.use_raw = self.use_raw
        
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
                    # Raw Socket: 去掉 IP 头部 (20 bytes)
                    if hasattr(self, 'use_raw') and self.use_raw and len(data) > 20:
                        ospf_data = data[20:]
                    else:
                        ospf_data = data
                    
                    # 处理报文并获取响应
                    response = self.router.process_packet(ospf_data, addr[0])
                    # 如果有响应，发送回去 (Raw Socket 需要 IP 头)
                    if response:
                        if hasattr(self, 'use_raw') and self.use_raw:
                            response = self._add_ip_header(response, addr[0])
                        self.sock.sendto(response, (addr[0], 89))
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
