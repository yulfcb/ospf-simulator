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


# RFC 1071 checksum calculation (used for OSPF packet header, NOT for LSA)
# Returns 16-bit one's complement of one's complement sum
def calc_checksum(data: bytes) -> int:
    """Calculate RFC 1071 checksum for OSPF packet headers (not LSA)"""
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


def fletcher_checksum(data: bytes, offset: int = 0) -> int:
    """
    Calculate Fletcher-16 checksum (RFC 2328 Appendix B)
    
    This is used for LSA checksum calculation, not for OSPF packet headers.
    
    Args:
        data: The data to checksum (LSA Header + LSA Body, with LS Age = 0)
        offset: Starting offset (not used in standard Fletcher-16)
    
    Returns:
        16-bit Fletcher-16 checksum
    """
    if len(data) == 0:
        return 0
    
    # Split data into 16-bit words
    words = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8  # Pad with zero
        words.append(word)
    
    # Calculate Fletcher sums
    c0 = 0  # Lower sum
    c1 = 0  # Upper sum
    
    for word in words:
        c0 = (c0 + word) & 0xFF
        c1 = (c1 + c0) & 0xFF
    
    # Combine c0 and c1 into final checksum
    # The checksum field is stored in network byte order (big-endian)
    return ((c1 << 8) | c0) & 0xFFFF


def calc_lsa_checksum(lsa_header: bytes, lsa_body: bytes) -> int:
    """
    Calculate LSA checksum according to RFC 2328 Appendix B.
    
    The checksum covers the LSA Header and LSA Body, with the LS Age field
    in the header treated as zero during calculation.
    
    Args:
        lsa_header: 20-byte LSA header
        lsa_body: LSA body (excluding header)
    
    Returns:
        16-bit Fletcher-16 checksum
    """
    # Create a copy of the header with LS Age set to 0
    # LSA Header format: LS Age (2) + Options (1) + Type (1) + LS ID (4) + 
    #                    Adv Router (4) + Sequence (4) + Checksum (2) + Length (2)
    # LS Age is at offset 0-1
    header_with_zero_age = b'\x00\x00' + lsa_header[2:]
    
    # Calculate Fletcher checksum over (header with age=0) + body
    return fletcher_checksum(header_with_zero_age + lsa_body)


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
        # 追加 LSA (Header + Body)
        # RFC 2328: DD报文中包含完整的LSA
        lsa_data = b''
        for lsa in self.lsa_headers:
            # LSA Header (20 bytes) - length为实际LSA长度
            # 使用正确的字段名: ls_age, ls_type, ls_id, ls_sequence
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
        # 解析 DD Header
        mtu, opts, flags, seq = struct.unpack("!HBB I", data[:8])
        # 解析 LSA Headers (每个 20 字节)
        lsa_headers = []
        offset = 8
        while offset + 20 <= len(data):
            lsa = struct.unpack("!HBB4s4sIHH", data[offset:offset+20])
            # 使用正确的字段名: ls_age, ls_type, ls_id, ls_sequence
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
                    # RFC 2328: Type(1) + LinkID(4) + LinkData(4) + TOS(1) + Metric(2) = 12 bytes
                    link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                    link_data = socket.inet_aton(link.get('link_data', '0.0.0.0'))
                    link_type = link.get('type', 3)
                    metric = link.get('metric', 1)
                    lsa_body += struct.pack("!B4s4sBH", link_type, link_id, link_data, 0, metric)
                
                lsa_length = 20 + len(lsa_body)  # Header + body
            elif lsa_type == 2:  # Network LSA
                routers = entry.get('attached_routers', [])
                # Network Mask (4) + 路由器列表
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                lsa_body = network_mask
                for r in routers:
                    lsa_body += socket.inet_aton(r)
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 3:  # Summary LSA (Network Summary)
                # RFC 2328: Network Mask (4) + metric (4) = 8 bytes
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                metric = struct.pack('!I', entry.get('metric', 1))
                lsa_body = network_mask + metric
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 4:  # ASBR Summary LSA
                # RFC 2328: Network Mask (4) + metric (4) = 8 bytes
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                metric = struct.pack('!I', entry.get('metric', 1))
                lsa_body = network_mask + metric
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 5:  # AS External LSA
                # RFC 2328: Network Mask (4) + E-bit (1) + metric (4) + Forwarding (4) + Tag (4) = 17 bytes
                network_mask = socket.inet_aton(entry.get('network_mask', '255.255.255.0'))
                e_bit = entry.get('e_bit', 0)
                metric = struct.pack('!I', entry.get('metric', 1))
                forwarding = socket.inet_aton(entry.get('forwarding_address', '0.0.0.0'))
                external_tag = struct.pack('!I', entry.get('external_route_tag', 0))
                # E-bit 在第一个字节的高位
                lsa_body = network_mask + bytes([e_bit << 7]) + metric + forwarding + external_tag
                lsa_length = 20 + len(lsa_body)
            elif lsa_type == 7:  # NSSA External LSA
                # 类似 Type 5
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
            
            # LSA Header: age(2) + options(1) + type(1) + id(4) + adv_router(4) + seq(4) + checksum(2) + length(2)
            # First, build header with checksum=0 for Fletcher checksum calculation
            # Note: LS Age field will be treated as 0 in calc_lsa_checksum
            lsa_header_for_calc = struct.pack("!HBB4s4sIHH",
                entry.get('age', 0),
                entry.get('options', 0x02),
                lsa_type,
                socket.inet_aton(entry.get('id', '0.0.0.0')),
                socket.inet_aton(entry.get('adv_router', '0.0.0.0')),
                entry.get('sequence', 0x80000001),
                0,  # checksum initial 0 (will be replaced)
                lsa_length
            )
            # Calculate Fletcher-16 checksum (RFC 2328 Appendix B)
            lsa_checksum = calc_lsa_checksum(lsa_header_for_calc, lsa_body)
            
            # LSA Header: age(2) + options(1) + type(1) + id(4) + adv_router(4) + seq(4) + checksum(2) + length(2)
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
                    if link_offset + 12 <= len(body):
                        # RFC 2328: Type(1) + LinkID(4) + LinkData(4) + TOS(1) + Metric(2) = 12 bytes
                        link = struct.unpack("!B4s4sBH", body[link_offset:link_offset+12])
                        links.append({
                            'type': link[0],
                            'link_id': socket.inet_ntoa(link[1]),
                            'link_data': socket.inet_ntoa(link[2]),
                            'metric': link[4]
                        })
                        link_offset += 12
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
    
    def add_interface(self, name: str, ip: str, netmask: str, cost: int = 1, mtu: int = 1500):
        """添加接口
        
        Args:
            name: 接口名称
            ip: 接口 IP 地址
            netmask: 子网掩码
            cost: 接口 cost (默认 1)
            mtu: 接口 MTU (默认 1500)
        """
        self.interfaces[name] = {
            'ip': ip,
            'netmask': netmask,
            'cost': cost,
            'mtu': mtu,  # 接口 MTU
            'network': self._calc_network(ip, netmask),
            'state': 'DR',  # DR, BDR, DROTHER
            'dr': '0.0.0.0',
            'bdr': '0.0.0.0'
        }
        
        # 添加接口到Router LSA (以太网络使用type=3 stub network)
        network = self._calc_network(ip, netmask)
        lsa_key = f"1-{self.router_id}"
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['links'].append({
                'link_id': network,
                'link_data': ip,
                'type': 3,  # stub network
                'metric': cost
            })
        
        logger.info(f"添加接口 {name}: {ip}/{netmask}, MTU={mtu}")
    
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
        """将静态路由注入 AS External LSA (Type 5)"""
        # AS External LSA (Type 5) 用于外部路由（静态路由等）
        # LSA Key: type 5 + network address
        lsa_key = f"5-{network}"
        
        # 计算网络号
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        # 生成或更新 Type 5 LSA (AS External LSA)
        # 注意: 字段名必须与 pack_lsa_body 中期望的一致
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 5,           # LSA类型: 5 = AS External LSA (ASE)
                'id': network_addr,  # LS ID: 对于Type 5是网络地址
                'adv_router': self.router_id,
                'sequence': 0x80000001,
                'checksum': 0,
                'age': 0,
                'options': 0x02,     # OSPF Options: DC=1 支持Demand Circuits
                'network': network_addr,
                'netmask': netmask,
                'metric': 1,         # 静态路由默认 metric
                'e_bit': 1,          # E-bit=1 表示外部 metric 类型为 Type 2
                'forwarding': next_hop if next_hop != "0.0.0.0" else "0.0.0.0",
                'external_route_tag': 0
            }
        
        # 更新 LSA body 字段 (与 pack_lsa_body 中的字段名保持一致)
        self.lsdb[lsa_key]['network_mask'] = netmask
        self.lsdb[lsa_key]['forwarding_address'] = next_hop if next_hop != "0.0.0.0" else "0.0.0.0"
        self.lsdb[lsa_key]['e_bit'] = 1  # 确保 E-bit 设置正确
        
        logger.info(f"注入 AS External LSA (Type 5): {network_addr}/{netmask} -> {next_hop}")
    
    def add_summary_route(self, network: str, netmask: str, metric: int = 1, adv_router: str = None):
        """注入 Summary LSA (Type 3) - 由ABR生成，用于通告区域间路由
        
        Args:
            network: 目标网络地址
            netmask: 网络掩码
            metric: 到达目标的代价
            adv_router: 通告路由器ID (默认为本路由器)
        """
        # 计算网络号
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"3-{network_addr}"
        advertiser = adv_router if adv_router else self.router_id
        
        # 生成或更新 Type 3 LSA (Summary LSA)
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 3,            # LSA类型: 3 = Summary LSA (Network Summary)
                'id': network_addr,   # LS ID: 目标网络地址
                'adv_router': advertiser,
                'sequence': 0x80000001,
                'checksum': 0,
                'age': 0,
                'options': 0x02,
                'network_mask': netmask,
                'metric': metric
            }
        
        logger.info(f"注入 Summary LSA (Type 3): {network_addr}/{netmask} metric={metric}")
    
    def add_asbr_summary(self, asbr_router_id: str, metric: int = 1, adv_router: str = None):
        """注入 ASBR Summary LSA (Type 4) - 由ABR生成，用于通告ASBR的位置
        
        Args:
            asbr_router_id: ASBR的router ID
            metric: 到达ASBR的代价
            adv_router: 通告路由器ID (默认为本路由器)
        """
        lsa_key = f"4-{asbr_router_id}"
        advertiser = adv_router if adv_router else self.router_id
        
        # 生成或更新 Type 4 LSA (ASBR Summary LSA)
        if lsa_key in self.lsdb:
            self.lsdb[lsa_key]['sequence'] += 1
        else:
            self.lsdb[lsa_key] = {
                'type': 4,            # LSA类型: 4 = ASBR Summary LSA
                'id': asbr_router_id, # LS ID: ASBR的Router ID
                'adv_router': advertiser,
                'sequence': 0x80000001,
                'checksum': 0,
                'age': 0,
                'options': 0x02,
                'network_mask': '0.0.0.0',  # Type 4不使用network mask
                'metric': metric
            }
        
        logger.info(f"注入 ASBR Summary LSA (Type 4): ASBR={asbr_router_id} metric={metric}")
    
    def generate_routes(self, base_network: str, count: int, prefix: int = 24):
        """批量生成网段 - 确保生成在不同网段
        
        Args:
            base_network: 基础网络地址 (如 "10.0.0.0") - 仅用于第一个网段
            count: 生成网段数量
            prefix: CIDR 前缀长度 (默认 24)
            
        Returns:
            生成的网段列表 (如 ["10.0.0.0/24", "10.1.0.0/24", ...])
            
        生成的网段分布在不同网段，例如:
        10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24, 172.16.0.0/24, 192.168.0.0/24
        不会在同一/16网段下生成多个/24子网（如 10.0.0.0/24 和 10.0.1.0/24）
        """
        # 定义多个不同的/16网段前缀，确保每个路由在不同/16网段
        # 每个条目都是不同的 /16 网段，避免同一/16下多个/24
        network_prefixes = [
            "10.0.0.0",    # 10.0.x.x/16
            "10.1.0.0",    # 10.1.x.x/16
            "10.2.0.0",    # 10.2.x.x/16
            "172.16.0.0",  # 172.16.x.x/16
            "172.17.0.0",  # 172.17.x.x/16
            "172.18.0.0",  # 172.18.x.x/16
            "192.168.0.0", # 192.168.0.x/16 (单独一个/24)
            "172.19.0.0",  # 172.19.x.x/16
            "172.20.0.0",  # 172.20.x.x/16
            "172.21.0.0",  # 172.21.x.x/16
            "172.22.0.0",  # 172.22.x.x/16
            "172.23.0.0",  # 172.23.x.x/16
        ]
        
        generated = []
        
        for i in range(count):
            # 使用循环选择网段前缀，确保不同路由在不同/16网段
            prefix_idx = i % len(network_prefixes)
            network_base = network_prefixes[prefix_idx]
            
            # 构建网络地址: x.x.0.0/24
            # 解析为网络地址 (第三个字节置0)
            parts = network_base.split('.')
            network_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
            network = f"{network_addr}/24"
            
            # 只生成网段信息，不生成完整路由
            generated.append(network)
        
        return generated
    
    def remove_static_route(self, network: str, netmask: str = "255.255.255.0", 
                            sock=None, use_raw=True, add_ip_header_func=None):
        """删除静态路由
        
        Args:
            network: 目标网络地址
            netmask: 网络掩码 (默认 255.255.255.0)
            sock: socket 对象，用于发送 MaxAge LSA（可选）
            use_raw: 是否使用 raw socket
            add_ip_header_func: 添加 IP 头部的函数
        
        通过发送 MaxAge LSA (LS Age = 3600) 来撤销路由。
        MaxAge LSA 会被邻居超时并从 LSDB 中清除。
        
        Returns:
            bool: True 表示成功删除，False 表示路由不存在
        """
        route_key = f"{network}-{netmask}"
        
        # 从路由表删除
        found = False
        if route_key in self.routes:
            del self.routes[route_key]
            logger.info(f"删除静态路由: {network}/{netmask}")
            found = True
        else:
            logger.warning(f"路由不存在: {network}/{netmask}")
        
        # 从 LSDB 删除对应的 Type 5 LSA (AS External LSA)
        # 计算网络地址
        ip_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        
        lsa_key = f"5-{network_addr}"
        
        if lsa_key in self.lsdb:
            # 如果有 socket，发送 MaxAge LSA 来撤销路由
            if sock is not None:
                # 构建并发送 MaxAge LSA
                maxage_lsa = {
                    'type': 5,
                    'id': network_addr,
                    'adv_router': self.router_id,
                    'sequence': 0x7FFFFFFF,
                    'checksum': 0,
                    'age': 3600,
                    'options': 0x02,
                    'network_mask': netmask,
                    'metric': 0xFFFFFF,
                    'e_bit': 1,
                    'forwarding_address': '0.0.0.0',
                    'external_route_tag': 0
                }
                
                lsu = LSUPacket(
                    age=3600,
                    type=5,
                    id=network_addr,
                    adv_router=self.router_id,
                    sequence=0x7FFFFFFF,
                    lsa_entries=[maxage_lsa]
                )
                
                msg = OSPFHeader(
                    type=OSPF_TYPE_LSU,
                    length=24 + len(lsu.pack()),
                    router_id=self.router_id,
                    area_id=self.area_id
                )
                
                packet = msg.pack(lsu.pack())
                
                # 发送给所有 FULL 状态的邻居
                for neighbor_id, neighbor_info in self.neighbors.items():
                    if neighbor_info.get('state') == NeighborState.FULL:
                        # 添加 IP 头部 (如果需要)
                        send_packet = packet
                        if use_raw and add_ip_header_func:
                            send_packet = add_ip_header_func(send_packet, neighbor_id)
                        
                        try:
                            sock.sendto(send_packet, (neighbor_id, 89))
                            logger.info(f"发送 MaxAge LSA 到邻居 {neighbor_id}: {network_addr}/{netmask}")
                            self.stats['lsu_sent'] += 1
                        except Exception as e:
                            logger.error(f"发送 MaxAge LSA 失败: {e}")
            
            # 从 LSDB 中删除
            del self.lsdb[lsa_key]
            logger.info(f"撤销 AS External LSA: {network_addr}/{netmask}")
        else:
            logger.warning(f"LSA 不存在: {lsa_key}")
        
        return found
    
    def _flood_maxage_lsa(self, lsa_key: str, network_addr: str, netmask: str):
        """泛洪 MaxAge LSA (撤销路由)
        
        发送 LS Age = 3600 的 LSA，邻居收到后会将其标记为 MaxAge 并在 MaxAgeDelay 后删除。
        
        Args:
            lsa_key: LSA 键名
            network_addr: 网络地址
            netmask: 网络掩码
        """
        # 构建 MaxAge LSA (Type 5 AS External LSA)
        # LS Age = 3600 (MaxAge)
        # Sequence = 0x7FFFFFFF (最大序列号)
        maxage_lsa = {
            'type': 5,           # AS External LSA
            'id': network_addr,   # LS ID = 网络地址
            'adv_router': self.router_id,
            'sequence': 0x7FFFFFFF,  # 最大序列号
            'checksum': 0,
            'age': 3600,         # MaxAge = 3600 秒
            'options': 0x02,
            'network_mask': netmask,
            'metric': 0xFFFFFF,  # 无效的 metric，表示不可达
            'e_bit': 1,
            'forwarding_address': '0.0.0.0',
            'external_route_tag': 0
        }
        
        # 构建 LSU 报文泛洪
        lsu = LSUPacket(
            age=3600,  # MaxAge
            type=5,
            id=network_addr,
            adv_router=self.router_id,
            sequence=0x7FFFFFFF,
            lsa_entries=[maxage_lsa]
        )
        
        msg = OSPFHeader(
            type=OSPF_TYPE_LSU,
            length=24 + len(lsu.pack()),
            router_id=self.router_id,
            area_id=self.area_id
        )
        
        packet = msg.pack(lsu.pack())
        logger.info(f"泛洪 MaxAge LSA: {network_addr}/{netmask}")
        
        # 发送给所有 FULL 状态的邻居
        # 需要通过 simulator 的 socket 发送，这里只返回 packet
        # 由调用者负责发送
        return packet
    
    def flood_maxage_lsa_to_neighbors(self, sock: socket.socket, use_raw: bool = True, add_ip_header_func=None):
        """泛洪所有 MaxAge LSA 到所有邻居
        
        用于 remove_static_route 后将 MaxAge LSA 发送给邻居
        
        Args:
            sock: socket to send on
            use_raw: 是否使用 raw socket
            add_ip_header_func: 添加 IP 头部的函数
        """
        # 遍历所有邻居，发送 MaxAge LSA
        for neighbor_id, neighbor_info in self.neighbors.items():
            if neighbor_info.get('state') == NeighborState.FULL:
                # 为每个 FULL 状态的邻居构建并发送 MaxAge LSA
                # 这里我们遍历 LSDB 找到需要撤销的 Type 5 LSA
                for lsa_key, lsa in list(self.lsdb.items()):
                    if lsa.get('type') == 5:
                        # 构建 MaxAge LSA
                        network_addr = lsa.get('id', '0.0.0.0')
                        netmask = lsa.get('network_mask', '255.255.255.0')
                        
                        maxage_lsa = {
                            'type': 5,
                            'id': network_addr,
                            'adv_router': self.router_id,
                            'sequence': 0x7FFFFFFF,
                            'checksum': 0,
                            'age': 3600,
                            'options': 0x02,
                            'network_mask': netmask,
                            'metric': 0xFFFFFF,
                            'e_bit': 1,
                            'forwarding_address': '0.0.0.0',
                            'external_route_tag': 0
                        }
                        
                        lsu = LSUPacket(
                            age=3600,
                            type=5,
                            id=network_addr,
                            adv_router=self.router_id,
                            sequence=0x7FFFFFFF,
                            lsa_entries=[maxage_lsa]
                        )
                        
                        msg = OSPFHeader(
                            type=OSPF_TYPE_LSU,
                            length=24 + len(lsu.pack()),
                            router_id=self.router_id,
                            area_id=self.area_id
                        )
                        
                        packet = msg.pack(lsu.pack())
                        
                        # 添加 IP 头部 (如果需要)
                        if use_raw and add_ip_header_func:
                            packet = add_ip_header_func(packet, neighbor_id)
                        
                        try:
                            sock.sendto(packet, (neighbor_id, 89))
                            logger.info(f"发送 MaxAge LSA 到邻居 {neighbor_id}: {network_addr}/{netmask}")
                            self.stats['lsu_sent'] += 1
                        except Exception as e:
                            logger.error(f"发送 MaxAge LSA 失败: {e}")
    
    def _fragment_packet(self, packet: bytes, mtu: int = 1500) -> List[bytes]:
        """根据 MTU 分片 OSPF 报文
        
        RFC 2328: OSPF 报文可以分片传输，每个分片都包含完整的 OSPF 头部。
        当报文大小超过接口 MTU 时，需要分片。
        
        Args:
            packet: 原始 OSPF 报文 (包含 IP 头部 + OSPF 头部 + 报文体)
            mtu: 接口 MTU (默认 1500)
            
        Returns:
            分片后的报文列表
        """
        # IP 头部 = 20 字节
        ip_header_len = 20
        # OSPF 头部 = 24 字节
        ospf_header_len = 24
        
        # 计算 OSPF 报文最大负载 (不包括 IP 头)
        max_ospf_payload = mtu - ip_header_len
        
        # 如果 OSPF 报文已经小于 MTU，无需分片
        if len(packet) <= mtu:
            return [packet]
        
        # 提取 OSPF 头部和报文体
        if len(packet) < ip_header_len + ospf_header_len:
            logger.warning(f"报文长度太短: {len(packet)}")
            return [packet]
        
        ip_header = packet[:ip_header_len]
        ospf_body = packet[ip_header_len:]
        
        # OSPF 报文总长度
        total_ospf_len = len(ospf_body)
        
        # 计算每个分片的 OSPF 负载
        # 每个分片需要包含完整的 OSPF 头部 (24 字节)
        max_payload_per_frag = max_ospf_payload - ospf_header_len
        
        if max_payload_per_frag <= 0:
            logger.error(f"MTU 太小 ({mtu})，无法容纳 OSPF 头部")
            return [packet]
        
        fragments = []
        offset = 0
        frag_id = 0
        
        while offset < total_ospf_len:
            # 计算当前分片的大小
            chunk_size = min(max_payload_per_frag, total_ospf_len - offset)
            
            # 提取当前分片的 OSPF 数据
            frag_ospf_body = ospf_body[offset:offset + chunk_size]
            
            # 构建新的 IP 头部
            # IP 头部格式: ver(4) + IHL(4) + TOS(1) + TotalLen(2) + ID(2) + Flags(3) + FragOff(13) + TTL(1) + Proto(1) + Checksum(2) + Src(4) + Dst(4)
            # 解析原始 IP 头部
            version_ihl = ip_header[0]
            tos = ip_header[1]
            total_len = ip_header_len + ospf_header_len + chunk_size
            packet_id = ip_header[4] << 8 | ip_header[5]
            
            # 设置分片标志: MF=1 表示还有更多分片, 除了最后一个分片
            is_last_frag = (offset + chunk_size >= total_ospf_len)
            if is_last_frag:
                flags_fragment = 0x0000  # MF=0, 不分片=0
            else:
                flags_fragment = 0x2000  # MF=1
            
            ttl = 64
            protocol = ip_header[9]
            src_ip = ip_header[12:16]
            dst_ip = ip_header[16:20]
            
            # 构建分片 IP 头部
            frag_ip_header = struct.pack("!BBHHHBBH4s4s",
                version_ihl, 
                tos, 
                total_len, 
                packet_id,
                flags_fragment,
                ttl, 
                protocol, 
                0,  # checksum 初始为 0
                src_ip, 
                dst_ip
            )
            
            # 计算校验和
            checksum = self._ip_checksum(frag_ip_header)
            frag_ip_header = struct.pack("!BBHHHBBH4s4s",
                version_ihl, 
                tos, 
                total_len, 
                packet_id,
                flags_fragment,
                ttl, 
                protocol, 
                checksum,
                src_ip, 
                dst_ip
            )
            
            # 组装完整报文
            frag_packet = frag_ip_header + ospf_header_len + frag_ospf_body
            fragments.append(frag_packet)
            
            logger.debug(f"分片 {frag_id}: offset={offset}, size={len(frag_packet)}, MF={'0' if is_last_frag else '1'}")
            
            offset += chunk_size
            frag_id += 1
        
        logger.info(f"分片完成: 原始大小 {len(packet)}, 分成 {len(fraguments)} 个分片, MTU={mtu}")
        return fragments
    
    def send_packet_with_mtu(self, sock: socket.socket, packet: bytes, target: str, iface_name: str = None):
        """根据接口 MTU 发送报文，需要时自动分片
        
        Args:
            sock: socket to send on
            packet: OSPF 报文 (不包含 IP 头部)
            target: 目标地址
            iface_name: 接口名称 (用于获取 MTU)
        """
        # 获取接口 MTU
        mtu = 1500  # 默认值
        if iface_name and iface_name in self.interfaces:
            mtu = self.interfaces[iface_name].get('mtu', 1500)
        
        # 添加 IP 头部
        if hasattr(self, 'use_raw') and self.use_raw:
            packet_with_ip = self._add_ip_header(packet, target)
        else:
            packet_with_ip = packet
        
        # 检查是否需要分片
        if len(packet_with_ip) > mtu:
            # 需要分片
            fragments = self._fragment_packet(packet_with_ip, mtu)
            for frag in fragments:
                try:
                    sock.sendto(frag, (target, 89))
                except Exception as e:
                    logger.error(f"发送分片失败: {e}")
        else:
            # 不需要分片，直接发送
            try:
                sock.sendto(packet_with_ip, (target, 89))
            except Exception as e:
                logger.error(f"发送报文失败: {e}")
    
    def send_hello(self, sock: socket.socket, target: str = ALL_SPF_ROUTERS, options: int = None):
        """发送 Hello 报文
        
        Args:
            sock: socket to send on
            target: target address (default ALL_SPF_ROUTERS)
            options: OSPF Options field (default 0x02)
        """
        if options is None:
            options = 0x02
            
        for iface_name, iface in self.interfaces.items():
            # 收集所有已知邻居的 router_id
            neighbor_list = list(self.neighbors.keys())
            
            hello = HelloPacket(
                network_mask=iface['netmask'],
                hello_interval=10,
                options=options,
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
            # 把 header 中的 checksum 字段(第13-14字节)置零后计算整个报文
            # OSPF header: 24 bytes = version(1) + type(1) + length(2) + router_id(4) + area_id(4) + checksum(2) + auth_type(2) + auth(8)
            calculated_checksum = calc_checksum(data[:12] + b'\x00\x00' + data[14:])
            if received_checksum != calculated_checksum:
                logger.warning(f"Checksum 校验失败: expected={calculated_checksum}, got={received_checksum}")
                # 注意: OSPF 要求 checksum 校验失败则丢弃报文
                # 但某些实现可能跳过此检查以兼容
            
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
        """处理 Hello 报文"""
        hello = HelloPacket.unpack(data)
        
        # 使用 OSPF Header 中的 router_id 作为邻居标识
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        response = None
        
        # 检查发送者的 Hello 报文中是否包含我们的接口 IP (2-way 通信确认)
        # 获取我们自己的接口 IP
        my_ips = [iface['ip'] for iface in self.interfaces.values()]
        is_2way = any(ip in hello.neighbor for ip in my_ips)
        
        if is_2way:
            # 对方已经看到了我们的 Hello，达成 2-way 通信
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.TWOWAY,
                    'priority': hello.router_priority,
                    'dr': hello.dr,
                    'bdr': hello.bdr
                }
            else:
                self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
            
            # 触发 DD 交换 (从 EXSTART 开始)
            response = self._start_dd_exchange(neighbor_id)
        else:
            # 更新邻居
            if neighbor_id not in self.neighbors:
                self.neighbors[neighbor_id] = {
                    'state': NeighborState.INIT,
                    'priority': hello.router_priority,
                    'dr': hello.dr,
                    'bdr': hello.bdr
                }
                # 如果之前已经收到过对方的 Hello，尝试再次检查
            else:
                # 已经存在，检查是否需要升级到 TWOWAY
                if self.neighbors[neighbor_id]['state'] == NeighborState.INIT:
                    # 再次检查，可能对方的 Hello 还没有包含我们
                    self.neighbors[neighbor_id]['state'] = NeighborState.TWOWAY
                    response = self._start_dd_exchange(neighbor_id)
        
        logger.info(f"收到 Hello from {neighbor_id}, 邻居状态: {self.neighbors[neighbor_id]['state']}")
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
        # 标记已发送初始DD
        self.neighbors[neighbor_id]['sent_initial_dd'] = True
        
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
        """处理 DD 报文 - RFC 2328 Section 10.8"""
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
        """获取邻居ID"""
        return peer_router_id if peer_router_id else src_addr

    def _ensure_neighbor_exists(self, neighbor_id: str):
        """确保邻居存在"""
        if neighbor_id not in self.neighbors:
            self.neighbors[neighbor_id] = {'state': NeighborState.INIT, 'priority': 1}

    def _handle_dd_exstart(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        """处理 ExStart 状态的 DD 报文 - RFC 2328 Section 10.8"""
        i_bit = self._parse_i_bit(dd.flags)
        m_bit = self._parse_m_bit(dd.flags)
        
        # 获取对端的 Router ID
        peer_router_id = dd.lsa_headers[0]['adv_router'] if dd.lsa_headers else neighbor_id
        
        if i_bit:
            # 收到 I=1 的 DD 报文 (初始 DD)
            # RFC 2328: 双方都认为自己是 Master，首先发送 I=1 的 DD
            # 需要比较 Router ID 来决定角色
            
            my_id_int = self._get_router_id_int()
            peer_id_int = self._get_router_id_int(peer_router_id)
            
            if my_id_int > peer_id_int:
                # 本端 Router ID 更大: 本端应该是 Master
                # 对端先发起了协商，本端需要重新发送 I=1 的初始化 DD (本端先发起)
                logger.info(f"本端 Router ID ({self.router_id}) > 对端 ({peer_router_id}), 重新发送 I=1 初始化 DD")
                
                # 选举 Master: 本端是 Master
                self.neighbors[neighbor_id]['is_master'] = True
                self.neighbors[neighbor_id]['dd_sequence'] = self._generate_dd_sequence()
                
                # 发送 I=1 的初始化 DD (本端先发起, MS=1)
                return self._send_initial_dd(neighbor_id)
            else:
                # 本端 Router ID 更小: 对端是 Master
                # 进入 exchange 状态，发送本端的 LSA 摘要
                logger.info(f"本端 Router ID ({self.router_id}) < 对端 ({peer_router_id}), 对端是 Master")
                
                # 选举 Master: 本端是 Slave
                self.neighbors[neighbor_id]['is_master'] = False
                self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
                
                # 进入 exchange 状态
                self._transition_to_exchange(neighbor_id)
                
                # 发送本端的 LSA 摘要 (I=0, M=1, MS=0)
                return self._send_dd_with_lsa(neighbor_id)
        else:
            # 收到 I=0 的 DD 报文
            # 对端已经完成初始协商，携带了 LSA 摘要
            # 本端也进入 exchange 状态，发送本端的 LSA 摘要信息
            
            logger.info(f"收到对端 I=0 的 DD, 进入 exchange 状态")
            
            # 先完成 Master/Slave 选举
            self._elect_master_slave(neighbor_id, dd)
            
            # 进入 exchange 状态
            self._transition_to_exchange(neighbor_id)
            
            # 发送本端的 LSA 摘要
            return self._send_dd_with_lsa(neighbor_id)

    def _parse_i_bit(self, flags: int) -> bool:
        """解析 I 位"""
        return (flags & 0x04) != 0

    def _parse_m_bit(self, flags: int) -> bool:
        """解析 M 位"""
        return (flags & 0x02) != 0

    def _parse_ms_bit(self, flags: int) -> bool:
        """解析 MS 位"""
        return (flags & 0x01) != 0

    def _elect_master_slave(self, neighbor_id: str, dd: DDPacket):
        """选举 Master/Slave"""
        my_id = self._get_router_id_int()
        peer_id = self._get_router_id_int(neighbor_id)
        
        if peer_id > my_id:
            self.neighbors[neighbor_id]['is_master'] = False
            self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence
        else:
            self.neighbors[neighbor_id]['is_master'] = True
            self.neighbors[neighbor_id]['dd_sequence'] = self._generate_dd_sequence()

    def _get_router_id_int(self, router_id: str = None) -> int:
        """获取 Router ID 的整数值"""
        rid = router_id if router_id else self.router_id
        return int.from_bytes(socket.inet_aton(rid), 'big')

    def _generate_dd_sequence(self) -> int:
        """生成 DD 序列号"""
        return int(time.time()) & 0xFFFFFFFF

    def _transition_to_exchange(self, neighbor_id: str):
        """转换到 Exchange 状态"""
        self.neighbors[neighbor_id]['state'] = NeighborState.EXCHANGE

    def _handle_dd_exchange(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        """处理 Exchange 状态的 DD 报文"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        m_bit = self._parse_m_bit(dd.flags)
        
        self._update_dd_sequence(neighbor_id, dd, is_master)
        self._check_peer_dd_done(neighbor_id, m_bit)
        
        if self._is_dd_exchange_complete(neighbor_id):
            return self._transition_to_loading(neighbor_id)
        
        return self._send_dd_response(neighbor_id)

    def _update_dd_sequence(self, neighbor_id: str, dd: DDPacket, is_master: bool):
        """更新 DD 序列号"""
        if is_master:
            self.neighbors[neighbor_id]['dd_sequence'] += 1
        else:
            self.neighbors[neighbor_id]['dd_sequence'] = dd.dd_sequence + 1

    def _check_peer_dd_done(self, neighbor_id: str, m_bit: bool):
        """检查对端 DD 是否完成"""
        if not m_bit:
            self.neighbors[neighbor_id]['peer_dd_done'] = True

    def _is_dd_exchange_complete(self, neighbor_id: str) -> bool:
        """检查 DD 交换是否完成"""
        return (self.neighbors[neighbor_id].get('peer_dd_done', False) and 
                not self.lsdb)

    def _transition_to_loading(self, neighbor_id: str) -> Optional[bytes]:
        """转换到 Loading 状态"""
        self.neighbors[neighbor_id]['state'] = NeighborState.LOADING
        return self._send_lsr(neighbor_id)

    def _handle_dd_other_state(self, neighbor_id: str, dd: DDPacket, src_addr: str) -> Optional[bytes]:
        """处理其他状态的 DD 报文"""
        self.neighbors[neighbor_id]['state'] = NeighborState.EXSTART
        return self._handle_dd_exstart(neighbor_id, dd, src_addr)

    def _send_dd_response(self, neighbor_id: str) -> Optional[bytes]:
        """发送 DD 响应"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        
        flags = (1 if is_master else 0) | 0x02
        return self._build_dd_packet(neighbor_id, seq, flags, lsa_headers)

    def _send_initial_dd(self, neighbor_id: str) -> Optional[bytes]:
        """发送初始 DD 报文 (I=1, M=1, MS=1) - 用于 ExStart 状态"""
        is_master = self.neighbors[neighbor_id].get('is_master', True)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        
        # 初始 DD 不包含 LSA 摘要 (空列表)
        # 标志位: I=1, M=1, MS=1 (本端认为自己是 Master)
        flags = 0x07  # I=1, M=1, MS=1
        
        logger.debug(f"发送初始 DD: I=1, M=1, MS={'1' if is_master else '0'}, seq={seq}")
        return self._build_dd_packet(neighbor_id, seq, flags, [])
    
    def _send_dd_with_lsa(self, neighbor_id: str) -> Optional[bytes]:
        """发送带 LSA 摘要的 DD 报文 (I=0, M=1/0, MS=0/1) - 用于 Exchange 状态"""
        is_master = self.neighbors[neighbor_id].get('is_master', False)
        seq = self.neighbors[neighbor_id]['dd_sequence']
        lsa_headers = self._build_lsa_headers()
        
        # 计算 M 位: 如果还有更多 LSA 要发送则 M=1
        # 简化处理: 如果 LSDB 有内容则 M=1
        m_bit = 1 if lsa_headers else 0
        
        # 标志位: I=0, M=1/0, MS=1/0
        flags = (m_bit << 1) | (1 if is_master else 0)  # I=0
        
        logger.debug(f"发送 DD (带 LSA 摘要): I=0, M={m_bit}, MS={'1' if is_master else '0'}, seq={seq}, lsa_count={len(lsa_headers)}")
        return self._build_dd_packet(neighbor_id, seq, flags, lsa_headers)

    def _calculate_lsa_checksum_and_length(self, lsa: dict) -> Tuple[int, int]:
        """计算 LSA 的真实 checksum 和 length
        
        Returns:
            (checksum, length): LSA 校验和和长度
        """
        lsa_type = lsa.get('type', 1)
        
        # 构建 LSA 主体 (Header 之外的部分)
        lsa_body = b''
        
        if lsa_type == 1:  # Router LSA
            links = lsa.get('links', [])
            # links count (2 bytes)
            lsa_body = struct.pack("!H", len(links))
            for link in links:
                link_id = socket.inet_aton(link.get('link_id', '0.0.0.0'))
                # link_data 可以是 IP 地址或接口索引
                link_data_val = link.get('link_data')
                if isinstance(link_data_val, str):
                    link_data = socket.inet_aton(link_data_val)
                else:
                    link_data = struct.pack("!I", link_data_val if link_data_val else 0)
                link_type = link.get('type', 3)
                metric = link.get('metric', 1)
                # TOS=0 (1 byte)
                lsa_body += struct.pack("!B4s4sBH", link_type, link_id, link_data, 0, metric)
        
        elif lsa_type == 2:  # Network LSA
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            lsa_body = network_mask
            attached_routers = lsa.get('attached_routers', [])
            for router_id in attached_routers:
                lsa_body += socket.inet_aton(router_id)
        
        elif lsa_type == 3:  # Summary LSA (Network Summary)
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        
        elif lsa_type == 4:  # ASBR Summary LSA
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            metric = struct.pack("!I", lsa.get('metric', 1))
            lsa_body = network_mask + metric
        
        elif lsa_type == 5:  # AS External LSA
            network_mask = socket.inet_aton(lsa.get('network_mask', '255.255.255.0'))
            e_bit = lsa.get('e_bit', 0)
            metric = struct.pack("!I", lsa.get('metric', 1))
            forwarding = socket.inet_aton(lsa.get('forwarding_address', '0.0.0.0'))
            external_tag = struct.pack("!I", lsa.get('external_route_tag', 0))
            # E-bit 在第一个字节的高位
            lsa_body = network_mask + bytes([e_bit << 7]) + metric + forwarding + external_tag
        
        # LSA 总长度 = Header(20) + Body
        lsa_length = 20 + len(lsa_body)
        
        # RFC 2328 Section 8.1: Checksum 覆盖范围从 LS Age 后（跳过 2 字节的 Age）到 LSA 结束
        # 即: Options + Type + LS ID + Adv Router + Sequence + Checksum(设为0) + Length + Body
        # 构建 LSA Header (跳过 LS Age)
        # Header 格式 (无 Age): Options(1) + Type(1) + ID(4) + AdvRouter(4) + Seq(4) + Checksum(2) + Length(2)
        lsa_header_no_age = struct.pack("!BB4s4sIHH",
            lsa.get('options', 0x02),
            lsa_type,
            socket.inet_aton(lsa.get('id', '0.0.0.0')),
            socket.inet_aton(lsa.get('adv_router', self.router_id)),
            lsa.get('sequence', 0x80000001),
            0,  # checksum 初始为 0
            lsa_length
        )
        
        # 计算 LSA 的校验和 (跳过 LS Age 字段)
        lsa_checksum = calc_checksum(lsa_header_no_age + lsa_body)
        
        return lsa_checksum, lsa_length
    
    def _build_lsa_headers(self) -> list:
        """构建 LSA 头部列表 (带真实的 checksum 和 length)"""
        headers = []
        for lsa_key, lsa in self.lsdb.items():
            # 计算真实的 checksum 和 length
            checksum, length = self._calculate_lsa_checksum_and_length(lsa)
            
            headers.append({
                'ls_age': lsa.get('age', 0),
                'ls_type': lsa.get('type', 1),
                'ls_id': lsa.get('id', '0.0.0.0'),
                'adv_router': lsa.get('adv_router', self.router_id),
                'ls_sequence': lsa.get('sequence', 0x80000001),
                'checksum': checksum,
                'length': length
            })
        return headers

    def _build_dd_packet(self, neighbor_id: str, seq: int, flags: int, lsa_headers: list) -> bytes:
        """构建 DD 报文"""
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
        return msg.pack(my_dd.pack())

    def _send_lsr(self, neighbor_id: str) -> Optional[bytes]:
        """发送 LSR 请求"""
        return None
    
    def _process_lsr(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 LSR 报文"""
        lsr = LSRPacket.unpack(data)
        # 使用 peer_router_id 作为邻居标识
        neighbor_id = peer_router_id if peer_router_id else src_addr
        self._update_neighbor_state(neighbor_id, NeighborState.LOADING)
        
        # 查找并返回 LSA
        lsa_key = f"{lsr.ls_type}-{lsr.ls_id}"
        if lsa_key in self.lsdb:
            return self._build_lsu([self.lsdb[lsa_key]], neighbor_id)
        return None
    
    def _process_lsu(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 LSU 报文"""
        lsu = LSUPacket.unpack(data)
        
        # 使用 peer_router_id 作为邻居标识
        neighbor_id = peer_router_id if peer_router_id else src_addr
        
        # 检查邻居状态 - 只有在Exchange/Loading/Full状态才处理LSU
        current_state = NeighborState.INIT
        if neighbor_id in self.neighbors:
            current_state = self.neighbors[neighbor_id].get('state', NeighborState.INIT)
        
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
        
        self._update_neighbor_state(neighbor_id, NeighborState.FULL)
        logger.info(f"收到 LSU from {neighbor_id}, LSDB 条目数: {len(self.lsdb)}")
        
        # 发送 LSAck
        return self._build_lsack(lsu.lsa_entries, neighbor_id)
    
    def _process_lsack(self, data: bytes, src_addr: str, peer_router_id: str = None) -> Optional[bytes]:
        """处理 LSAck 报文"""
        # 使用 peer_router_id 作为邻居标识
        neighbor_id = peer_router_id if peer_router_id else src_addr
        logger.debug(f"收到 LSAck from {neighbor_id}")
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
