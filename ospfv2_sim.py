"""
OSPFv2 Simulator with Type-5 LSA (AS-External-LSA) Support

This module simulates OSPFv2 routing protocol including:
- Router-LSA (Type-1)
- Network-LSA (Type-2)
- Summary-LSA (Type-3, Type-4)
- AS-External-LSA (Type-5)

Author: OSPFv2-SIM
"""

import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum


class LSAType(Enum):
    """OSPF LSA Types"""
    ROUTER_LSA = 1          # Router-LSA
    NETWORK_LSA = 2         # Network-LSA
    SUMMARY_LSA = 3        # Summary-LSA (Network)
    SUMMARY_LSA_ASBR = 4   # Summary-LSA (ASBR)
    AS_EXTERNAL_LSA = 5     # AS-External-LSA
    GROUP_MEMBERSHIP_LSA = 6


@dataclass
class OSPFHeader:
    """OSPF Packet Header"""
    version: int = 2
    type: int = 1
    packet_length: int = 0
    router_id: str = ""
    area_id: str = "0.0.0.0"
    checksum: int = 0
    auth_type: int = 0
    auth_data: str = "0" * 8


@dataclass
class LSALink:
    """LSA Link information"""
    link_id: str = ""
    link_data: str = ""
    type: int = 0  # 1=Point-to-point, 2=Transit, 3=Stub, 4=Virtual
    metric: int = 1


@dataclass
class RouterLSA:
    """Type-1 Router-LSA"""
    lsa_type: int = LSAType.ROUTER_LSA.value
    lsa_id: str = ""
    advertising_router: str = ""
    sequence: int = 0x80000001
    links: List[LSALink] = field(default_factory=list)
    flags: int = 0  # B=Area Border Router, E=AS Border Router, V=Virtual Link Endpoint
    
    
@dataclass
class NetworkLSA:
    """Type-2 Network-LSA"""
    lsa_type: int = LSAType.NETWORK_LSA.value
    lsa_id: str = ""
    advertising_router: str = ""
    sequence: int = 0x80000001
    network_mask: str = ""
    attached_routers: List[str] = field(default_factory=list)


@dataclass
class SummaryLSA:
    """Type-3 Summary-LSA and Type-4 ASBR-Summary-LSA"""
    lsa_type: int = LSAType.SUMMARY_LSA.value
    lsa_id: str = ""
    advertising_router: str = ""
    sequence: int = 0x80000001
    network_mask: str = ""
    metric: int = 1


@dataclass
class ASExternalLSA:
    """Type-5 AS-External-LSA"""
    lsa_type: int = LSAType.AS_EXTERNAL_LSA.value
    lsa_id: str = ""
    advertising_router: str = ""
    sequence: int = 0x80000001
    network_mask: str = ""
    metric: int = 1
    metric_type: int = 1  # 1=Type-1 (E1), 2=Type-2 (E2)
    forward_address: str = "0.0.0.0"
    external_route_tag: int = 0


@dataclass
class OSPFInterface:
    """OSPF Interface"""
    ip_address: str = ""
    network_mask: str = "255.255.255.0"
    cost: int = 10
    hello_interval: int = 10
    dead_interval: int = 40
    priority: int = 1
    state: str = "DOWN"


@dataclass
class OSPFRouter:
    """OSPF Router"""
    router_id: str = "0.0.0.0"
    area_id: str = "0.0.0.0"
    interfaces: List[OSPFInterface] = field(default_factory=list)
    is_abr: bool = False
    is_asbr: bool = False
    router_lsa: Optional[RouterLSA] = None
    lsdb: Dict[int, Dict] = field(default_factory=dict)
    routing_table: Dict[str, Dict] = field(default_factory=dict)
    
    def __post_init__(self):
        # Initialize LSDB for each LSA type
        self.lsdb = {
            LSAType.ROUTER_LSA.value: {},
            LSAType.NETWORK_LSA.value: {},
            LSAType.SUMMARY_LSA.value: {},
            LSAType.SUMMARY_LSA_ASBR.value: {},
            LSAType.AS_EXTERNAL_LSA.value: {},
        }


class OSPFLSDB:
    """Link State Database"""
    
    def __init__(self):
        self.lsdb: Dict[int, Dict[str, Dict]] = {
            LSAType.ROUTER_LSA.value: {},
            LSAType.NETWORK_LSA.value: {},
            LSAType.SUMMARY_LSA.value: {},
            LSAType.SUMMARY_LSA_ASBR.value: {},
            LSAType.AS_EXTERNAL_LSA.value: {},
        }
    
    def add_lsa(self, lsa_type: int, lsa_id: str, lsa_data):
        """Add or update an LSA in the database"""
        if lsa_type not in self.lsdb:
            self.lsdb[lsa_type] = {}
        self.lsdb[lsa_type][lsa_id] = lsa_data
    
    def get_lsa(self, lsa_type: int, lsa_id: str):
        """Get an LSA from the database"""
        return self.lsdb.get(lsa_type, {}).get(lsa_id)
    
    def get_all_lsa(self, lsa_type: int) -> Dict:
        """Get all LSAs of a specific type"""
        return self.lsdb.get(lsa_type, {})
    
    def install_external_lsa(self, asbr: OSPFRouter, external_network: str, 
                              mask: str, metric: int, metric_type: int = 2):
        """Install AS-External-LSA (Type-5) from ASBR"""
        ext_lsa = ASExternalLSA(
            lsa_type=LSAType.AS_EXTERNAL_LSA.value,
            lsa_id=external_network,
            advertising_router=asbr.router_id,
            sequence=0x80000001,
            network_mask=mask,
            metric=metric,
            metric_type=metric_type,
            forward_address="0.0.0.0",
            external_route_tag=random.randint(1, 65535)
        )
        self.add_lsa(LSAType.AS_EXTERNAL_LSA.value, external_network, ext_lsa)
        return ext_lsa


class OSPFSimulator:
    """OSPFv2 Simulator with Type-5 LSA support"""
    
    def __init__(self):
        self.routers: Dict[str, OSPFRouter] = {}
        self.lsdb = OSPFLSDB()
        self.external_networks: List[tuple] = []
    
    def add_router(self, router: OSPFRouter):
        """Add a router to the simulation"""
        self.routers[router.router_id] = router
        print(f"[OSPF] Router {router.router_id} added to simulation")
        if router.is_asbr:
            print(f"[OSPF] Router {router.router_id} is an AS Border Router (ASBR)")
    
    def create_router_lsa(self, router: OSPFRouter) -> RouterLSA:
        """Create Router-LSA (Type-1)"""
        links = []
        
        for iface in router.interfaces:
            # Create link for each interface
            link = LSALink(
                link_id=iface.ip_address,
                link_data=iface.ip_address,
                type=3,  # Stub network for simplicity
                metric=iface.cost
            )
            links.append(link)
        
        router_lsa = RouterLSA(
            lsa_type=LSAType.ROUTER_LSA.value,
            lsa_id=router.router_id,
            advertising_router=router.router_id,
            sequence=0x80000001,
            links=links,
            flags=(1 if router.is_abr else 0) | (2 if router.is_asbr else 0)
        )
        
        return router_lsa
    
    def create_network_lsa(self, router: OSPFRouter, designated_router: str) -> NetworkLSA:
        """Create Network-LSA (Type-2)"""
        network_lsa = NetworkLSA(
            lsa_type=LSAType.NETWORK_LSA.value,
            lsa_id=designated_router,
            advertising_router=designated_router,
            network_mask=router.interfaces[0].network_mask if router.interfaces else "255.255.255.0",
            attached_routers=[router.router_id]
        )
        return network_lsa
    
    def create_summary_lsa(self, router_id: str, destination: str, 
                           mask: str, metric: int, lsa_type: int = 3) -> SummaryLSA:
        """Create Summary-LSA (Type-3) or ASBR-Summary-LSA (Type-4)"""
        summary_lsa = SummaryLSA(
            lsa_type=lsa_type,
            lsa_id=destination,
            advertising_router=router_id,
            network_mask=mask,
            metric=metric
        )
        return summary_lsa
    
    def create_as_external_lsa(self, asbr: OSPFRouter, external_network: str,
                                mask: str, metric: int, metric_type: int = 2) -> ASExternalLSA:
        """Create AS-External-LSA (Type-5)
        
        Type-5 LSA is generated by AS Border Routers (ASBR) to advertise
        external routes into the OSPF domain.
        
        Metric Types:
        - Type-1 (E1): Metric = External Cost + Internal Cost
        - Type-2 (E2): Metric = External Cost only (default)
        """
        ext_lsa = ASExternalLSA(
            lsa_type=LSAType.AS_EXTERNAL_LSA.value,
            lsa_id=external_network,
            advertising_router=asbr.router_id,
            sequence=0x80000001,
            network_mask=mask,
            metric=metric,
            metric_type=metric_type,
            forward_address="0.0.0.0",
            external_route_tag=random.randint(1, 65535)
        )
        
        self.lsdb.add_lsa(LSAType.AS_EXTERNAL_LSA.value, external_network, ext_lsa)
        self.external_networks.append((external_network, mask, metric, metric_type))
        
        return ext_lsa
    
    def flood_lsa(self, lsa_type: int, lsa_id: str, lsa_data):
        """Flood LSA to all routers"""
        self.lsdb.add_lsa(lsa_type, lsa_id, lsa_data)
        for router in self.routers.values():
            router.lsdb[lsa_type][lsa_id] = lsa_data
    
    def calculate_spf(self, router_id: str):
        """Run SPF algorithm for a router"""
        print(f"\n[SPF] Running SPF calculation for Router {router_id}")
        
        if router_id not in self.routers:
            return
        
        router = self.routers[router_id]
        router.routing_table = {}
        
        # Get Router-LSAs from LSDB
        router_lsas = self.lsdb.get_all_lsa(LSAType.ROUTER_LSA.value)
        
        # Build SPF tree
        visited = set()
        candidate_list = []
        
        # Start with this router's LSA
        if router.router_id in router_lsas:
            rtr_lsa = router_lsas[router.router_id]
            for link in rtr_lsa.links:
                candidate_list.append({
                    'dest': link.link_id,
                    'cost': link.metric,
                    'via': router.router_id
                })
        
        while candidate_list:
            # Sort by cost
            candidate_list.sort(key=lambda x: x['cost'])
            next_hop = candidate_list.pop(0)
            
            if next_hop['dest'] in visited:
                continue
            
            visited.add(next_hop['dest'])
            
            # Add to routing table
            router.routing_table[next_hop['dest']] = {
                'cost': next_hop['cost'],
                'via': next_hop['via']
            }
            
            # Process links from this LSA
            if next_hop['dest'] in router_lsas:
                dest_lsa = router_lsas[next_hop['dest']]
                for link in dest_lsa.links:
                    if link.link_id not in visited:
                        new_cost = next_hop['cost'] + link.metric
                        candidate_list.append({
                            'dest': link.link_id,
                            'cost': new_cost,
                            'via': next_hop['dest']
                        })
        
        print(f"[SPF] SPF calculation complete for Router {router_id}")
    
    def calculate_routing_with_external(self, router_id: str):
        """Calculate routing table including external routes (Type-5 LSA)"""
        self.calculate_spf(router_id)
        
        if router_id not in self.routers:
            return
        
        router = self.routers[router_id]
        
        # Get AS-External-LSAs
        ext_lsas = self.lsdb.get_all_lsa(LSAType.AS_EXTERNAL_LSA.value)
        
        print(f"\n[Routing] Installing external routes for Router {router_id}")
        
        for lsa_id, ext_lsa in ext_lsas.items():
            if isinstance(ext_lsa, ASExternalLSA):
                # Calculate cost based on metric type
                if ext_lsa.metric_type == 1:  # E1
                    internal_cost = router.routing_table.get(ext_lsa.advertising_router, {}).get('cost', 0)
                    total_cost = ext_lsa.metric + internal_cost
                else:  # E2
                    total_cost = ext_lsa.metric
                
                router.routing_table[ext_lsa.lsa_id] = {
                    'cost': total_cost,
                    'via': ext_lsa.advertising_router,
                    'type': 'E2' if ext_lsa.metric_type == 2 else 'E1',
                    'external': True
                }
                print(f"  - External route: {ext_lsa.lsa_id}/{ext_lsa.network_mask} "
                      f"via {ext_lsa.advertising_router}, cost={total_cost}")
    
    def print_lsdb(self):
        """Print the Link State Database"""
        print("\n" + "="*60)
        print("LINK STATE DATABASE")
        print("="*60)
        
        for lsa_type in [1, 2, 3, 4, 5]:
            lsas = self.lsdb.get_all_lsa(lsa_type)
            if lsas:
                print(f"\n--- LSA Type {lsa_type} ---")
                for lsa_id, lsa_data in lsas.items():
                    if isinstance(lsa_data, RouterLSA):
                        print(f"  Router-LSA: {lsa_data.lsa_id}")
                        print(f"    Advertising Router: {lsa_data.advertising_router}")
                        print(f"    Flags: B={bool(lsa_data.flags & 1)}, E={bool(lsa_data.flags & 2)}")
                        print(f"    Links: {len(lsa_data.links)}")
                    elif isinstance(lsa_data, NetworkLSA):
                        print(f"  Network-LSA: {lsa_data.lsa_id}")
                        print(f"    DR: {lsa_data.advertising_router}")
                        print(f"    Attached: {lsa_data.attached_routers}")
                    elif isinstance(lsa_data, SummaryLSA):
                        print(f"  Summary-LSA: {lsa_data.lsa_id}")
                        print(f"    Mask: {lsa_data.network_mask}, Metric: {lsa_data.metric}")
                    elif isinstance(lsa_data, ASExternalLSA):
                        print(f"  AS-External-LSA (Type-5): {lsa_data.lsa_id}")
                        print(f"    Mask: {lsa_data.network_mask}")
                        print(f"    Metric: {lsa_data.metric} (Type-{lsa_data.metric_type})")
                        print(f"    Advertising Router: {lsa_data.advertising_router}")
                        print(f"    Forward Address: {lsa_data.forward_address}")
                        print(f"    Route Tag: {lsa_data.external_route_tag}")
    
    def print_routing_table(self, router_id: str):
        """Print routing table for a router"""
        if router_id not in self.routers:
            return
        
        router = self.routers[router_id]
        print(f"\n--- Routing Table for Router {router_id} ---")
        
        for dest, info in router.routing_table.items():
            if info.get('external'):
                print(f"  {dest} via {info['via']} cost={info['cost']} [{info.get('type', 'E2')}] [External]")
            else:
                print(f"  {dest} via {info['via']} cost={info['cost']}")


def demo():
    """Demonstrate OSPFv2 with Type-5 LSA"""
    print("="*60)
    print("OSPFv2 Simulator - Type-5 LSA (AS-External-LSA) Demo")
    print("="*60)
    
    sim = OSPFSimulator()
    
    # Create routers
    router1 = OSPFRouter(
        router_id="1.1.1.1",
        area_id="0.0.0.0",
        interfaces=[OSPFInterface(ip_address="10.0.1.1", cost=10)],
        is_asbr=True  # This router connects to external network
    )
    
    router2 = OSPFRouter(
        router_id="2.2.2.2",
        area_id="0.0.0.0",
        interfaces=[OSPFInterface(ip_address="10.0.1.2", cost=10)],
        is_abr=True  # Area Border Router
    )
    
    router3 = OSPFRouter(
        router_id="3.3.3.3",
        area_id="0.0.0.0",
        interfaces=[OSPFInterface(ip_address="10.0.2.1", cost=10)]
    )
    
    # Add routers to simulation
    sim.add_router(router1)
    sim.add_router(router2)
    sim.add_router(router3)
    
    # Create and flood Router-LSAs (Type-1)
    for router in sim.routers.values():
        rtr_lsa = sim.create_router_lsa(router)
        sim.flood_lsa(LSAType.ROUTER_LSA.value, router.router_id, rtr_lsa)
    
    # ASBR (router1) advertises external network with Type-5 LSA
    print("\n[OSPF] ASBR Router 1.1.1.1 advertising external network 192.168.100.0/24")
    ext_lsa = sim.create_as_external_lsa(
        asbr=router1,
        external_network="192.168.100.0",
        mask="255.255.255.0",
        metric=20,
        metric_type=2  # Type-2 (E2) external route
    )
    
    # Print LSDB
    sim.print_lsdb()
    
    # Calculate routing tables
    for router_id in sim.routers:
        sim.calculate_routing_with_external(router_id)
        sim.print_routing_table(router_id)
    
    print("\n" + "="*60)
    print("Demo complete!")
    print("="*60)


if __name__ == "__main__":
    demo()
