#!/usr/bin/env python3
"""
OSPF 模拟器 - 图形化配置界面
基于 PyQt5
支持多实例: 同一物理接口上运行多个 OSPF 实例
"""

import sys
import threading
import time
import logging
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

logger = logging.getLogger(__name__)

# 导入 OSPF 核心
sys.path.insert(0, '/root/.openclaw/workspace/src')
from ospf_core import OSPFSimulator, OSPFInstance, NeighborState, get_system_interfaces, cidr_to_netmask


class OSPFGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.simulator = None
        self.running = False
        self.instances = {}  # instance_id -> instance info
        self.current_instance_id = None
        self.init_ui()
    
    def eventFilter(self, obj, event):
        """事件过滤器：阻止静态路由表空白区域点击取消选中"""
        if obj == self.static_route_table.viewport():
            if event.type() == event.MouseButtonPress:
                index = self.static_route_table.indexAt(event.pos())
                if not index.isValid():
                    return True
        return super().eventFilter(obj, event)
    
    def init_ui(self):
        self.setWindowTitle("OSPFv2 模拟器 (多实例支持)")
        self.setGeometry(100, 100, 1100, 800)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)
        
        # === 实例管理区 ===
        instance_group = QGroupBox("OSPF 实例管理")
        instance_layout = QGridLayout()
        
        # 实例列表
        instance_layout.addWidget(QLabel("实例列表:"), 0, 0)
        self.instance_combo = QComboBox()
        self.instance_combo.currentIndexChanged.connect(self.on_instance_changed)
        instance_layout.addWidget(self.instance_combo, 0, 1, 1, 2)
        
        # 添加实例按钮
        self.add_instance_btn = QPushButton("➕ 新建实例")
        self.add_instance_btn.clicked.connect(self.add_new_instance)
        instance_layout.addWidget(self.add_instance_btn, 0, 3)
        
        # 删除实例按钮
        self.del_instance_btn = QPushButton("🗑 删除实例")
        self.del_instance_btn.clicked.connect(self.delete_instance)
        instance_layout.addWidget(self.del_instance_btn, 0, 4)
        
        instance_group.setLayout(instance_layout)
        layout.addWidget(instance_group)
        
        # === 配置区 ===
        config_group = QGroupBox("OSPF 配置 (当前实例)")
        config_layout = QGridLayout()
        
        # Router ID
        config_layout.addWidget(QLabel("Router ID:"), 0, 0)
        self.router_id_edit = QLineEdit("192.168.1.1")
        config_layout.addWidget(self.router_id_edit, 0, 1)
        
        # Area ID
        config_layout.addWidget(QLabel("Area ID:"), 0, 2)
        self.area_id_edit = QLineEdit("0.0.0.0")
        config_layout.addWidget(self.area_id_edit, 0, 3)
        
        # Source IP (用于多实例)
        config_layout.addWidget(QLabel("源 IP:"), 0, 4)
        self.source_ip_edit = QLineEdit("")
        self.source_ip_edit.setPlaceholderText("留空使用接口IP")
        config_layout.addWidget(self.source_ip_edit, 0, 5)
        
        # 接口名称
        config_layout.addWidget(QLabel("接口名称:"), 1, 0)
        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.addItem("自定义...")
        self.iface_combo.currentIndexChanged.connect(self.on_interface_changed)
        config_layout.addWidget(self.iface_combo, 1, 1)
        
        self.refresh_iface_btn = QPushButton("🔄")
        self.refresh_iface_btn.setToolTip("刷新接口列表")
        self.refresh_iface_btn.clicked.connect(self.refresh_interfaces)
        self.refresh_iface_btn.setMaximumWidth(40)
        config_layout.addWidget(self.refresh_iface_btn, 1, 2)
        
        # 接口 IP
        config_layout.addWidget(QLabel("接口 IP:"), 1, 3)
        self.iface_ip_edit = QLineEdit("192.168.1.1")
        config_layout.addWidget(self.iface_ip_edit, 1, 4)
        
        # 子网掩码
        config_layout.addWidget(QLabel("子网掩码:"), 1, 5)
        self.netmask_edit = QLineEdit("255.255.255.0")
        config_layout.addWidget(self.netmask_edit, 1, 6)
        
        # 成本
        config_layout.addWidget(QLabel("Cost:"), 2, 0)
        self.cost_spin = QSpinBox()
        self.cost_spin.setValue(1)
        self.cost_spin.setMaximum(65535)
        config_layout.addWidget(self.cost_spin, 2, 1)
        
        # MTU
        config_layout.addWidget(QLabel("MTU:"), 2, 2)
        self.mtu_spin = QSpinBox()
        self.mtu_spin.setValue(1500)
        self.mtu_spin.setRange(68, 9000)
        config_layout.addWidget(self.mtu_spin, 2, 3)
        
        # DD优先级
        config_layout.addWidget(QLabel("DD优先级:"), 2, 4)
        self.priority_spin = QSpinBox()
        self.priority_spin.setValue(1)
        self.priority_spin.setMaximum(255)
        config_layout.addWidget(self.priority_spin, 2, 5)
        
        # 添加/删除接口按钮
        btn_layout = QHBoxLayout()
        self.add_iface_btn = QPushButton("➕ 添加接口")
        self.add_iface_btn.clicked.connect(self.add_interface)
        btn_layout.addWidget(self.add_iface_btn)
        
        self.del_iface_btn = QPushButton("➖ 删除接口")
        self.del_iface_btn.clicked.connect(self.delete_interface)
        btn_layout.addWidget(self.del_iface_btn)
        
        config_layout.addLayout(btn_layout, 3, 0, 1, 3)
        
        self.system_interfaces = {}
        self.refresh_interfaces()
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # === 路由注入区 ===
        route_group = QGroupBox("静态路由注入")
        route_layout = QGridLayout()
        
        route_layout.addWidget(QLabel("基础网络:"), 0, 0)
        self.base_network_edit = QLineEdit("10.0.0.0")
        route_layout.addWidget(self.base_network_edit, 0, 1)
        
        route_layout.addWidget(QLabel("路由数量:"), 0, 2)
        self.route_count_spin = QSpinBox()
        self.route_count_spin.setValue(10)
        self.route_count_spin.setMaximum(1000)
        route_layout.addWidget(self.route_count_spin, 0, 3)
        
        route_layout.addWidget(QLabel("前缀长度:"), 1, 0)
        self.prefix_spin = QSpinBox()
        self.prefix_spin.setValue(24)
        self.prefix_spin.setRange(8, 32)
        route_layout.addWidget(self.prefix_spin, 1, 1)
        
        route_layout.addWidget(QLabel("下一跳:"), 1, 2)
        self.next_hop_edit = QLineEdit("0.0.0.0")
        route_layout.addWidget(self.next_hop_edit, 1, 3)
        
        self.gen_routes_btn = QPushButton("批量生成路由")
        self.gen_routes_btn.clicked.connect(self.generate_routes)
        route_layout.addWidget(self.gen_routes_btn, 2, 0, 1, 4)
        
        self.inject_btn = QPushButton("注入 LSA 到邻居")
        self.inject_btn.clicked.connect(self.inject_lsa)
        route_layout.addWidget(self.inject_btn, 3, 0, 1, 4)
        
        route_group.setLayout(route_layout)
        layout.addWidget(route_group)
        
        # === 控制区 ===
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("启动 OSPF")
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 10px; }")
        self.start_btn.clicked.connect(self.start_ospf)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止 OSPF")
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 10px; }")
        self.stop_btn.clicked.connect(self.stop_ospf)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.refresh_btn = QPushButton("刷新状态")
        self.refresh_btn.clicked.connect(self.refresh_status)
        control_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(control_layout)
        
        # === 状态显示区 ===
        status_group = QGroupBox("状态信息")
        status_layout = QVBoxLayout()
        
        # 实例状态
        self.instance_status_text = QTextEdit()
        self.instance_status_text.setMaximumHeight(80)
        self.instance_status_text.setReadOnly(True)
        status_layout.addWidget(QLabel("实例状态:"))
        status_layout.addWidget(self.instance_status_text)
        
        # 接口状态
        self.iface_table = QTableWidget()
        self.iface_table.setColumnCount(6)
        self.iface_table.setHorizontalHeaderLabels(["实例", "接口", "IP", "掩码", "Cost", "状态"])
        self.iface_table.horizontalHeader().setStretchLastSection(True)
        status_layout.addWidget(QLabel("接口状态:"))
        status_layout.addWidget(self.iface_table)
        
        # 邻居状态
        self.neighbor_table = QTableWidget()
        self.neighbor_table.setColumnCount(5)
        self.neighbor_table.setHorizontalHeaderLabels(["实例", "邻居IP", "状态", "DR", "BDR"])
        self.neighbor_table.horizontalHeader().setStretchLastSection(True)
        status_layout.addWidget(QLabel("邻居状态:"))
        status_layout.addWidget(self.neighbor_table)
        
        # 路由表
        self.route_table = QTableWidget()
        self.route_table.setColumnCount(4)
        self.route_table.setHorizontalHeaderLabels(["网络", "掩码", "下一跳", "类型"])
        self.route_table.horizontalHeader().setStretchLastSection(True)
        status_layout.addWidget(QLabel("路由表:"))
        status_layout.addWidget(self.route_table)
        
        # 静态路由表
        self.static_route_table = QTableWidget()
        self.static_route_table.setColumnCount(3)
        self.static_route_table.setHorizontalHeaderLabels(["网络", "掩码", "下一跳"])
        self.static_route_table.horizontalHeader().setStretchLastSection(True)
        self.static_route_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.static_route_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.static_route_table.setFocusPolicy(Qt.NoFocus)
        self.static_route_table.setStyleSheet("""
            QTableWidget::item:selected { background-color: #0078D7; color: white; }
            QTableWidget::item:selected:!active { background-color: #0078D7; color: white; }
        """)
        self.static_route_table.viewport().installEventFilter(self)
        status_layout.addWidget(QLabel("静态路由:"))
        status_layout.addWidget(self.static_route_table)
        
        self.del_static_route_btn = QPushButton("删除选中静态路由")
        self.del_static_route_btn.clicked.connect(self.delete_static_route)
        status_layout.addWidget(self.del_static_route_btn)
        
        # 统计
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(100)
        self.stats_text.setReadOnly(True)
        status_layout.addWidget(QLabel("统计:"))
        status_layout.addWidget(self.stats_text)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # 接口列表
        self.interfaces = {}
    
    def add_new_instance(self):
        """添加新实例"""
        dialog = QDialog(self)
        dialog.setWindowTitle("新建 OSPF 实例")
        layout = QVBoxLayout()
        
        # Router ID
        router_id_layout = QHBoxLayout()
        router_id_layout.addWidget(QLabel("Router ID:"))
        router_id_edit = QLineEdit("192.168.1.2")
        router_id_layout.addWidget(router_id_edit)
        layout.addLayout(router_id_layout)
        
        # Area ID
        area_id_layout = QHBoxLayout()
        area_id_layout.addWidget(QLabel("Area ID:"))
        area_id_edit = QLineEdit("0.0.0.0")
        area_id_layout.addWidget(area_id_edit)
        layout.addLayout(area_id_layout)
        
        # Source IP
        source_ip_layout = QHBoxLayout()
        source_ip_layout.addWidget(QLabel("源 IP:"))
        source_ip_edit = QLineEdit()
        source_ip_edit.setPlaceholderText("留空使用接口IP")
        source_ip_layout.addWidget(source_ip_edit)
        layout.addLayout(source_ip_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        dialog.setLayout(layout)
        
        def on_ok():
            router_id = router_id_edit.text()
            area_id = area_id_edit.text()
            source_ip = source_ip_edit.text() if source_ip_edit.text() else None
            
            if not router_id:
                QMessageBox.warning(self, "错误", "请输入 Router ID")
                return
            
            if self.simulator and self.running:
                # 在运行时创建实例
                instance = self.simulator.create_instance(router_id, area_id, source_ip)
                instance_id = instance.instance_id
            else:
                # 离线模式，只记录配置
                instance_id = len(self.instances) + 1
            
            self.instances[instance_id] = {
                'router_id': router_id,
                'area_id': area_id,
                'source_ip': source_ip,
                'interfaces': {}
            }
            
            # 更新实例下拉框
            self.instance_combo.clear()
            for iid, info in self.instances.items():
                self.instance_combo.addItem(f"实例{iid}: {info['router_id']}", iid)
            
            dialog.accept()
            QMessageBox.information(self, "成功", f"实例 {instance_id} ({router_id}) 已创建")
        
        ok_btn.clicked.connect(on_ok)
        cancel_btn.clicked.connect(dialog.reject)
        
        dialog.exec_()
    
    def delete_instance(self):
        """删除选中的实例"""
        current_idx = self.instance_combo.currentIndex()
        if current_idx < 0:
            QMessageBox.warning(self, "错误", "请选择要删除的实例")
            return
        
        instance_id = self.instance_combo.currentData()
        
        reply = QMessageBox.question(self, "确认", f"确定删除实例 {instance_id}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.simulator and self.running:
                self.simulator.delete_instance(instance_id)
            
            del self.instances[instance_id]
            
            self.instance_combo.blockSignals(True)
            self.instance_combo.clear()
            for iid, info in self.instances.items():
                self.instance_combo.addItem(f"实例{iid}: {info['router_id']}", iid)
            self.instance_combo.blockSignals(False)
            
            QMessageBox.information(self, "成功", f"实例 {instance_id} 已删除")
    
    def on_instance_changed(self, index):
        """实例选择变化"""
        if index < 0:
            return
        
        instance_id = self.instance_combo.currentData()
        if instance_id and instance_id in self.instances:
            info = self.instances[instance_id]
            self.router_id_edit.setText(info['router_id'])
            self.area_id_edit.setText(info['area_id'])
            self.source_ip_edit.setText(info.get('source_ip', '') or '')
    
    def start_ospf(self):
        """启动 OSPF"""
        if not self.instances:
            QMessageBox.warning(self, "错误", "请先创建至少一个 OSPF 实例")
            return
        
        # 创建模拟器（使用第一个实例的 router_id）
        first_inst = list(self.instances.values())[0]
        self.simulator = OSPFSimulator(first_inst['router_id'], first_inst['area_id'])
        
        # 添加所有实例
        for iid, info in self.instances.items():
            if iid in self.simulator.instances:
                continue
            
            instance = self.simulator.create_instance(
                router_id=info['router_id'],
                area_id=info['area_id'],
                source_ip=info.get('source_ip')
            )
            
            # 添加接口
            for name, iface_info in info.get('interfaces', {}).items():
                instance.add_interface(name, iface_info['ip'], iface_info['netmask'],
                                       iface_info['cost'], iface_info['mtu'])
        
        # 同时添加主 router 的接口（向后兼容）
        for name, info in self.interfaces.items():
            self.simulator.router.add_interface(name, info['ip'], info['netmask'], info['cost'])
        
        self.simulator.start()
        self.running = True
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start(2000)
        
        QMessageBox.information(self, "成功", f"OSPF 模拟器已启动 ({len(self.instances)} 个实例)")
    
    def stop_ospf(self):
        """停止 OSPF"""
        if self.simulator:
            self.simulator.stop()
            self.simulator.router.neighbors.clear()
            self.simulator.router.routes.clear()
            self.simulator.router.lsdb.clear()
            
            for instance in self.simulator.instances.values():
                instance.neighbors.clear()
                instance.routes.clear()
                instance.lsdb.clear()
        
        self.running = False
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if hasattr(self, 'timer'):
            self.timer.stop()
        
        self.neighbor_table.setRowCount(0)
        self.route_table.setRowCount(0)
        self.stats_text.setPlainText("OSPF 已停止")
        
        QMessageBox.information(self, "成功", "OSPF 模拟器已停止")
    
    def refresh_interfaces(self):
        """刷新系统接口列表"""
        self.system_interfaces = get_system_interfaces()
        
        current = self.iface_combo.currentText()
        
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        self.iface_combo.addItem("自定义...")
        
        for iface_name, iface_info in self.system_interfaces.items():
            display = f"{iface_name} ({iface_info['ip']})"
            self.iface_combo.addItem(display, iface_info)
        
        idx = self.iface_combo.findText(current)
        if idx >= 0:
            self.iface_combo.setCurrentIndex(idx)
        
        self.iface_combo.blockSignals(False)
        logger.info(f"刷新接口列表: {list(self.system_interfaces.keys())}")
    
    def on_interface_changed(self, index):
        """接口下拉框选择变化"""
        if index == 0:
            self.iface_ip_edit.setEnabled(True)
            self.iface_ip_edit.setText("")
            self.netmask_edit.setEnabled(True)
            self.netmask_edit.setText("255.255.255.0")
        else:
            iface_info = self.iface_combo.currentData()
            if iface_info:
                self.iface_ip_edit.setText(iface_info.get('ip', ''))
                netmask = iface_info.get('netmask', '255.255.255.0')
                if '/' in netmask:
                    netmask = cidr_to_netmask(netmask)
                self.netmask_edit.setText(netmask)
                self.iface_ip_edit.setEnabled(False)
                self.netmask_edit.setEnabled(False)
    
    def delete_interface(self):
        """删除选中的接口"""
        current_row = self.iface_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "错误", "请先选择要删除的接口")
            return
        
        name_item = self.iface_table.item(current_row, 1)
        if name_item:
            name = name_item.text()
            instance_item = self.iface_table.item(current_row, 0)
            instance_id = instance_item.text() if instance_item else "main"
            
            if instance_id == "main":
                if name in self.interfaces:
                    del self.interfaces[name]
            elif instance_id.isdigit() and int(instance_id) in self.instances:
                inst_id = int(instance_id)
                if name in self.instances[inst_id]['interfaces']:
                    del self.instances[inst_id]['interfaces'][name]
            
            self.iface_table.removeRow(current_row)
            logger.info(f"删除接口: {name} from {instance_id}")
    
    def add_interface(self):
        """添加接口"""
        current_instance_idx = self.instance_combo.currentIndex()
        instance_id = self.instance_combo.currentData() if current_instance_idx >= 0 else None
        
        if self.iface_combo.currentIndex() == 0:
            name = self.iface_combo.currentText()
        else:
            name = self.iface_combo.currentText().split(' ')[0]
        
        ip = self.iface_ip_edit.text()
        netmask = self.netmask_edit.text()
        cost = self.cost_spin.value()
        mtu = self.mtu_spin.value()
        
        if not name or not ip:
            QMessageBox.warning(self, "错误", "请输入接口名称和IP")
            return
        
        iface_info = {'ip': ip, 'netmask': netmask, 'cost': cost, 'mtu': mtu}
        
        if instance_id and instance_id in self.instances:
            # 添加到指定实例
            self.instances[instance_id]['interfaces'][name] = iface_info
            display_instance = str(instance_id)
        else:
            # 添加到主 router
            self.interfaces[name] = iface_info
            display_instance = "main"
        
        # 更新表格
        row = self.iface_table.rowCount()
        self.iface_table.insertRow(row)
        self.iface_table.setItem(row, 0, QTableWidgetItem(display_instance))
        self.iface_table.setItem(row, 1, QTableWidgetItem(name))
        self.iface_table.setItem(row, 2, QTableWidgetItem(ip))
        self.iface_table.setItem(row, 3, QTableWidgetItem(netmask))
        self.iface_table.setItem(row, 4, QTableWidgetItem(str(cost)))
        self.iface_table.setItem(row, 5, QTableWidgetItem("Down"))
        
        # 如果 OSPF 已启动，添加到 router
        if self.running and self.simulator:
            if instance_id and instance_id in self.simulator.instances:
                inst = self.simulator.instances[instance_id]
                inst.add_interface(name, ip, netmask, cost, mtu)
            else:
                self.simulator.router.add_interface(name, ip, netmask, cost, mtu)
        
        QMessageBox.information(self, "成功", f"接口 {name} 已添加到实例 {display_instance}")
    
    def generate_routes(self):
        """批量生成路由"""
        if not self.simulator:
            QMessageBox.warning(self, "错误", "请先启动 OSPF")
            return
        
        base_network = self.base_network_edit.text()
        count = self.route_count_spin.value()
        prefix = self.prefix_spin.value()
        next_hop = self.next_hop_edit.text()
        
        netmask = self._prefix_to_mask(prefix)
        
        # 获取当前选中的实例
        current_instance_idx = self.instance_combo.currentIndex()
        instance_id = self.instance_combo.currentData() if current_instance_idx >= 0 else None
        
        for i in range(count):
            network = self._increment_network(base_network, i)
            
            if instance_id and instance_id in self.simulator.instances:
                self.simulator.instances[instance_id].add_static_route(network, netmask, next_hop)
            else:
                self.simulator.router.add_static_route(network, netmask, next_hop)
        
        QMessageBox.information(self, "成功", f"已生成 {count} 条路由")
        self.refresh_status()
    
    def inject_lsa(self):
        """注入 LSA"""
        if not self.simulator:
            QMessageBox.warning(self, "错误", "请先启动 OSPF")
            return
        
        current_instance_idx = self.instance_combo.currentIndex()
        instance_id = self.instance_combo.currentData() if current_instance_idx >= 0 else None
        
        if instance_id and instance_id in self.simulator.instances:
            inst = self.simulator.instances[instance_id]
            if self.simulator.sock:
                inst.flood_lsa(self.simulator.sock, use_raw=self.simulator.use_raw,
                             add_ip_header_func=self.simulator._add_ip_header)
        else:
            if self.simulator.sock:
                self.simulator.router.flood_lsa(self.simulator.sock,
                                               use_raw=self.simulator.use_raw,
                                               add_ip_header_func=self.simulator._add_ip_header)
        
        QMessageBox.information(self, "成功", "LSA 已注入到邻居")
    
    def delete_static_route(self):
        """删除选中的静态路由"""
        if not self.simulator:
            QMessageBox.warning(self, "错误", "请先启动 OSPF")
            return
        
        selected_rows = set(item.row() for item in self.static_route_table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "错误", "请先选择要删除的静态路由")
            return
        
        selected_rows = sorted(selected_rows, reverse=True)
        
        current_instance_idx = self.instance_combo.currentIndex()
        instance_id = self.instance_combo.currentData() if current_instance_idx >= 0 else None
        
        deleted_count = 0
        for row in selected_rows:
            network_item = self.static_route_table.item(row, 0)
            netmask_item = self.static_route_table.item(row, 1)
            
            if network_item and netmask_item:
                network = network_item.text()
                netmask = netmask_item.text()
                
                if instance_id and instance_id in self.simulator.instances:
                    inst = self.simulator.instances[instance_id]
                    success = inst.remove_static_route(network, netmask, self.simulator.sock,
                                                      self.simulator.use_raw,
                                                      self.simulator._add_ip_header)
                else:
                    success = self.simulator.router.remove_static_route(network, netmask,
                                                                        self.simulator.sock,
                                                                        self.simulator.use_raw,
                                                                        self.simulator._add_ip_header)
                if success:
                    deleted_count += 1
        
        if deleted_count > 0:
            for row in selected_rows:
                self.static_route_table.removeRow(row)
            QMessageBox.information(self, "成功", f"已删除 {deleted_count} 条静态路由")
            self.refresh_status()
        else:
            QMessageBox.warning(self, "错误", "删除失败，所选路由不存在")
    
    def _update_static_route_table(self):
        """更新静态路由表格"""
        selected_routes = set()
        for item in self.static_route_table.selectedItems():
            row = item.row()
            network_item = self.static_route_table.item(row, 0)
            netmask_item = self.static_route_table.item(row, 1)
            if network_item and netmask_item:
                selected_routes.add((network_item.text(), netmask_item.text()))
        
        static_routes = []
        
        if self.simulator:
            # 主 router 的静态路由
            for route_key, route in self.simulator.router.routes.items():
                if route.get('type') == 'static':
                    static_routes.append({
                        'network': route['network'], 'netmask': route['netmask'],
                        'next_hop': route.get('next_hop', '0.0.0.0'), 'instance': 'main'
                    })
            
            # 所有实例的静态路由
            for iid, inst in self.simulator.instances.items():
                for route_key, route in inst.routes.items():
                    if route.get('type') == 'static':
                        static_routes.append({
                            'network': route['network'], 'netmask': route['netmask'],
                            'next_hop': route.get('next_hop', '0.0.0.0'), 'instance': str(iid)
                        })
        
        self.static_route_table.setRowCount(0)
        new_selected_rows = []
        
        for route in static_routes:
            row = self.static_route_table.rowCount()
            self.static_route_table.insertRow(row)
            self.static_route_table.setItem(row, 0, QTableWidgetItem(route['network']))
            self.static_route_table.setItem(row, 1, QTableWidgetItem(route['netmask']))
            self.static_route_table.setItem(row, 2, QTableWidgetItem(route['next_hop']))
            
            if (route['network'], route['netmask']) in selected_routes:
                new_selected_rows.append(row)
        
        for row in new_selected_rows:
            for col in range(self.static_route_table.columnCount()):
                item = self.static_route_table.item(row, col)
                if item:
                    item.setSelected(True)
    
    def refresh_status(self):
        """刷新状态"""
        if not self.simulator:
            return
        
        status = self.simulator.router.get_status()
        
        # 更新实例状态
        instance_status = f"主实例 Router ID: {status['router_id']}\n"
        for iid, inst in self.simulator.instances.items():
            inst_status = inst.get_status()
            instance_status += f"实例{iid}: Router ID={inst_status['router_id']}, " \
                             f"邻居={inst_status['neighbors']}, " \
                             f"LSDB={inst_status['lsdb_entries']}, " \
                             f"路由={inst_status['routes']}\n"
        self.instance_status_text.setPlainText(instance_status)
        
        # 更新统计
        stats = status['stats']
        stats_text = f"""Hello 发送: {stats['hello_sent']}  接收: {stats['hello_recv']}
DD 发送: {stats['dd_sent']}  接收: {stats['dd_recv']}
LSR 发送: {stats['lsr_sent']}  接收: {stats['lsr_recv']}
LSU 发送: {stats['lsu_sent']}  接收: {stats['lsu_recv']}
LSAck 发送: {stats['lsack_sent']}  接收: {stats['lsack_recv']}
LSDB 条目: {status['lsdb_entries']}
路由条目: {status['routes']}"""
        self.stats_text.setPlainText(stats_text)
        
        # 更新邻居表格
        self.neighbor_table.setRowCount(0)
        for neighbor_id, info in self.simulator.router.neighbors.items():
            row = self.neighbor_table.rowCount()
            self.neighbor_table.insertRow(row)
            self.neighbor_table.setItem(row, 0, QTableWidgetItem("main"))
            self.neighbor_table.setItem(row, 1, QTableWidgetItem(neighbor_id))
            self.neighbor_table.setItem(row, 2, QTableWidgetItem(str(info['state']).split('.')[1]))
            self.neighbor_table.setItem(row, 3, QTableWidgetItem(info.get('dr', '0.0.0.0')))
            self.neighbor_table.setItem(row, 4, QTableWidgetItem(info.get('bdr', '0.0.0.0')))
        
        # 所有实例的邻居
        for iid, inst in self.simulator.instances.items():
            for neighbor_id, info in inst.neighbors.items():
                row = self.neighbor_table.rowCount()
                self.neighbor_table.insertRow(row)
                self.neighbor_table.setItem(row, 0, QTableWidgetItem(str(iid)))
                self.neighbor_table.setItem(row, 1, QTableWidgetItem(neighbor_id))
                self.neighbor_table.setItem(row, 2, QTableWidgetItem(str(info['state']).split('.')[1]))
                self.neighbor_table.setItem(row, 3, QTableWidgetItem(info.get('dr', '0.0.0.0')))
                self.neighbor_table.setItem(row, 4, QTableWidgetItem(info.get('bdr', '0.0.0.0')))
        
        # 更新路由表格
        self.route_table.setRowCount(0)
        for route_key, route in self.simulator.router.routes.items():
            row = self.route_table.rowCount()
            self.route_table.insertRow(row)
            self.route_table.setItem(row, 0, QTableWidgetItem(route['network']))
            self.route_table.setItem(row, 1, QTableWidgetItem(route['netmask']))
            self.route_table.setItem(row, 2, QTableWidgetItem(route.get('next_hop', '0.0.0.0')))
            self.route_table.setItem(row, 3, QTableWidgetItem(route.get('type', 'ospf')))
        
        # 更新静态路由表格
        self._update_static_route_table()
    
    def _prefix_to_mask(self, prefix: int) -> str:
        """前缀转掩码"""
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return socket.inet_ntoa(struct.pack("!I", mask))
    
    def _increment_network(self, base: str, offset: int) -> str:
        """递增网络号"""
        prefix = self.prefix_spin.value()
        
        base_int = struct.unpack("!I", socket.inet_aton(base))[0]
        netmask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        base_network_int = base_int & netmask
        
        host_bits = 32 - prefix
        increment = (1 << host_bits) if host_bits > 0 else 0
        new_network_int = base_network_int + (offset * increment)
        
        return socket.inet_ntoa(struct.pack("!I", new_network_int))


import socket
import struct

def main():
    app = QApplication(sys.argv)
    window = OSPFGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
