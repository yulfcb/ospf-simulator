#!/usr/bin/env python3
"""
OSPF 模拟器 - 图形化配置界面
基于 PyQt5
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
sys.path.insert(0, '/work/ospf_sim/src')
from ospf_core import OSPFSimulator, NeighborState, get_system_interfaces, cidr_to_netmask


class OSPFGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.simulator = None
        self.running = False
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("OSPFv2 模拟器")
        self.setGeometry(100, 100, 900, 700)
        
        # 中心部件
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)
        
        # === 配置区 ===
        config_group = QGroupBox("OSPF 配置")
        config_layout = QGridLayout()
        
        # Router ID
        config_layout.addWidget(QLabel("Router ID:"), 0, 0)
        self.router_id_edit = QLineEdit("192.168.1.1")
        config_layout.addWidget(self.router_id_edit, 0, 1)
        
        # Area ID
        config_layout.addWidget(QLabel("Area ID:"), 0, 2)
        self.area_id_edit = QLineEdit("0.0.0.0")
        config_layout.addWidget(self.area_id_edit, 0, 3)
        
        # 接口名称 - 下拉选择 + 自定义
        config_layout.addWidget(QLabel("接口名称:"), 1, 0)
        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.addItem("自定义...")
        self.iface_combo.currentIndexChanged.connect(self.on_interface_changed)
        config_layout.addWidget(self.iface_combo, 1, 1)
        
        # 刷新接口按钮
        self.refresh_iface_btn = QPushButton("🔄")
        self.refresh_iface_btn.setToolTip("刷新接口列表")
        self.refresh_iface_btn.clicked.connect(self.refresh_interfaces)
        self.refresh_iface_btn.setMaximumWidth(40)
        config_layout.addWidget(self.refresh_iface_btn, 1, 2)
        
        # 接口 IP
        config_layout.addWidget(QLabel("接口 IP:"), 1, 3)
        self.iface_ip_edit = QLineEdit("192.168.1.1")
        config_layout.addWidget(self.iface_ip_edit, 2, 0)
        
        # 子网掩码
        config_layout.addWidget(QLabel("子网掩码:"), 2, 1)
        self.netmask_edit = QLineEdit("255.255.255.0")
        config_layout.addWidget(self.netmask_edit, 2, 2)
        
        # 成本
        config_layout.addWidget(QLabel("Cost:"), 2, 3)
        self.cost_spin = QSpinBox()
        self.cost_spin.setValue(1)
        self.cost_spin.setMaximum(65535)
        config_layout.addWidget(self.cost_spin, 3, 0)
        
        # 添加/删除接口按钮
        btn_layout = QHBoxLayout()
        self.add_iface_btn = QPushButton("➕ 添加接口")
        self.add_iface_btn.clicked.connect(self.add_interface)
        btn_layout.addWidget(self.add_iface_btn)
        
        self.del_iface_btn = QPushButton("➖ 删除接口")
        self.del_iface_btn.clicked.connect(self.delete_interface)
        btn_layout.addWidget(self.del_iface_btn)
        
        config_layout.addLayout(btn_layout, 3, 1, 1, 3)
        
        # 初始化接口列表
        self.system_interfaces = {}
        self.refresh_interfaces()
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # === 路由注入区 ===
        route_group = QGroupBox("静态路由注入")
        route_layout = QGridLayout()
        
        # 基础网络
        route_layout.addWidget(QLabel("基础网络:"), 0, 0)
        self.base_network_edit = QLineEdit("10.0.0.0")
        route_layout.addWidget(self.base_network_edit, 0, 1)
        
        # 数量
        route_layout.addWidget(QLabel("路由数量:"), 0, 2)
        self.route_count_spin = QSpinBox()
        self.route_count_spin.setValue(10)
        self.route_count_spin.setMaximum(1000)
        route_layout.addWidget(self.route_count_spin, 0, 3)
        
        # 前缀
        route_layout.addWidget(QLabel("前缀长度:"), 1, 0)
        self.prefix_spin = QSpinBox()
        self.prefix_spin.setValue(24)
        self.prefix_spin.setRange(8, 32)
        route_layout.addWidget(self.prefix_spin, 1, 1)
        
        # 下一跳
        route_layout.addWidget(QLabel("下一跳:"), 1, 2)
        self.next_hop_edit = QLineEdit("0.0.0.0")
        route_layout.addWidget(self.next_hop_edit, 1, 3)
        
        # 生成路由按钮
        self.gen_routes_btn = QPushButton("批量生成路由")
        self.gen_routes_btn.clicked.connect(self.generate_routes)
        route_layout.addWidget(self.gen_routes_btn, 2, 0, 1, 4)
        
        # 注入 LSA 按钮
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
        
        # 接口状态
        self.iface_table = QTableWidget()
        self.iface_table.setColumnCount(5)
        self.iface_table.setHorizontalHeaderLabels(["接口", "IP", "掩码", "Cost", "状态"])
        status_layout.addWidget(QLabel("接口状态:"))
        status_layout.addWidget(self.iface_table)
        
        # 邻居状态
        self.neighbor_table = QTableWidget()
        self.neighbor_table.setColumnCount(4)
        self.neighbor_table.setHorizontalHeaderLabels(["邻居IP", "状态", "DR", "BDR"])
        status_layout.addWidget(QLabel("邻居状态:"))
        status_layout.addWidget(self.neighbor_table)
        
        # 路由表
        self.route_table = QTableWidget()
        self.route_table.setColumnCount(4)
        self.route_table.setHorizontalHeaderLabels(["网络", "掩码", "下一跳", "类型"])
        status_layout.addWidget(QLabel("路由表:"))
        status_layout.addWidget(self.route_table)
        
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
    
    def start_ospf(self):
        """启动 OSPF"""
        router_id = self.router_id_edit.text()
        area_id = self.area_id_edit.text()
        
        if not router_id:
            QMessageBox.warning(self, "错误", "请输入 Router ID")
            return
        
        self.simulator = OSPFSimulator(router_id, area_id)
        
        # 添加已配置的接口
        for name, info in self.interfaces.items():
            self.simulator.router.add_interface(name, info['ip'], info['netmask'], info['cost'])
        
        self.simulator.start()
        self.running = True
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # 启动状态更新定时器
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start(2000)
        
        QMessageBox.information(self, "成功", "OSPF 模拟器已启动")
    
    def stop_ospf(self):
        """停止 OSPF"""
        if self.simulator:
            self.simulator.stop()
        self.running = False
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if hasattr(self, 'timer'):
            self.timer.stop()
        
        QMessageBox.information(self, "成功", "OSPF 模拟器已停止")
    
    def refresh_interfaces(self):
        """刷新系统接口列表"""
        self.system_interfaces = get_system_interfaces()
        
        # 保存当前选择
        current = self.iface_combo.currentText()
        
        # 清空并重新填充
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        self.iface_combo.addItem("自定义...")
        
        for iface_name, iface_info in self.system_interfaces.items():
            display = f"{iface_name} ({iface_info['ip']})"
            self.iface_combo.addItem(display, iface_info)
        
        # 恢复选择
        idx = self.iface_combo.findText(current)
        if idx >= 0:
            self.iface_combo.setCurrentIndex(idx)
        
        self.iface_combo.blockSignals(False)
        logger.info(f"刷新接口列表: {list(self.system_interfaces.keys())}")
    
    def on_interface_changed(self, index):
        """接口下拉框选择变化"""
        if index == 0:
            # 自定义
            self.iface_ip_edit.setEnabled(True)
            self.iface_ip_edit.setText("")
            self.netmask_edit.setEnabled(True)
            self.netmask_edit.setText("255.255.255.0")
        else:
            # 选择系统接口
            iface_info = self.iface_combo.currentData()
            if iface_info:
                self.iface_ip_edit.setText(iface_info.get('ip', ''))
                netmask = iface_info.get('netmask', '255.255.255.0')
                # 如果是 CIDR 格式，转换
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
        
        name_item = self.iface_table.item(current_row, 0)
        if name_item:
            name = name_item.text()
            if name in self.interfaces:
                del self.interfaces[name]
                self.iface_table.removeRow(current_row)
                logger.info(f"删除接口: {name}")
    
    def add_interface(self):
        """添加接口"""
        # 获取接口名称
        if self.iface_combo.currentIndex() == 0:
            # 自定义
            name = self.iface_combo.currentText()
        else:
            # 从下拉框选择
            name = self.iface_combo.currentText().split(' ')[0]
        
        ip = self.iface_ip_edit.text()
        netmask = self.netmask_edit.text()
        cost = self.cost_spin.value()
        
        if not name or not ip:
            QMessageBox.warning(self, "错误", "请输入接口名称和IP")
            return
        
        self.interfaces[name] = {'ip': ip, 'netmask': netmask, 'cost': cost}
        
        # 更新表格
        row = self.iface_table.rowCount()
        self.iface_table.insertRow(row)
        self.iface_table.setItem(row, 0, QTableWidgetItem(name))
        self.iface_table.setItem(row, 1, QTableWidgetItem(ip))
        self.iface_table.setItem(row, 2, QTableWidgetItem(netmask))
        self.iface_table.setItem(row, 3, QTableWidgetItem(str(cost)))
        self.iface_table.setItem(row, 4, QTableWidgetItem("Down"))
        
        QMessageBox.information(self, "成功", f"接口 {name} 已添加")
    
    def generate_routes(self):
        """批量生成路由"""
        if not self.simulator:
            QMessageBox.warning(self, "错误", "请先启动 OSPF")
            return
        
        base_network = self.base_network_edit.text()
        count = self.route_count_spin.value()
        prefix = self.prefix_spin.value()
        next_hop = self.next_hop_edit.text()
        
        # 生成路由
        netmask = self._prefix_to_mask(prefix)
        for i in range(count):
            network = self._increment_network(base_network, i)
            self.simulator.router.add_static_route(network, netmask, next_hop)
        
        QMessageBox.information(self, "成功", f"已生成 {count} 条路由")
        self.refresh_status()
    
    def inject_lsa(self):
        """注入 LSA"""
        if not self.simulator:
            QMessageBox.warning(self, "错误", "请先启动 OSPF")
            return
        
        # 泛洪 LSA 到所有邻居
        if self.simulator.sock:
            self.simulator.router.flood_lsa(
                self.simulator.sock,
                use_raw=self.simulator.use_raw,
                add_ip_header_func=self.simulator._add_ip_header
            )
            QMessageBox.information(self, "成功", "LSA 已注入到邻居")
        else:
            QMessageBox.warning(self, "错误", "OSPF 未运行")
    
    def refresh_status(self):
        """刷新状态"""
        if not self.simulator:
            return
        
        status = self.simulator.router.get_status()
        
        # 更新统计
        stats = status['stats']
        stats_text = f"""
Hello 发送: {stats['hello_sent']}  接收: {stats['hello_recv']}
DD 发送: {stats['dd_sent']}  接收: {stats['dd_recv']}
LSR 发送: {stats['lsr_sent']}  接收: {stats['lsr_recv']}
LSU 发送: {stats['lsu_sent']}  接收: {stats['lsu_recv']}
LSAck 发送: {stats['lsack_sent']}  接收: {stats['lsack_recv']}
LSDB 条目: {status['lsdb_entries']}
路由条目: {status['routes']}
"""
        self.stats_text.setPlainText(stats_text)
        
        # 更新邻居表格
        self.neighbor_table.setRowCount(0)
        for neighbor_id, info in self.simulator.router.neighbors.items():
            row = self.neighbor_table.rowCount()
            self.neighbor_table.insertRow(row)
            self.neighbor_table.setItem(row, 0, QTableWidgetItem(neighbor_id))
            self.neighbor_table.setItem(row, 1, QTableWidgetItem(str(info['state']).split('.')[1]))
            self.neighbor_table.setItem(row, 2, QTableWidgetItem(info.get('dr', '0.0.0.0')))
            self.neighbor_table.setItem(row, 3, QTableWidgetItem(info.get('bdr', '0.0.0.0')))
        
        # 更新路由表格
        self.route_table.setRowCount(0)
        for route_key, route in self.simulator.router.routes.items():
            row = self.route_table.rowCount()
            self.route_table.insertRow(row)
            self.route_table.setItem(row, 0, QTableWidgetItem(route['network']))
            self.route_table.setItem(row, 1, QTableWidgetItem(route['netmask']))
            self.route_table.setItem(row, 2, QTableWidgetItem(route.get('next_hop', '0.0.0.0')))
            self.route_table.setItem(row, 3, QTableWidgetItem(route.get('type', 'ospf')))
    
    def _prefix_to_mask(self, prefix: int) -> str:
        """前缀转掩码"""
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return socket.inet_ntoa(struct.pack("!I", mask))
    
    def _increment_network(self, base: str, offset: int) -> str:
        """递增网络号"""
        parts = list(map(int, base.split('.')))
        parts[2] = (parts[2] + offset // 256) % 256
        parts[3] = (parts[3] + offset % 256) % 256
        return '.'.join(map(str, parts))


import socket
import struct

def main():
    app = QApplication(sys.argv)
    window = OSPFGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
