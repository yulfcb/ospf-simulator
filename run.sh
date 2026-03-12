#!/bin/bash
# OSPF 模拟器启动脚本

cd /work/ospf_sim

# 检查 Python 和依赖
echo "检查环境..."

# 检查 PyQt5
python3 -c "import PyQt5" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "安装 PyQt5..."
    pip3 install PyQt5
fi

# 检查依赖
python3 -c "import socket, struct, threading" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "依赖检查通过"
else
    echo "缺少必要依赖"
    exit 1
fi

# 运行测试
echo ""
echo "=== 运行测试 ==="
python3 tests/test_ospf.py

# 启动 GUI
echo ""
echo "=== 启动 GUI ==="
echo "如果无 GUI 环境，请使用: python3 src/ospf_core.py"
python3 src/ospf_gui.py
