# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## 脚本目录

### 黄金价格监控
- 路径：`/script/gold_price/`
- 脚本：`gold_price_daemon.py`（主）、`gold_price_check.sh`（启动）
- 数据：`gold_price_log.md`
- README：`/script/gold_price/README.md`
- Cron：`@reboot /script/gold_price/gold_price_check.sh`

### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.
