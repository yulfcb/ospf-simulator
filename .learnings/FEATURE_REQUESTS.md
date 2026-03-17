# Feature Requests Log

Record capabilities the user wants but don't exist yet.

## Format

```markdown
## [FEAT-YYYYMMDD-XXX] capability_name

**Logged**: YYYY-MM-DDTHH:MM:SSZ
**Priority**: medium
**Status**: pending
**Area**: frontend | backend | infra | tests | docs | config

### Requested Capability
What the user wants to do

### User Context
Why they need it

### Complexity Estimate
simple | medium | complex

### Suggested Implementation
How it could be built

### Metadata
- Frequency: first_time | recurring
- Related Features: existing_feature

---
```

---

## Recent Entries

<!-- Add new feature requests below -->

## [FEAT-20260317-001] 黄金价格播报增加变化幅度

**Logged**: 2026-03-17T14:28:00Z
**Priority**: medium
**Status**: pending
**Area**: config

### Requested Capability
黄金价格播报需要显示更多时间维度的变化幅度

### User Context
用户要求播报增加：20分钟前、30分钟前、60分钟前的变化幅度。当前只有今天0点和10分钟前。

### Complexity Estimate
simple

### Suggested Implementation
修改 /script/gold_price/gold_price_daemon.py 中的 calculate_changes 函数，增加 20min、30min、60min 的计算

### Metadata
- Frequency: recurring
- Related Features: gold_price_monitor

