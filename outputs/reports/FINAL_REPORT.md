# 最终分析报告

## 1. 严格滞后分析（直接依赖）
- **数据源**：`outputs/strict/rustsec_rqx2_strict_lags.csv`（已生成）
- **可视化**：在 `outputs/figures/lag_days_by_severity_svgs` 中找到 6 张按严重度分组的直方图

## 2. 传播分析（传递依赖影响）
### 关键指标
```text
patch propagation analysis (hops=1..16)

all hops
  count = 1128888
  min   = 0 days
  p50   = 3.0000 days
  avg   = 94.7922 days
  max   = 3181 days

hop 1
  count = 31781
  min   = 0 days
  p50   = 291.0000 days
  avg   = 503.3711 days
  max   = 3181 days

hop 2
  count = 108418
  min   = 0 days
  p50   = 46.0000 days
  avg   = 161.4597 days
  max   = 2361 days

hop 3
  count = 179461
  min   = 0 days
  p50   = 10.0000 days
  avg   = 114.5750 days
  max   = 2284 days

hop 4
  count = 195250
  min   = 0 days
  p50   = 5.0000 days
  avg   = 91.5689 days
  max   = 2231 days

hop 5
  count = 205310
  min   = 0 days
  p50   = 1.0000 days
  avg   = 70.0881 days
  max   = 2073 days

hop 6
  count = 166017
  min   = 0 days
  p50   = 0.0000 days
  avg   = 56.7422 days
  max   = 2059 days

hop 7
  count = 114918
  min   = 0 days
  p50   = 0.0000 days
  avg   = 49.7848 days
  max   = 1787 days

hop 8
  count = 74276
  min   = 0 days
  p50   = 0.0000 days
  avg   = 49.4481 days
  max   = 1904 days

hop 9
  count = 32038
  min   = 0 days
  p50   = 0.0000 days
  avg   = 38.0982 days
  max   = 1797 days

hop 10
  count = 12317
  min   = 0 days
  p50   = 0.0000 days
  avg   = 32.3106 days
  max   = 1508 days

hop 11
  count = 5083
  min   = 0 days
  p50   = 0.0000 days
  avg   = 26.6911 days
  max   = 1570 days

hop 12
  count = 2509
  min   = 0 days
  p50   = 1.0000 days
  avg   = 31.0678 days
  max   = 699 days

hop 13
  count = 1221
  min   = 0 days
  p50   = 0.0000 days
  avg   = 22.6593 days
  max   = 741 days

hop 14
  count = 235
  min   = 0 days
  p50   = 0.0000 days
  avg   = 9.8128 days
  max   = 256 days

hop 15
  count = 37
  min   = 0 days
  p50   = 0.0000 days
  avg   = 9.4595 days
  max   = 186 days

hop 16
  count = 17
  min   = 0 days
  p50   = 0.0000 days
  avg   = 0.0000 days
  max   = 0 days
```
- **可视化**：在 `outputs/propagation/rustsec_rqx2_propagation_svgs` 中找到 17 张传播滞后直方图
  - **说明**：这些图的纵轴使用 **log10 对数刻度**，用于更清晰地展示长尾分布（按您的要求）。

## 3. 约束分析（阻断）
### 关键指标
```text
constraint break analysis (edge=downstream crate at fix_time)

totals
  downstream_crates_with_history = 128501
  affected_edges                = 113224
  locked_out_edges              = 24217
  break_rate_percent            = 21
  unknown_req_unparseable       = 0

affected edges dep_req shape (at fix_time)
  exact-pin (=...)              = 656
  has upper bound (< or <=)     = 488
  caret 0.x (^0.)               = 62010
  other                         = 50070
```
- **可视化**：在 `outputs/constraint/rustsec_rqx2_constraint_svgs` 中找到 2 张约束相关图

## 4. 文件清单
| 文件/目录 | 说明 | 状态 |
|---|---|---|
| `outputs/strict/rustsec_rqx2_strict_lags.csv` | 直接依赖滞后（原始明细数据） | ✅ 已生成 |
| `outputs/propagation/rustsec_rqx2_propagation_summary.txt` | 传播分析各 hop 的统计摘要 | ✅ 已生成 |
| `outputs/constraint/rustsec_rqx2_constraint_summary.txt` | 约束阻断统计摘要 | ✅ 已生成 |
| `outputs/propagation/rustsec_rqx2_propagation_svgs/` | 传播滞后直方图（对数纵轴） | ✅ 已生成 |
| `outputs/constraint/rustsec_rqx2_constraint_svgs/` | 约束类型与阻断率可视化 | ✅ 已生成 |
| `outputs/figures/lag_days_by_severity_svgs/` | 严重度分组的严格滞后直方图 | ✅ 已生成 |
| `outputs/propagation/propagation_events_raw.csv` | 传播事件采样明细（用于抽样校验/复现） | ✅ 已生成 |

根据生成的报告数据，为您总结以下核心发现：

1. 直接依赖是更新瓶颈 (Propagation Lag) :
   
   - Hop 1 (直接依赖) 的平均滞后时间高达 503 天 (中位数 291 天)。
   - Hop 2 (间接依赖) 的平均滞后时间迅速降至 161 天 (中位数 46 天)。
   - 结论 : 这表明 Rust 生态系统中，直接依赖的更新往往最慢（可能需要手动干预），而间接依赖通常能通过工具链更及时地更新。
2. 阻断率分析 (Constraint Analysis) :
   
   - 在受影响的依赖关系中，有 21% (24,217 / 113,224) 被版本约束直接"锁死" (Locked out)，导致无法修复。
   - 最主要的约束形式是 ^0. (Caret requirements)，这是造成阻断的主要原因。
3. 长尾分布 :
   
   - 数据呈现极端的长尾分布（Max lag 达 3181 天，而大量数据集中在低值区），这也验证了您要求使用对数刻度 (Log Scale) 的必要性，否则极值会掩盖整体分布特征。
