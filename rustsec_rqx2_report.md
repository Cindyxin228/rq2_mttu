# RustSec 修复滞后与补丁传播：结果文件与指标说明

本报告汇总本仓库的批处理工具在一次运行中产生的主要输出文件、字段含义、以及图表路径，便于直接复制到外部报告中引用。

## 一键运行（明细 + 汇总 + 传播 + 断裂率 + 所有图）

在项目根目录执行：

```bash
export PG_POOL_MAX=50

cargo run --release --bin rqx2_rustsec_batch -- \
  --output rustsec_rqx2_strict_lags.csv \
  --summary-output rustsec_rqx2_strict_summary.csv \
  --log-output rustsec_rqx2_run.log \
  --downstream-cache-crates 500 \
  --propagation \
  --propagation-summary-output rustsec_rqx2_propagation_summary.txt \
  --propagation-output-dir rustsec_rqx2_propagation_svgs \
  --constraint \
  --constraint-breakdown-output rustsec_rqx2_constraint_breakdown.csv \
  --constraint-summary-output rustsec_rqx2_constraint_summary.txt \
  --constraint-output-dir rustsec_rqx2_constraint_svgs \
&& python3 plot_lag_distribution.py \
  --by-severity \
  --output-dir lag_days_by_severity_svgs
```

## strict lag（下游显式修复滞后）

### 明细 CSV

- 路径：`./rustsec_rqx2_strict_lags.csv`
- 每行含义：固定一个 RustSec 公告与一个下游 crate，记录该下游第一次满足“严格修复事件”的发布时间与滞后天数。
- 字段：`rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_crate,downstream_version,downstream_time,lag_days,original_req,fixed_req`
  - `fixed_version,fix_time`：匹配到的上游修复版本与其发布时间（可能是 patched 的某个分支修复版本，不一定是最小版本）。
  - `downstream_version,downstream_time`：下游 crate 触发严格修复事件的版本号与发布时间。
  - `lag_days`：`(downstream_time - fix_time).num_days()`，按天取整。
  - `original_req`：下游在“曾经受影响”时使用的依赖约束（最后一次允许漏洞版本的 `dep_req`）。
  - `fixed_req`：下游在“首次修复”时使用的依赖约束（触发修复事件的 `dep_req`）。

### 汇总 CSV

- 路径：`./rustsec_rqx2_strict_summary.csv`
- 每行含义：按 RustSec 公告汇总该公告下所有 strict lag 事件的分布统计。
- 字段：`rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_fixed_cnt,lag_days_min,lag_days_p50,lag_days_avg,lag_days_max`
  - `fixed_version,fix_time`：用于汇总口径的修复起点（取可用修复时间的最早值）。
  - `downstream_fixed_cnt`：该公告下产生 strict lag 事件的下游数量。
  - `p50`：中位数（第 50 百分位）。

### lag_days 分布图（Python）

- 目录：`./lag_days_by_severity_svgs/`
- 图表：
  - `lag_days_hist_LOW.svg`
  - `lag_days_hist_MEDIUM.svg`
  - `lag_days_hist_HIGH.svg`
  - `lag_days_hist_CRITICAL.svg`
  - `lag_days_hist_INFO.svg`
  - `lag_days_hist_UNKNOWN.svg`

## 补丁传播（无限 BFS，逐层 hop 统计）

### 统计报告（txt）

- 路径：`./rustsec_rqx2_propagation_summary.txt`
- 含义：把 hop=1 的修复事件作为种子载体，继续向下游做时间尊重的传播 BFS，分别对 hop=1..K 的 `lag_days` 做 `count/min/p50/avg/max` 统计，同时给出 “all hops” 的合并统计。

### 传播直方图（SVG）

- 目录：`./rustsec_rqx2_propagation_svgs/`
- 图表：
  - `propagation_lag_hist_all.svg`：合并所有 hop 的分布
  - `propagation_lag_hist_hop_<K>.svg`：每一层 hop 的分布

## 链条断裂率（依赖约束导致补丁无法下传）

### 定义

- 边（edge）：在某个公告的修复时间点 `fix_time`，对每个下游 crate 取其在 `fix_time` 之前最近一次发布版本的 `dep_req` 作为该 crate 的“当前依赖约束”。
- 受影响边（affected edge）：该 `dep_req` 允许至少一个已知受影响版本（由 patched/unaffected 推导得到的 vuln 版本集合）。
- 断裂边（locked-out edge）：该 `dep_req` 不允许任何已发布的修复版本（patched 提取到且可解析的修复版本集合），因此不修改约束无法通过解析到达修复。
- 链条断裂率（break_rate_percent）：`locked_out_edges / affected_edges * 100`（整数百分比）。

### 汇总（txt）

- 路径：`./rustsec_rqx2_constraint_summary.txt`
- 含义：全量的 `affected_edges / locked_out_edges / break_rate_percent`，以及受影响边的 `dep_req` 形态分布。

### 逐公告明细（CSV）

- 路径：`./rustsec_rqx2_constraint_breakdown.csv`
- 字段：`rustsec_id,cve_id,severity,target_crate,fix_time,downstream_crates_with_history,affected_edges,locked_out_edges,break_rate_percent,affected_req_exact_pin,affected_req_has_upper_bound,affected_req_caret_0x,affected_req_other,unknown_req_unparseable`
  - `unknown_req_unparseable`：下游在 `fix_time` 前的最新 `dep_req` 无法被 semver 解析，无法纳入受影响/断裂判定。

### 图表（SVG）

- 目录：`./rustsec_rqx2_constraint_svgs/`
- 图表：
  - `constraint_break_rate_hist_advisory.svg`：逐公告断裂率百分比的分布直方图
  - `constraint_req_shape_bar.svg`：受影响边的 `dep_req` 形态柱状图（`=...`、含 `<`、`^0.`、其它）

## 运行日志

- 路径：`./rustsec_rqx2_run.log`
- 含义：进度、跳过原因、修复时间回退命中情况、传播回退等。

