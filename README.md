# time-to-fix-cve

用 crates.io 的 PostgreSQL 数据与 RustSec 公告，统计安全修复向下游 crate 传播的“严格修复滞后（strict lag）”，并导出 CSV 便于进一步分析。

## 前置条件

### 1) crates.io PostgreSQL 数据库

程序会直接查询 crates.io 的关系型数据（至少需要 `crates / versions / dependencies` 等表）。仓库里提供了一个导入脚本 [import.sql](file:///home/test/rust_project_backup/import.sql)（假设你已经准备好了 `data/*.csv` 的 crates.io dump）。

### 2) 环境变量

程序通过环境变量连接 PostgreSQL（也支持在当前目录用 `.env` 文件注入环境变量）：

- `PG_HOST`（默认 `localhost:5432`）
- `PG_USER`（默认 `postgres`）
- `PG_PASSWORD`（默认空）
- `PG_DATABASE`（默认 `crates_io`）
- 可选：`PG_POOL_MAX`（默认 10）、`PG_POOL_TIMEOUT_MS`（默认 3000）

示例：

```bash
export PG_HOST=localhost:5432
export PG_USER=postgres
export PG_PASSWORD=your_password
export PG_DATABASE=crates_io
```

## 安装/构建

```bash
cargo build --release
```

## 使用方法

本仓库的主要入口是两个二进制程序（`src/main.rs` 目前只是占位输出）。

### 快速开始（最常用命令）

全量分析命令（推荐，输出 strict lag CSV + 逐层传播报告 + 所有图）：

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
&& python3 plot_lag_distribution.py \
  --by-severity \
  --output-dir lag_days_by_severity_svgs
```

试跑命令（只跑前 N 条公告，用于检查环境/输出是否正常）：

```bash
cargo run --release --bin rqx2_rustsec_batch -- \
  --max-advisories 10 \
  --propagation \
  --log-output rustsec_rqx2_run.log
```

### 1) 单个漏洞：`rqx2_strict`

查看帮助：

```bash
cargo run --bin rqx2_strict -- --help
```

参数：

- `--cve-id <CVE_ID>`
- `--target-crate <TARGET_CRATE>`
- `--fixed-version <FIXED_VERSION>`
- `--vuln-version-sample <VULN_VERSION_SAMPLE>`

运行示例：

```bash
cargo run --release --bin rqx2_strict -- \
  --cve-id CVE-2022-24713 \
  --target-crate regex \
  --fixed-version 1.5.5 \
  --vuln-version-sample 1.5.4
```

输出：

- 生成 `rqx2_strict_lag_<cve_id>.csv`（例如 `rqx2_strict_lag_CVE-2022-24713.csv`）
- CSV 字段：
  - `crate`：下游 crate 名
  - `fix_version / fix_time`：上游修复版本及其发布时间
  - `lag_days`：下游首次“严格修复发布”距离 `fix_time` 的天数
  - `original_req`：下游最后一次仍允许漏洞样本版本的依赖约束（如 `^1.5.4`）
  - `fixed_req`：下游第一次允许修复版本且不再允许漏洞样本版本的依赖约束

`--vuln-version-sample` 的选择建议：给一个“确实属于漏洞范围内”的版本号（程序用它判断某个依赖约束是否仍允许漏洞版本线）。

### 2) RustSec 批处理：`rqx2_rustsec_batch`

该程序会从 GitHub 下载 RustSec advisory-db（zip），解析所有 crates advisory，并批量计算 strict lag。

查看帮助：

```bash
cargo run --bin rqx2_rustsec_batch -- --help
```

常用参数：

- `--output <OUTPUT>`：明细 CSV 输出路径（默认 `rustsec_rqx2_strict_lags.csv`）
- `--summary-output <SUMMARY_OUTPUT>`：汇总 CSV 输出路径（默认 `rustsec_rqx2_strict_summary.csv`）
- `--only <ID1,ID2,...>`：仅处理指定的 CVE 或 RustSec ID（逗号分隔）
- `--propagation`：启用补丁传导阻力分析（无限 BFS 到叶子为止）
- `--propagation-summary-output <PATH>`：传播统计 txt 输出路径（默认 `rustsec_rqx2_propagation_summary.txt`）
- `--propagation-output-dir <DIR>`：传播统计 SVG 输出目录（默认 `rustsec_rqx2_propagation_svgs`）
- `--propagation-events-output <PATH>`：传播事件明细 CSV（用于校验/抽样复现路径，可选）
- `--propagation-events-limit <N>`：传播事件明细最多写入 N 行（0 表示不限）
- `--propagation-max-hops <N>`：限制 BFS 的最大 hop（默认不限制）
- `--propagation-bins <N>`：传播直方图 bins（默认 60）
- `--constraint`：启用“依赖约束导致补丁无法下传”的断裂率分析
- `--constraint-breakdown-output <PATH>`：断裂率逐公告明细 CSV（默认 `rustsec_rqx2_constraint_breakdown.csv`）
- `--constraint-summary-output <PATH>`：断裂率汇总 txt（默认 `rustsec_rqx2_constraint_summary.txt`）
- `--constraint-output-dir <DIR>`：断裂率相关 SVG 输出目录（默认 `rustsec_rqx2_constraint_svgs`）
- `--constraint-bins <N>`：断裂率直方图 bins（默认 40）
- `--constraint-min-age-days <N>`：仅统计修复起点时间距今至少 N 天的公告（默认 0，不过滤）
- `--downstream-cache-crates <N>`：下游依赖查询缓存的 crate 数量（默认 50）
- `--max-advisories <N>`：仅处理前 N 条公告（试跑用）
- `--log-output <PATH>`：将运行进度/跳过原因/传播回退等日志写入文件（同时仍会输出到终端）

传播回退口径（仅影响 `--propagation`）：

- 如果公告里解析不出可用的修复版本（patched 信息缺失或无法提取出具体版本），会记录一条 `propagation fallback: ...` 日志，并用“该 crate 的最新版本发布时间”作为传播的起点版本/时间继续做向下游传播分析。
- 如果 patched/unaffected 都为空，则视为“该 crate 所有版本都受影响”（用于漏洞版本集合判定）。
  - 注意：strict lag 仍需要可用的 `fixed_version + fix_time` 才能计算；没有的话该公告不会产出 strict lag 行，但传播分析仍可继续进行。

包名归一化（避免查库查不到版本）：

- 少数 RustSec 公告里的 `package` 名称可能与 crates.io 名称不一致（例如 `rustdecimal` 实际是 `rust_decimal`）。程序会做一层别名映射，并在日志里输出 `package alias: rustsec_pkg=... db_pkg=...` 便于核对。

修复时间获取策略（fix_time）：

- strict lag 的 `fix_time` 优先来自 crates.io dump（PostgreSQL 的 versions.created_at）。
- 如果 RustSec 给出的修复版本号在 dump 里查不到时间，会按下面顺序回退：
  1. dump 内等价版本匹配（忽略 build metadata）：例如 dump 里可能有 `300.0.10+openssl-src.300.0.10`，而 RustSec 写的是 `300.0.10`。在语义化版本（SemVer）里，`+...` 属于 build metadata，**不参与版本大小比较**，因此它们语义上是同一个版本号；程序会在该 crate 的所有版本字符串里找出 major/minor/patch/pre 完全一致的“真实版本字符串”，再用它去查时间。
  2. patched 约束下选取“最早已发布”的修复版本：如果 RustSec 提到的那个修复版本号本身并未发布到 crates.io（例如 API 404），就从 dump 里的已发布版本中，找出第一个满足 patched 约束的版本（它一定存在于 dump），并用它的 created_at 作为 `fix_time`。
  3. crates.io API 回退：若 dump 仍查不到，则请求 `https://crates.io/api/v1/crates/<crate>/<version>`，用返回的 `created_at` 作为该版本发布时间（会在最终汇总打印 `crates.io version-time fallback: hits=... misses=...`）。

#### 一键生成完整结果（明细 + 汇总 + 逐层传播报告 + 所有图）

下面这一条命令会在一次运行中产出：

- strict lag 明细/汇总（CSV）
- 补丁传播逐层统计报告（txt）
- 补丁传播逐层直方图（SVG）
- strict lag 的按 severity 分组直方图（SVG，python 脚本）

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

#### 输出文件总览（路径 / 内容）

该项目会输出多类文件，默认都写在当前工作目录；大部分路径都可通过参数覆盖（见 `--help`）。

批处理主程序 `rqx2_rustsec_batch`：

- strict lag 明细 CSV：`./rustsec_rqx2_strict_lags.csv`（可用 `--output` 改名）
  - 每行是一条“严格修复事件”（某公告 × 某下游 crate），字段见下文明细解释
- strict lag 汇总 CSV：`./rustsec_rqx2_strict_summary.csv`（可用 `--summary-output` 改名）
  - 按公告汇总 strict lag 的 `count/min/p50/avg/max`
- 运行日志（可选）：`./rustsec_rqx2_run.log`（用 `--log-output` 开启）
  - 包含进度、跳过原因、修复时间回退、传播回退等信息

传播分析（需要 `--propagation`）：

- 传播统计 txt：`./rustsec_rqx2_propagation_summary.txt`（可用 `--propagation-summary-output` 改名）
  - 对 hop=1..K 以及 all hops 的 `lag_days` 统计（count/min/p50/avg/max）
- 传播直方图目录：`./rustsec_rqx2_propagation_svgs/`（可用 `--propagation-output-dir` 改目录）
  - `propagation_lag_hist_all.svg`：所有 hop 合并后的分布图
  - `propagation_lag_hist_hop_<K>.svg`：每一层 hop 的分布图
- 传播事件明细 CSV（可选）：由 `--propagation-events-output <PATH>` 指定
  - 记录传播边的采样明细（用于抽样校验/复现）

链条断裂率（需要 `--constraint`）：

- 断裂率逐公告明细 CSV：`./rustsec_rqx2_constraint_breakdown.csv`（可用 `--constraint-breakdown-output` 改名）
  - 每条公告一行：受影响边数量、断裂边数量、断裂率百分比、以及 `dep_req` 形态计数
- 断裂率汇总 txt：`./rustsec_rqx2_constraint_summary.txt`（可用 `--constraint-summary-output` 改名）
  - 全量汇总（affected_edges / locked_out_edges / break_rate_percent）及形态分布
- 断裂率图表目录：`./rustsec_rqx2_constraint_svgs/`（可用 `--constraint-output-dir` 改目录）
  - `constraint_break_rate_hist_advisory.svg`：逐公告断裂率分布直方图
  - `constraint_req_shape_bar.svg`：受影响边的 `dep_req` 形态柱状图

Python 辅助脚本：

- strict lag 直方图（单图）：默认 `./lag_days_hist.svg`（`python3 plot_lag_distribution.py --output ...`）
- strict lag 直方图（按 severity 分组）：输出到 `--output-dir` 指定目录（例如 `./lag_days_by_severity_svgs/`）
- strict summary 表格（Markdown）：`python3 render_summary_table.py --output <PATH>`（默认输出到 stdout）

试跑版（只跑前 N 条公告）：

```bash
cargo run --release --bin rqx2_rustsec_batch -- \
  --max-advisories 10 \
  --propagation \
  --log-output rustsec_rqx2_run.log
```

#### 运行完整分析

执行以下命令运行全量 RustSec 公告分析：

```bash
cargo run --release --bin rqx2_rustsec_batch
```

该命令会：
1.  下载最新的 RustSec Advisory Database。
2.  连接本地 PostgreSQL 数据库（通过 `PG_HOST/PG_USER/PG_PASSWORD/PG_DATABASE` 等环境变量配置）。
3.  对所有公告进行全量版本判定与 strict lag 计算。
4.  输出结果到 `rustsec_rqx2_strict_lags.csv`（明细）和 `rustsec_rqx2_strict_summary.csv`（汇总）。

注意：该命令默认不启用 `--propagation`，也不会生成传播 SVG 或按 severity 的图；如果你想要“全量 + 传播 + 图”，用上面的“快速开始（最常用命令）”即可。

输出：

- 明细 `rustsec_rqx2_strict_lags.csv` 字段：
  - `rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_crate,downstream_version,downstream_time,lag_days,original_req,fixed_req`
- 汇总 `rustsec_rqx2_strict_summary.csv` 字段：
  - `rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_fixed_cnt,lag_days_min,lag_days_p50,lag_days_avg,lag_days_max`

#### 指标解释（lag_days / p50 / 为什么会出现 0）

- `lag_days`：用 crates.io 的 `created_at` 做时间戳，按天取整：`(downstream_time - fix_time).num_days()`。
- `p50`：第 50 百分位数，也就是中位数。含义是：至少 50% 的样本 `lag_days <= p50`，且至少 50% 的样本 `lag_days >= p50`。
- `p50 = 0.0000 days`：表示至少一半事件的滞后小于 24 小时（按天取整后为 0），并不代表“没有修复/没有传播”。
- 负数 `lag_days`：属于“时间穿越”的无效事件（下游发布时间早于匹配到的上游修复发布时间）。程序会在 strict lag 计算阶段过滤这类记录并输出告警计数，避免污染统计。

#### 按漏洞等级（severity）看 lag_days，并输出 SVG

思路：

1.  RustSec Advisory 的 TOML front matter 中包含 `advisory.severity`（如 `LOW / MEDIUM / HIGH / CRITICAL / INFO`）。
2.  批处理程序解析该字段，并把标准化后的 `severity` 写入明细与汇总 CSV。
3.  若公告未显式给出 `advisory.severity`，则尝试从 `advisory.cvss`（CVSS v3.0/3.1 向量）计算 base score 并映射为 `LOW/MEDIUM/HIGH/CRITICAL`；若为信息型公告（存在 `advisory.informational`）则记为 `INFO`；否则为 `UNKNOWN`。
4.  画图时按 `severity` 对明细 CSV 的 `lag_days` 分组，每一组单独画一张直方图（SVG）。

运行时进度输出：

- 程序会每隔约 5 秒在终端输出一行 `progress: ...`；在进行传播 BFS 时也会输出 `propagation: ...`（包含队列长度与已扩散事件数），用于判断是否仍在运行。

命令约定（建议显式指定输出名，避免覆盖/混淆）：

- 总图（不分组，不过滤）：输出单个 SVG

```bash
python3 plot_lag_distribution.py \
  --output lag_days_hist_all.svg
```

- 总图（带过滤）：输出单个 SVG（文件名建议包含 filter 标识）

```bash
python3 plot_lag_distribution.py \
  --filter 'CVE-2022-24713|RUSTSEC-2022' \
  --output lag_days_hist_filter_cve2022.svg
```

- 分组图（按 severity，不过滤）：输出一个目录（每个等级一张图）

```bash
python3 plot_lag_distribution.py \
  --by-severity \
  --output-dir lag_days_by_severity_svgs_all
```

- 分组图（按 severity + 过滤）：输出一个目录（目录名建议包含 filter 标识）

```bash
python3 plot_lag_distribution.py \
  --by-severity \
  --filter 'CVE-2022-24713|RUSTSEC-2022' \
  --output-dir lag_days_by_severity_svgs_filter_cve2022
```

`--filter` 说明：这是一个正则表达式，会匹配明细 CSV 行中的 `rustsec_id / cve_id / severity / target_crate / downstream_crate` 任意字段，匹配到的行才参与统计与画图。

生成每个等级对应的分布图：

```bash
python3 plot_lag_distribution.py --by-severity --output-dir lag_days_by_severity_svgs
```

注意：当使用 `--by-severity` 时，脚本会先清空 `output-dir` 中已有的 `lag_days_hist_*.svg`，再重新生成，避免多次运行导致旧图混入。

输出目录示例：

- `lag_days_by_severity_svgs/lag_days_hist_LOW.svg`
- `lag_days_by_severity_svgs/lag_days_hist_MEDIUM.svg`
- `lag_days_by_severity_svgs/lag_days_hist_HIGH.svg`
- `lag_days_by_severity_svgs/lag_days_hist_CRITICAL.svg`
- `lag_days_by_severity_svgs/lag_days_hist_INFO.svg`
- `lag_days_by_severity_svgs/lag_days_hist_UNKNOWN.svg`（公告未提供或无法识别 severity 时）

#### 补丁传导阻力（无限 BFS，输出统计 + 图）

目标：衡量补丁从上游往下游“每多走一层”平均会额外耗时多少天。

定义（按 hop 分层）：

- hop=1：漏洞上游 crate（A）发布修复版本后，直接依赖它的下游 crate（B）首次发布严格修复版本的延迟（也就是明细 CSV 的 `lag_days`）。
- hop=2：把 hop=1 中 B 的“修复版本”当作补丁载体；统计依赖 B 的下游 crate（C）发生一次“显式修复事件”的延迟：在载体修复时间之前曾经过敏（依赖最小允许版本低于载体修复版本），并在之后首次把依赖最小允许版本抬到不低于载体修复版本（等价于排毒 + 引入）。
- hop=3、hop=4 ...：同理继续向下传播。

逐层 lag_days 的计算思路（时间尊重的事件链）：

1.  先为每个 RustSec 公告生成 hop=1 的“严格修复事件”集合（这一步和 strict lag 明细 CSV 是同一批事件）。
2.  将 hop=1 事件中的每个下游 crate（B）视为一个补丁载体：它携带 `(fix_version, fix_time)`，表示“B 在 fix_time 发布了一个版本 fix_version，被当作补丁向下游传播”。
3.  对每个补丁载体 crate，查询它的所有下游依赖 crate 的依赖历史（按 `created_at` 排序），在每个下游 crate（C）内部寻找一次“显式修复事件”，并把该事件的 `lag_days` 记为本 hop 的一条样本。
4.  对 hop=2 产生的新载体继续做 BFS 扩展到 hop=3、hop=4...，直到队列耗尽（或 `--propagation-max-hops` 限制生效）。

事件判定（hop>=2 的“显式修复事件”）：

- 依赖关系的观察对象是 crates.io dump 中的 `dep_req`（版本约束字符串），并以 `created_at` 作为时间戳。
- 对 `dep_req` 抽取“最小允许版本” `min_allowed(dep_req)`（近似下界），用于表达“是否发生了把下界抬过修复点”的显式升级。
- 对于给定载体 `(fix_version, fix_time)`，在某个下游 crate（C）的发布序列里：
  - **状态 A（Ever Affected）**：在 `fix_time` 之前，存在最后一个版本的 `min_allowed(dep_req) < fix_version`，表示该下游在修复点之前仍允许落在修复点之前的版本段里。
  - **状态 B（Explicit Fix）**：在 `fix_time` 之后，找到第一个版本使得 `min_allowed(dep_req) >= fix_version`，表示该下游显式把依赖下界抬到修复点及之后。
- 若能找到状态 B，则该下游的传播 `lag_days = (状态B版本的 created_at - fix_time).num_days()`，并把它作为一条 AdoptionEvent 计入当前 hop。

BFS 的“去重/避免环路”口径：

- BFS 过程中对每个 crate 维护 best_seen：只保留“更小 hop”或“同 hop 更早 fix_time”的到达状态；只有在到达状态严格变好时才会再次入队扩展。
- 因此这里的 hop 最大值代表“在该去重口径下观测到的最深事件链层数”，不会枚举同一 crate 的所有不同路径组合。

统计输出口径说明：

- `rustsec_rqx2_propagation_summary.txt` 第一行的 `hops=1..K`：K 是本次运行处理到的所有公告中，实际产生过事件的最大 hop。
- `min/p50/avg/max` 统计的是每个 hop 内所有事件的 `lag_days` 分布；`p50` 为中位数。
- `p50 = 0.0000 days` 表示至少一半事件的滞后小于 24 小时（按天取整后为 0），不等于“未修复”。

与“静态依赖图深度”的关系：

- 本分析的 hop 是基于“修复/采用事件”的时间尊重传播链；静态反向依赖图的 BFS 深度是“存在依赖边”的最短路深度。
- 静态图通常是跨时间的边集合并集，可能包含“时间穿越的捷径”，因此两者的最大深度不要求相等。

运行命令（一次输出 CSV + 传播统计 txt + 传播直方图 SVG）：

```bash
cargo run --release --bin rqx2_rustsec_batch -- \
  --propagation \
  --propagation-summary-output rustsec_rqx2_propagation_summary.txt \
  --propagation-output-dir rustsec_rqx2_propagation_svgs
```

输出文件：

- `rustsec_rqx2_propagation_summary.txt`：按 hop 与全量 all hops 的统计（count / min / p50 / avg / max）。
- `rustsec_rqx2_propagation_svgs/propagation_lag_hist_all.svg`：所有 hop 合并后的 `lag_days` 分布图。
- `rustsec_rqx2_propagation_svgs/propagation_lag_hist_hop_<K>.svg`：每一层 hop 的 `lag_days` 分布图。

#### 链条断裂率（依赖约束导致补丁无法下传）

目标：评估“版本锁定/依赖约束政策”对安全补丁传播的结构性阻碍。

什么时候需要看依赖约束：

- 对于某个 RustSec 公告的上游 crate，在修复时间点 `fix_time`，如果某个下游 crate 的依赖约束 `dep_req` 允许受影响版本，但不允许任何已发布的修复版本，则该下游在不改约束的前提下无法通过解析到达修复版本，属于“链条断裂”。

统计口径（对 `DownstreamVersionInfo.dep_req` 的形态做归类）：

- `=...`：精确锁死（exact pin）
- 含 `<` 或 `<=`：显式上界（upper bound）
- `^0.`：0.x 隐性锁定风险较高（caret 0.x）
- 其它：不属于以上三类

运行命令（在跑 strict lag / propagation 时顺带输出断裂率统计与图）：

```bash
cargo run --release --bin rqx2_rustsec_batch -- \
  --constraint \
  --constraint-min-age-days 30 \
  --constraint-summary-output rustsec_rqx2_constraint_summary.txt \
  --constraint-breakdown-output rustsec_rqx2_constraint_breakdown.csv \
  --constraint-output-dir rustsec_rqx2_constraint_svgs
```

输出文件：

- `rustsec_rqx2_constraint_summary.txt`：全量汇总（affected_edges / locked_out_edges / break_rate_percent）以及受影响边的依赖约束形态分布。
- `rustsec_rqx2_constraint_breakdown.csv`：逐公告明细（每条公告的 affected_edges、locked_out_edges、break_rate_percent 与形态计数）。
- `rustsec_rqx2_constraint_svgs/constraint_break_rate_hist_advisory.svg`：逐公告断裂率（百分比）的分布直方图。
- `rustsec_rqx2_constraint_svgs/constraint_req_shape_bar.svg`：受影响边的依赖约束形态柱状图。

口径解释（`fix_time` / “最近一次版本” / 指标含义）：

- `fix_time`：该公告的“修复已出现”的时间戳，来自 crates.io 的版本发布时间 `created_at`。一个公告可能在多个版本线上都有修复版本（例如同时修了 `0.3.9` 与 `0.4.2`），因此会得到多个修复版本发布时间。断裂率分析需要选定一个时间截面作为快照，这里取“最早出现的修复发布时间”作为 `fix_time`，含义是：从这个时刻开始，生态里已经存在至少一个可用修复版本。注意这里度量的是“约束是否允许解析到修复”（结构性可达性），不等价于“下游是否已经完成修复发布”。如果你担心“修复刚发布一两天，生态还来不及行动”带来解释困难，可以用 `--constraint-min-age-days` 过滤掉过新的公告（例如 30 天）。
- “修复时点快照”：对每个（公告，target_crate）的统计，都会把时间固定在该公告的 `fix_time`，只看“当时下游生态的依赖约束长什么样”。
- “最近一次版本”：对每个下游 crate，把它所有发布版本按 `created_at` 排序，取 `created_at < fix_time` 的最后一个版本；该版本对应的 `dep_req` 就是该下游在修复时点的“当前依赖约束”。如果某下游在 `fix_time` 之前还没有发布过任何版本，则该下游不会参与该公告的断裂率统计。
- edge：这里的一条 edge 表示“在 `fix_time` 修复时点，一个下游 crate 对上游 target_crate 的一条依赖约束快照”。
- `affected_edges`：在这些 edge 中，`dep_req` 允许至少一个已知受影响版本（vuln_versions）的 edge 数量。vuln_versions 是用该 crate 的历史版本集合结合 RustSec 的 patched/unaffected 推导得到的“受影响版本集合”。
- `locked_out_edges`：在 `affected_edges` 中，`dep_req` 不允许任何已发布的修复版本（patched 提取到且能查到发布时间的修复版本集合）的 edge 数量；这表示“不修改约束，仅靠解析/更新无法到达修复版本”，属于链条断裂。
- `break_rate_percent`：`locked_out_edges / affected_edges * 100`（整数百分比）。
- `unknown_req_unparseable`：修复时点的 `dep_req` 无法被 semver 解析的 edge 数量；这类 edge 无法判断是否受影响/是否断裂。
- `affected edges dep_req shape`：只在 `affected_edges` 里，对修复时点的 `dep_req` 做简单形态分桶计数：
  - `=...`：精确锁死
  - 含 `<` 或 `<=`：显式上界
  - `^0.`：0.x caret 约束
  - 其它：不属于以上三类

注意：

- `constraint_summary.txt` 的 totals 是跨所有公告累加的计数，同一个下游 crate 在不同公告里会重复出现；如果需要按公告解读断裂率，用 `rustsec_rqx2_constraint_breakdown.csv` 更直观。

运行时进度输出：

- 程序会每隔约 5 秒在终端输出一行 `progress: ...`；在进行传播 BFS 时也会输出 `propagation: ...`（包含队列长度与已扩散事件数），用于判断是否仍在运行。

性能建议（不减少计算内容）：

- 增大数据库连接池：通过环境变量 `PG_POOL_MAX`（例如 30 或 50）。
- 增大下游缓存：通过参数 `--downstream-cache-crates`（例如 200 或 500），可以显著减少重复查询。

示例：

```bash
export PG_POOL_MAX=50

cargo run --release --bin rqx2_rustsec_batch -- \
  --downstream-cache-crates 500 \
  --propagation \
  --propagation-summary-output rustsec_rqx2_propagation_summary.txt \
  --propagation-output-dir rustsec_rqx2_propagation_svgs
```

## 核心实现逻辑与流程

该工具的核心逻辑是建立在**“状态机回放”**和**“严格版本匹配”**基础上的，旨在测量“显式修复”行为。整个流程分为三个阶段：

### 1. 定标（确定“药”和“毒”）

工具首先解析 RustSec 数据库中的公告信息，确定判断标准：

1.  **解析公告**：从 RustSec 数据库下载并解析 Advisory。
2.  **确定“特效药”（Fixed Versions）**：
    *   读取 `patched` 字段的所有版本（例如 `["1.2.3", "2.0.1"]`）。
    *   将这些版本全部纳入“特效药”清单。
3.  **确定“受影响范围”（Vulnerable Versions）**：
    *   查询该 crate 的所有历史版本。
    *   利用 Advisory 中的 `patched`（已修复）和 `unaffected`（不受影响）字段，排除所有安全版本。
    *   剩余的所有版本都被标记为“有毒版本集合”。

### 2. 追溯（找到“密切接触者”）

利用 PostgreSQL 数据库的高效索引，快速锁定下游：

1.  **反向查询**：利用 `dependencies` 表的索引，瞬间找到所有依赖该库的下游 crate。
2.  **构建时间轴**：把每个下游 crate 的所有发布版本按 `created_at` 时间排序，形成一条“历史轨迹”。

### 3. 判定（诊断“康复”过程）

遍历下游的历史轨迹，维护一个状态机，诊断是否发生了“显式修复”。我们采用**集合论**逻辑进行严格判定：

*   **状态 A (Ever Affected)**：如果依赖约束 $Req$ 与有毒版本集合 $Vuln$ 存在**交集**（$Req \cap Vuln \neq \emptyset$），标记为“曾经过敏”。
*   **状态 B (Explicit Fix)**：如果满足以下条件，则判定为修复：
    1.  曾经处于状态 A。
    2.  **排毒**：当前依赖约束完全排除所有有毒版本（$Req \cap Vuln = \emptyset$，即 $Req \subseteq Safe$）。
    3.  **引入**：当前版本满足以下任一条件：
        *   **直接匹配**：允许任意一个“特效药”版本（`req.matches(any_fixed_version)`）。
        *   **隐式包含**：虽然不直接匹配（如跨大版本升级），但其允许的最小版本高于任意一个“特效药”版本（例如从 `0.9` 升到 `1.0`，而修复版是 `0.9.1`）。

### 潜在限制与漏判风险

该工具测量的是**狭义的、原地升级的修复行为**，目前的限制主要在于：
*   **发布时间准确性**：依赖 crates.io 数据库记录的 `created_at`，可能与实际代码合并时间有微小偏差。

## strict lag 的判定（简述）

对每个下游 crate 的发布时间序列，寻找一次“状态迁移”：

1) 曾经发布过某个版本，其依赖约束 `dep_req` 允许一个漏洞样本版本 `vuln_sample`
2) 随后第一次发布的新版本，其 `dep_req` 允许修复版本 `fixed_version`，并且不再允许 `vuln_sample`

该下游的 `lag_days` 定义为：

`(下游首次满足 2) 的发布时间 - 上游修复版本发布时间).num_days()`


这里“三万多”的结果指的是 明细文件 rustsec_rqx2_strict_lags.csv 里写出的记录行数（也就是程序输出日志里的 written rows: 30288，以及画图时统计到的 lag_days 条目数）。

更具体地说，每一行代表一次“严格修复事件”：

固定一个 RustSec 公告（rustsec_id / cve_id，对应一个漏洞）
固定一个下游 crate（downstream_crate）
在下游的发布历史里，找到它从“曾经受影响（依赖范围与漏洞版本集合有交集）”变成“严格修复（依赖范围不再包含任何漏洞版本，并且引入了修复版本）”的第一次转变
这一次转变就写出一行，并计算这次修复的 lag_days
所以 30288 不是“漏洞数量”，也不是“下游 crate 数量”，而是“漏洞 × 下游”的修复事件数量（更准确：满足 strict fix 条件的事件条数）。
