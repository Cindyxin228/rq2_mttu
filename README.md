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
- `--downstream-cache-crates <N>`：下游依赖查询缓存的 crate 数量（默认 50）
- `--max-advisories <N>`：仅处理前 N 条公告（试跑用）

#### 运行完整分析

执行以下命令运行全量 RustSec 公告分析：

```bash
cargo run --release --bin rqx2_rustsec_batch
```

该命令会：
1.  下载最新的 RustSec Advisory Database。
2.  连接本地 PostgreSQL 数据库（需提前配置 `DATABASE_URL`）。
3.  对所有公告进行全量版本判定与 strict lag 计算。
4.  输出结果到 `rustsec_rqx2_strict_lags.csv`（明细）和 `rustsec_rqx2_strict_summary.csv`（汇总）。

输出：

- 明细 `rustsec_rqx2_strict_lags.csv` 字段：
  - `rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_crate,downstream_version,downstream_time,lag_days,original_req,fixed_req`
- 汇总 `rustsec_rqx2_strict_summary.csv` 字段：
  - `rustsec_id,cve_id,severity,target_crate,fixed_version,fix_time,downstream_fixed_cnt,lag_days_min,lag_days_p50,lag_days_avg,lag_days_max`

#### 输出 CSV 含义（怎么得到 lag_days）

这两个 CSV 的关系是：明细负责“每一次修复事件”，汇总负责“把同一个漏洞下的修复事件做统计”。

- 明细 `rustsec_rqx2_strict_lags.csv`：每一行代表一次 “漏洞 × 下游 crate” 的**严格修复事件**
  - `rustsec_id / cve_id`：RustSec 公告 ID 与 CVE（若无 CVE，则用 RustSec ID 代替）
  - `severity`：漏洞严重等级（见下方 severity 计算规则）
  - `target_crate`：存在漏洞的上游 crate
  - `fixed_version / fix_time`：上游修复版本以及该版本在 crates.io 的发布时间
  - `downstream_crate`：下游 crate 名
  - `downstream_version / downstream_time`：下游发生“严格修复”的那个发布版本，以及该版本发布时间
  - `lag_days`：天数差，计算公式为 `downstream_time - matched_fix_time`（向下取整到天）
  - `original_req`：下游最后一次仍可能选到漏洞版本的依赖约束（例如 `^0.7`）
  - `fixed_req`：下游第一次不再包含任何漏洞版本、且引入修复版本的依赖约束（例如 `^0.9`）

- 汇总 `rustsec_rqx2_strict_summary.csv`：按同一个漏洞（同一个 `rustsec_id/cve_id/target_crate`）汇总统计
  - `downstream_fixed_cnt`：该漏洞下，发生严格修复的下游事件数（对应明细行数）
  - `lag_days_min / p50 / avg / max`：对该漏洞下所有 `lag_days` 的统计

#### 按漏洞等级（severity）看 lag_days，并输出 SVG

思路：

1.  RustSec Advisory 的 TOML front matter 中包含 `advisory.severity`（如 `LOW / MEDIUM / HIGH / CRITICAL / INFO`）。
2.  批处理程序解析该字段，并把标准化后的 `severity` 写入明细与汇总 CSV。
3.  若公告未显式给出 `advisory.severity`，则尝试从 `advisory.cvss`（CVSS v3.0/3.1 向量）计算 base score 并映射为 `LOW/MEDIUM/HIGH/CRITICAL`；若为信息型公告（存在 `advisory.informational`）则记为 `INFO`；否则为 `UNKNOWN`。
4.  画图时按 `severity` 对明细 CSV 的 `lag_days` 分组，每一组单独画一张直方图（SVG）。

severity 计算规则（用于写入 CSV 的 `severity` 列）：

- 优先级：
  1. 若存在 `advisory.severity`：直接使用并标准化为 `INFO/LOW/MEDIUM/HIGH/CRITICAL`
  2. 否则若存在 `advisory.cvss` 且为 `CVSS:3.0/...` 或 `CVSS:3.1/...`：从向量计算 CVSS base score，再映射等级
  3. 否则若存在 `advisory.informational`：记为 `INFO`
  4. 否则：记为 `UNKNOWN`

- CVSS base score 映射（v3.x 常见区间）：
  - `0.0` → `INFO`
  - `[0.1, 4.0)` → `LOW`
  - `[4.0, 7.0)` → `MEDIUM`
  - `[7.0, 9.0)` → `HIGH`
  - `[9.0, 10.0]` → `CRITICAL`

为什么还会有 `UNKNOWN`：

- RustSec 并不强制每条公告都填 `severity` 或 `cvss`；当公告既没有显式 `severity`，也没有可解析的 CVSS v3 向量（且不是 informational），我们就无法“可靠推导”等级，只能标为 `UNKNOWN`，避免主观猜测导致统计失真。

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

#### 如何确认结果正确（建议核对）

1) 明细总行数 = 按 severity 分组求和（同一份 CSV、同一过滤条件下必须相等）：

```bash
python3 - <<'PY'
import csv
from collections import Counter
p='rustsec_rqx2_strict_lags.csv'
ctr=Counter(); total=0
with open(p,newline='') as f:
    for row in csv.DictReader(f):
        v=row.get('lag_days','').strip()
        if not v:
            continue
        total += 1
        sev=(row.get('severity') or 'UNKNOWN').strip().upper() or 'UNKNOWN'
        ctr[sev] += 1
print("total_lag_rows", total)
print("sum_by_severity", sum(ctr.values()))
print(dict(ctr))
PY
```

2) 随机抽一行，手动验证 `lag_days = downstream_time - matched_fix_time` 的“天数差”是否一致：

```bash
python3 - <<'PY'
import csv
from datetime import datetime, timezone

def parse_ts(s: str) -> datetime:
    s = s.replace(" UTC", "").strip()
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)

p='rustsec_rqx2_strict_lags.csv'
with open(p,newline='') as f:
    r=csv.DictReader(f)
    row=next(r)
fix=parse_ts(row['fix_time'])
down=parse_ts(row['downstream_time'])
calc=(down-fix).days
print("example", row['rustsec_id'], row['downstream_crate'], row['downstream_version'])
print("csv_lag_days", row['lag_days'])
print("recomputed_days", calc)
PY
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
