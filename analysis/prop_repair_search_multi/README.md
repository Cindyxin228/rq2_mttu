## 多跳 (Hop ≥ 2) 下游修复 PR 抓取与分类

本目录用于扩展 Hop=1 的 PR 抓取与分类逻辑到 **Hop ≥ 2** 的传播层级：  
为每一层 hop 的修复事件（hop=2,3,...）抓取对应 GitHub PR，并判定修复类型（全自动 / 半自动 / 人工 / 静默）。

### 1. 总体思路

- **输入**：由 Rust 批处理程序 `rqx2_rustsec_batch` 生成的 **多跳传播事件明细 CSV**，每行是一条 `root_rustsec_id × hop × downstream_crate` 的修复事件，包含：
  - `root_rustsec_id, root_cve_id, root_target_crate`
  - `hop`（1,2,3,...）
  - `upstream_crate, upstream_fix_version, upstream_fix_time`
  - `downstream_crate, downstream_version, downstream_time`
  - `lag_days, dep_req`
- **处理中间层**：
  - 先按 `hop` 拆分为若干“每层一个 CSV”（hop=1 已经是 `propagation_hop1/`，hop≥2 复用同一结构）
  - 对每层 hop 的 CSV 独立跑一次 PR 抓取脚本，输出对应的 PR 映射结果。
- **输出**：对每个 hop（2..K）生成一份 PR 映射 CSV，字段与 Hop=1 保持一致，便于后续合并和对比分析。

### 2. 目录与文件规划

计划在本目录下维护以下文件（部分已存在 / 待实现）：

- `METHODOLOGY.md`：多跳传播 + PR 抓取与分类的整体方法论说明（数据流、假设、限制）。
- `prepare_events_by_hop.py`（待实现）：
  - 输入：全量传播事件 CSV（包含 hop=1..K）
  - 输出：按 hop 拆分后的明细表，例如：
    - `outputs/propagation_hop1/propagation_events_hop1_full.csv`（已存在）
    - `outputs/propagation_hop2/propagation_events_hop2_full.csv`
    - `outputs/propagation_hop3/propagation_events_hop3_full.csv`
    - ...
- `run_analysis_multi.py`（待实现）：
  - 在现有 `analysis/prop_repair_search/run_analysis.py` 基础上封装一层：
    - 支持参数 `--hop 2` 指定处理哪一层；
    - 或者直接接受某个 hop CSV 路径作为输入。
  - 输出：
    - `outputs/pr_repair_hop2/pr_mapping_full_hop2.csv`
    - `outputs/pr_repair_hop3/pr_mapping_full_hop3.csv`
    - ...

### 3. 依赖

- Rust 批处理程序：
  - `cargo run --release --bin rqx2_rustsec_batch -- --propagation ...`
  - 需要 PostgreSQL + crates.io dump（同 Hop=1 分析）
- Python 3.9+
  - `requests`
  - （可选）`pandas`（仅用于方便地按 hop 拆分）
- GitHub API Token：
  - 环境变量 `GITHUB_TOKEN`，或通过 `--token` 参数传入

### 4. 输入输出约定（与 Hop=1 对齐）

拆分后的每层 hop CSV 至少包含字段（与 Hop=1 一致）：

```text
root_rustsec_id,root_cve_id,upstream_crate,downstream_crate,
downstream_version,upstream_fix_time,downstream_time,hop,lag_days,dep_req
```

PR 抓取脚本会将：

- `upstream_fix_time` → 作为窗口起点
- `downstream_time` → 作为窗口终点（+1 小时 buffer），在内部映射为 `downstream_fix_time`

输出的 PR 映射 CSV 字段与 Hop=1 脚本保持一致（便于拼接与统计）：

```text
root_rustsec_id,root_cve_id,upstream_crate,downstream_crate,downstream_version,
upstream_fix_time,downstream_fix_time,repo_url,
pr_url,pr_number,pr_title,pr_merged_at,pr_author,merged_by,
author_is_bot,merged_by_is_bot,classification,candidate_count,
search_status,match_score,snapshot_path
```

### 5. 与 Hop=1 的差异

- 时间含义不同：
  - Hop=1：`downstream_time` = 直接依赖漏洞包的 crate 发布修复版本的时间。
  - Hop≥2：`downstream_time` = 间接下游（通过中间“载体”传播）的 crate 首次不再依赖漏洞版本的时间。
- 修复语义更复杂：
  - Hop=2/3 往往同时升级多个中间依赖（carrier），PR 标题未必直接提到 root 包名或者 CVE。
  - 预计手动/半自动修复比例会更高，自动化工具可能覆盖率更低。

后续在 `METHODOLOGY.md` 中会详细展开：如何利用现有 Rust 传播分析的结果构造多跳事件表、如何复用 Hop=1 的 PR 抓取与分类逻辑、以及需要注意的偏差与局限。

