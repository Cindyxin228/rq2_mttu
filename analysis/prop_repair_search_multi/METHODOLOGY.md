## 多跳传播 (Hop ≥ 2) 修复 PR 搜索与分类方法论

本文件描述如何在已经完成的 Hop=1 分析基础上，扩展到 **Hop=2 及之后层级**，为每一层传播事件找到对应的修复 PR，并按修复类型（全自动 / 半自动 / 人工 / 静默）分类。

---

### 1. 背景与目标

- 已有工作：
  - 通过 Rust 批处理 `rqx2_rustsec_batch`，基于 RustSec + crates.io index 计算：
    - 每条公告的 **上游修复时间** (`upstream_fix_time`)
    - Hop=1..K 的 **传播事件**（下游 crate 及其修复时间 `downstream_time`）
  - 针对 **Hop=1**，我们已经：
    - 构造了 Hop=1 修复事件明细表
    - 在 `upstream_fix_time` 和 `downstream_time+1h` 的窗口内搜索 GitHub PR
    - 按作者/合并者区分 **automated / semi_auto / manual / direct**
- 新目标：
  - 将上述 PR 映射与分类逻辑扩展到 **Hop=2..K**，获得每一层的：
    - PR 找到率（found rate）
    - 修复类型分布（人工 / 半自动 / 全自动 / 静默）
    - 为后续比较不同 hop 的“修复行为模式”提供数据基础。

---

### 2. 数据来源与结构

#### 2.1 Rust 侧传播事件输出

`rqx2_rustsec_batch` 在开启 `--propagation` 和 `--propagation-events-output` 时，会输出包含多跳传播事件的 CSV，字段包括：

- `root_rustsec_id, root_cve_id, root_target_crate`
- `hop`：传播层级（1,2,3,...）
- `upstream_crate`：本 hop 的“上游”依赖包
- `upstream_fix_version, upstream_fix_time`：上游修复版本及其 crates.io 发布时间
- `downstream_crate, downstream_version, downstream_time`：本 hop 的“下游”依赖包及首次不再使用漏洞版本的发布时间
- `lag_days`：按天取整的传播延迟
- `dep_req`：本 hop 边上的依赖约束（如 `^0.9`, `~1.0` 等）

我们已经为 Hop=1 单独导出了：

- `outputs/propagation_hop1/propagation_events_hop1_full.csv`

类似地，可通过再次运行 Rust 程序（不限制 `propagation_max_hops`），将所有 hop 的传播事件写入一个大 CSV，再由 Python 脚本按 hop 拆分。

#### 2.2 分层事件表构造

目标是得到一组“每层一个 CSV”的事件表：

- Hop=1（已存在）：
  - `outputs/propagation_hop1/propagation_events_hop1_full.csv`
- Hop=2（待生成）：
  - `outputs/propagation_hop2/propagation_events_hop2_full.csv`
- Hop=3：
  - `outputs/propagation_hop3/propagation_events_hop3_full.csv`
- ...

每个表的字段应至少包含：

```text
root_rustsec_id,root_cve_id,upstream_crate,downstream_crate,
downstream_version,upstream_fix_time,downstream_time,hop,lag_days,dep_req
```

注意：Hop≥2 时的 `upstream_crate` 不再是 root 包，而是上一层的 carrier；但 `root_rustsec_id/root_cve_id` 仍指向最初的漏洞公告。

---

### 3. PR 搜索与分类逻辑（复用 Hop=1）

对每一层 hop，我们复用 `analysis/prop_repair_search/run_analysis.py` 的逻辑，只是输入换成对应 hop 的 CSV。

#### 3.1 时间窗口

- **起点**：`upstream_fix_time`
  - 本 hop 上游 crate 的修复版本在 crates.io 发布的时间。
  - 逻辑：下游要在上游修复可用之后才能升级。
- **终点**：`downstream_time + 1h`
  - 下游 crate 首次不再依赖漏洞版本的 crates.io 发布时间。
  - 逻辑：版本发布通常晚于合并时间，+1 小时 buffer 以容忍 CI/CD 延迟。

#### 3.2 候选获取 (GitHub Search API)

与 Hop=1 一致：

- 查询语句：

```text
repo:{owner}/{repo} is:pr is:merged merged:{T_start}..{T_end}
```

- 先按时间窗口获取所有已合并 PR，再做内容级过滤。
- 速率限制：
  - Search API：30 req/min，脚本通过 RateLimiter 控制为约 2.1s/次
  - Core API：约 0.8s/次，满足 5000 req/h 限制

#### 3.3 强过滤：依赖文件变更

仍然采用 **“必须改动 Cargo.toml 或 Cargo.lock”** 的硬约束：

- 调用 `GET /repos/{owner}/{repo}/pulls/{number}/files`
- 仅当文件列表中包含 `Cargo.toml` 或 `Cargo.lock` 时，才认为该 PR 为候选修复 PR。

对于 Hop≥2，这仍然合理，因为：

- 无论是直接修复 root 包还是 carrier 包，只要是通过升级依赖修复漏洞，一定要改动依赖管理文件。

#### 3.4 打分与择优

对每个候选 PR 计算一个简单的打分，规则与 Hop=1 一致：

- 标题/正文包含本 hop 的 `upstream_crate` → 高权重加分
- 标题包含 `bump/upgrade/update` 等关键词 → 辅助加分
- 标题/正文包含 `CVE` → 安全相关加分
- 合并时间越接近 `downstream_time`，得分越高（以小时差反比加分）

然后选取得分最高的 PR 作为本 hop 事件的“最可能修复 PR”。

#### 3.5 修复类型分类

对选中的 PR，从 Search 结果和 PR 详情中获取：

- `pr_author`（issues search 中的 `user.login`）
- `merged_by`（`GET /pulls/{number}` 返回的 `merged_by.login`）

然后按以下规则分类：

- **automated**：
  - `author` 是 bot（Dependabot/Renovate 等），且 `merged_by` 是 bot 或为空（自动合并）
- **semi_auto**：
  - `author` 是 bot，但 `merged_by` 是真人（人工点击 Merge）
- **manual**：
  - `author` 是真人（不以 [bot] 结尾等）
- **direct**：
  - 时间窗口内没有符合 Cargo 文件过滤的 PR：
    - `not_found_in_window`：窗口内无 PR
    - `candidates_filtered_out`：有 PR 但都未改动 Cargo
- **unknown**：
  - 无法获取仓库 (`skipped_no_repo`) 或时间解析失败 (`error_time_parse`)

---

### 4. 多跳特有的挑战

#### 4.1 语义模糊性增大

在 Hop=2/3 甚至更深层：

- 下游 PR 很可能同时升级多个 carrier 依赖，标题中不一定出现 root 包名。
- 某些 PR 可能是大规模依赖升级（“Update all dependencies”），其中包含但不限于修复该漏洞。
- PR 可能混合了依赖升级和业务逻辑变更。

这会带来两个影响：

1. **false negative**：真实参与修复的 PR 被过滤掉（例如只改了中间层 carrier 的 Cargo，而我们只看某一个 crate 仓库）。
2. **false positive**：选中的 PR 虽然改了 Cargo，但主要目的并非修复该漏洞（只是顺带升级）。

目前版本仍采用保守策略：

- 强制要求触达 Cargo 文件，避免明显无关的 PR；
- 用关键词 + 时间接近度打分来提升相关性；
- 将剩余不确定性交给后续人工抽样验证。

#### 4.2 性能与限流

由于 Hop≥2 的事件数量远大于 Hop=1：

- Search 调用次数约为 `O(#events)`；
- files/详情请求次数约为 `O(#events × 平均候选数)`；
- 必须依赖缓存（search 结果与 PR 文件列表）避免重复请求。

因此：

- 推荐按 hop 分层处理（一次只跑一层），便于控制耗时与速率；
- 对大 hop 值（如 ≥5）可以先抽样（`--limit`）做探索性分析，再决定是否全量跑。

---

### 5. 分析输出与后续工作

每层 hop 的 PR 映射完成后，我们将得到一组 CSV：

- `outputs/pr_repair_hop2/pr_mapping_full_hop2.csv`
- `outputs/pr_repair_hop3/pr_mapping_full_hop3.csv`
- ...

可以基于这些结果做：

1. **按 hop 的修复类型分布**：
   - 比较 Hop=1/2/3 中 manual / semi_auto / automated / direct 的比例变化。
2. **按公告 (root_rustsec_id) 聚合**：
   - 对同一 CVE，在不同 hop 上的修复模式是否不同。
3. **同一 hop 内的 lag_days vs 修复类型**：
   - 例如，对 Hop=2，比较自动化修复 vs 人工修复的传播延迟差异。

后续可以在 `analysis/prop_repair_search_multi/` 下添加统计脚本，将多层结果汇总为 Markdown 报告或表格，类似 `hop1_repair_analysis_report.md` 的形式。

