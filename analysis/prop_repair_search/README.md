# Hop=1 下游修复 PR 抓取与分类

本目录用于“漏洞传播延迟”研究的 Step 3 & 4：为 Hop=1 修复事件抓取对应 GitHub PR，并判定修复类型（全自动 / 半自动 / 人工 / 静默）。

## 依赖
* Python 3.9+
* `requests`
* 环境变量 `GITHUB_TOKEN`

安装：
```bash
pip install requests
export GITHUB_TOKEN="your_token"
```

## 输入要求
一个 CSV，至少包含字段：
```
root_rustsec_id,root_cve_id,upstream_crate,downstream_crate,
downstream_version,upstream_fix_time,downstream_fix_time
```
可选字段：`repo_url`（如无则按 downstream_crate 再查），`hop_distance`（存在时会自动过滤为 1）。

时间格式：支持 `YYYY-MM-DD HH:MM:SS[.ffffff] UTC` 或 ISO8601。

## 运行
```bash
python3 analysis/prop_repair_search/run_analysis.py \
  --input path/to/hop1_events.csv \
  --output outputs/pr_repair_hop1/pr_mapping.csv
```

### 用 Hop=1 全量传播事件 CSV 跑全量 PR 抓取（推荐）

前置：设置 GitHub Token（不要把 token 写进命令历史或仓库文件）：

```bash
export GITHUB_TOKEN="YOUR_TOKEN"
```

运行（全量 hop=1）：

```bash
python3 analysis/prop_repair_search/run_analysis.py \
  --input outputs/propagation_hop1/propagation_events_hop1_full.csv \
  --output outputs/pr_repair_hop1/pr_mapping_full_hop1.csv \
  --cache-dir cache/prop_search_full
```
可选参数：
- `--limit N`：只跑前 N 条
- `--force`：忽略已有输出重新写
- `--token`：显式传 Token
- `--cache-dir`：自定义缓存目录

## 逻辑概要
1) 搜索窗口：`[upstream_fix_time, downstream_fix_time + 1h]`  
2) GitHub Search：`repo:{owner}/{repo} is:pr is:merged merged:{start}..{end}`  
3) 过滤：必须改动 `Cargo.toml` 或 `Cargo.lock`  
4) 打分择优：标题/正文含上游包名、bump/upgrade/update、CVE，且距离 downstream 发布越近得分越高  
5) 分类：
   - automated：作者是 bot（Dependabot/Renovate 等），合并者为 bot 或为空  
   - semi_auto：作者是 bot，合并者为真人  
   - manual：作者真人  
   - direct：窗口内无 PR 命中  
6) 输出字段：`pr_url, pr_author, merged_by, author_is_bot, merged_by_is_bot, classification, candidate_count, search_status, match_score, snapshot_path`

## 代码实现要点（与脚本对应）

### 输入字段映射

- 上游修复时间：读取 `upstream_fix_time`
- 下游修复时间：优先读取 `downstream_fix_time`，若输入表没有该列则自动回退为 `downstream_time`（因此可以直接使用 `outputs/propagation_hop1/propagation_events_hop1_full.csv`）

### PR 候选选择流程

- 先用 Search API 取时间窗口内所有 merged PR（issues search 返回的 PR 条目）
- 再用 `GET /repos/{owner}/{repo}/pulls/{number}/files` 强制过滤：必须触达 `Cargo.toml` 或 `Cargo.lock`
- 对过滤后的候选 PR 打分并选最高分：
  - 标题/正文包含上游包名
  - 标题包含 bump/upgrade/update
  - 标题/正文包含 CVE
  - 合并时间越靠近下游发布（`downstream_time`）得分越高

### 修复类型分类（四类）

- **automated**：作者是 bot，且合并者为 bot 或为空（自动合并）
- **semi_auto**：作者是 bot，但合并者是真人
- **manual**：作者是真人（通常意味着需要人工适配）
- **direct**：窗口内没有满足 Cargo 文件过滤的 PR（注意：缺 repo / 时间解析失败会标记为 `unknown`，不计入 direct）

### 预期输出与规模

- 输出 CSV：`outputs/pr_repair_hop1/pr_mapping_full_hop1.csv`
- 每条输入事件一行输出，核心字段：
  - `search_status`: `found / not_found_in_window / candidates_filtered_out / skipped_no_repo / error_time_parse`
  - `classification`: `automated / semi_auto / manual / direct / unknown`
  - `pr_url/pr_title/pr_author/merged_by/...`（仅 `found` 时有值）
- 对于你当前的 Hop=1 全量输入（约 3 万行），预期：
  - 会有一部分仓库无 GitHub repo（`skipped_no_repo`）
  - 一部分事件属于 direct（发布修复但窗口内找不到对应 PR，或修复不是通过 PR）
  - 能命中的事件会分布在 automated/semi_auto/manual 三类

## 缓存与审计
- 搜索结果、PR 详情、文件列表均缓存到 `cache/prop_search/`
- 每个事件的候选与最终选择快照写入 `cache/prop_search/snapshots/{key}.json`
- 若输入缺少 `repo_url`，脚本会调用 crates.io API（1 req/sec，带缓存）自动补全下游仓库地址

## 后续工作
- 若需 Hop=1 原始事件构造（RustSec + crates.io index），可在此目录新增数据准备脚本；当前脚本聚焦 PR 抓取与分类。

python3 analysis/prop_repair_search/run_analysis.py \
    --input outputs/propagation_hop1/propagation_events_hop1_full.csv \
    --output outputs/pr_repair_hop1/pr_mapping_full_hop1.csv \
    --cache-dir cache/prop_search_full \
    --limit 200 \
    --force
