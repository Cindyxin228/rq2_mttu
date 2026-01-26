# Hop=1 修复 PR 搜索与分类方法论

目标：为 Hop=1 修复事件自动化抓取 GitHub PR，并判定修复类型（全自动 / 半自动 / 人工 / 静默），支撑传播延迟分析。

## 1. 时间锚点
* **Upstream Fix Time**：上游漏洞包第一个修复版本发布的 crates.io 时间。
* **Downstream Fix Time**：下游受影响包第一个不再允许漏洞版本的发布时间（crates.io）。
搜索窗口：`[Upstream Fix Time, Downstream Fix Time + 1h]`。

## 2. 搜索与过滤
1) GitHub Search API：
```
repo:{owner}/{repo} is:pr is:merged merged:{start}..{end}
```
2) 强制过滤：PR 必须改动 `Cargo.toml` 或 `Cargo.lock`。  
3) 可选过滤：若有 monorepo 子路径，可再筛路径前缀（未在代码里默认打开）。  
4) 打分择优：标题/正文含上游包名、bump/upgrade/update、CVE；合并时间距离 Downstream 发布越近得分越高。

## 3. 分类规则
* **automated**：作者是 bot（Dependabot/Renovate/GitHub Actions 等），合并者为 bot 或为空（自动合并）。
* **semi_auto**：作者是 bot，合并者为真人。
* **manual**：作者为真人（通常伴随代码适配）。
* **direct**：窗口内未找到满足过滤条件的 PR（视作“静默发布”）。

## 4. 输出与审计
* 主要字段：`pr_url, pr_author, merged_by, author_is_bot, merged_by_is_bot, classification, candidate_count, search_status, match_score, snapshot_path`
* 审计：每个事件的候选与最终选择写入 `cache/prop_search/snapshots/{key}.json`，便于复核。

## 5. 局限
* 无 PR / 直接 push 的修复只能归为 direct，无法提供 PR 级别上下文。
* 仓库私有或删除时无法获取。
* Monorepo 若无路径过滤，可能仍有歧义；可在文件过滤上加路径前缀以降低误报。
