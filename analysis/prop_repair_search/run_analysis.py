"""
重新实现：Hop=1 下游修复 PR 抓取 + 自动/半自动/人工/静默 分类

输入：包含 Hop=1 修复事件的 CSV，要求字段：
  root_rustsec_id, root_cve_id, upstream_crate, downstream_crate,
  downstream_version, upstream_fix_time, downstream_fix_time
可选字段：repo_url, hop_distance（若存在将自动过滤 hop=1）

输出：outputs/pr_repair_hop1/pr_mapping.csv
  增加分类字段：author_is_bot, merged_by_is_bot, classification 等
缓存：cache/prop_search/ 下保存搜索、PR详情、文件列表、候选快照
"""

import argparse
import csv
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# --- 日志设置 ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("prop_repair_search")

# --- 常量 ---
DEFAULT_CACHE_DIR = "cache/prop_search"
OUTPUT_DIR = "outputs/pr_repair_hop1"
DEFAULT_OUTPUT = f"{OUTPUT_DIR}/pr_mapping.csv"
BOT_LOGINS = {
    "dependabot[bot]",
    "renovate[bot]",
    "renovate-bot",
    "github-actions[bot]",
    "dependabot-preview[bot]",
}

# --- 工具函数 ---


def ensure_dirs(cache_dir: str):
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def parse_time_to_dt(value: str) -> Optional[datetime]:
    """接受类似 '2016-11-06 03:11:39.197825 UTC' 或 ISO8601 字符串"""
    if not value:
        return None
    v = value.strip().replace(" UTC", "").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except Exception:
        try:
            if "." in v:
                dt = datetime.strptime(v, "%Y-%m-%d %H:%M:%S.%f")
            else:
                dt = datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.warning(f"时间解析失败: {value} ({e})")
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def extract_repo_slug(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    match = re.search(r"github\.com[:/]([\w\-.]+)/([\w\-.]+)", url)
    if match:
        owner = match.group(1)
        repo = match.group(2).replace(".git", "")
        return f"{owner}/{repo}"
    return None


def is_bot_login(login: Optional[str]) -> bool:
    if not login:
        return False
    l = login.lower()
    return l in BOT_LOGINS or l.endswith("[bot]") or l.endswith("-bot") or l.endswith("_bot")


def score_candidate(pr: Dict[str, Any], upstream_crate: str, downstream_time: datetime) -> int:
    title = (pr.get("title") or "").lower()
    body = (pr.get("body") or "").lower()
    upstream = upstream_crate.lower()
    score = 0
    if upstream in title:
        score += 10
    if upstream in body:
        score += 5
    if "bump" in title or "upgrade" in title or "update" in title:
        score += 3
    if "cve" in title or "cve" in body:
        score += 4
    merged_at = pr.get("pull_request", {}).get("merged_at") or pr.get("merged_at")
    if merged_at:
        try:
            mdt = parse_time_to_dt(merged_at)
            if mdt:
                delta = abs((downstream_time - mdt).total_seconds())
                # 更近的合并时间加分（反比取整）
                score += max(0, 5 - int(delta / 3600))
        except Exception:
            pass
    return score


# --- GitHub Client ---


class RateLimiter:
    def __init__(self, interval: float):
        self.interval = interval
        self.last_call = 0.0

    def wait(self):
        now = time.time()
        elapsed = now - self.last_call
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_call = time.time()


class GitHubClient:
    def __init__(self, token: str, cache_dir: str):
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "prop-repair-search",
        }
        self.cache_dir = cache_dir
        self.core_limiter = RateLimiter(0.8)   # ~5000/hr
        self.search_limiter = RateLimiter(2.1) # ~30/min

    def _get(self, url: str, params=None, is_search=False) -> Optional[Any]:
        limiter = self.search_limiter if is_search else self.core_limiter
        limiter.wait()
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        except Exception as e:
            logger.warning(f"请求异常 {url}: {e}")
            return None

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (401,):
            logger.error("GitHub Token 无效或权限不足")
            return None
        if resp.status_code in (403, 429):
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait_s = max(reset - time.time(), 60)
            logger.warning(f"命中速率限制，等待 {wait_s:.0f}s")
            time.sleep(wait_s + 1)
            return self._get(url, params, is_search)
        if resp.status_code == 404:
            return None
        logger.warning(f"请求失败 {url} -> {resp.status_code}")
        return None

    def search_prs(self, repo_slug: str, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        def fmt(dt: datetime) -> str:
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        q = f"repo:{repo_slug} is:pr is:merged merged:{fmt(start)}..{fmt(end)}"
        cache_path = os.path.join(self.cache_dir, f"search_{repo_slug}_{int(start.timestamp())}_{int(end.timestamp())}.json")
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)

        url = f"{self.base_url}/search/issues"
        params = {"q": q, "per_page": 100}
        data = self._get(url, params=params, is_search=True)
        items = data.get("items", []) if data else []
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(items, f)
        return items

    def get_pr_files(self, repo_slug: str, pr_number: int) -> List[str]:
        cache_path = os.path.join(self.cache_dir, "pr_files", f"{repo_slug.replace('/','_')}_{pr_number}.json")
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except Exception:
                    pass
        url = f"{self.base_url}/repos/{repo_slug}/pulls/{pr_number}/files"
        data = self._get(url)
        filenames = [f.get("filename", "") for f in data] if data else []
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(filenames, f)
        return filenames

    def get_pr_detail(self, repo_slug: str, pr_number: int) -> Optional[Dict[str, Any]]:
        cache_path = os.path.join(self.cache_dir, "pr_detail", f"{repo_slug.replace('/','_')}_{pr_number}.json")
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except Exception:
                    pass
        url = f"{self.base_url}/repos/{repo_slug}/pulls/{pr_number}"
        data = self._get(url)
        if data:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        return data


# --- 处理单个事件 ---


@dataclass
class EventRow:
    row: Dict[str, Any]

    @property
    def key(self) -> str:
        return f"{self.row.get('root_rustsec_id','')}|{self.row.get('downstream_crate','')}|{self.row.get('downstream_version','')}"


class CratesIOClient:
    """用于补全 repo_url（当输入缺失时）"""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.rate = RateLimiter(1.0)  # 1 req/sec
        self.session = requests.Session()
        self.headers = {"User-Agent": "prop-repair-search"}

    def _cache_path(self, crate: str) -> str:
        return os.path.join(self.cache_dir, "crates_io", f"{crate}.json")

    def get_repo_url(self, crate: str) -> Optional[str]:
        if not crate:
            return None
        cache_path = self._cache_path(crate)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("repository")
            except Exception:
                pass
        self.rate.wait()
        try:
            resp = self.session.get(f"https://crates.io/api/v1/crates/{crate}", headers=self.headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                repo = data.get("crate", {}).get("repository")
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump({"repository": repo}, f)
                return repo
            elif resp.status_code == 404:
                return None
            else:
                logger.warning(f"crates.io {crate} -> {resp.status_code}")
                return None
        except Exception as e:
            logger.warning(f"crates.io {crate} 异常: {e}")
            return None


def classify(author_login: Optional[str], merged_by_login: Optional[str]) -> Tuple[str, bool, bool]:
    author_bot = is_bot_login(author_login)
    merged_bot = is_bot_login(merged_by_login)
    if author_login is None:
        return "direct", author_bot, merged_bot
    if author_bot and (merged_bot or merged_by_login is None):
        return "automated", author_bot, merged_bot
    if author_bot and not merged_bot and merged_by_login:
        return "semi_auto", author_bot, merged_bot
    if not author_bot:
        return "manual", author_bot, merged_bot
    return "manual", author_bot, merged_bot


def process_event(
    gh: GitHubClient,
    crates_client: CratesIOClient,
    event: EventRow,
    default_repo_url: Optional[str],
    cache_dir: str,
) -> Dict[str, Any]:
    row = event.row
    result = row.copy()

    repo_url = row.get("repo_url") or default_repo_url
    if not repo_url:
        repo_url = crates_client.get_repo_url(row.get("downstream_crate", ""))
    repo_slug = extract_repo_slug(repo_url)
    if not repo_slug:
        result.update({
            "search_status": "skipped_no_repo",
            "classification": "unknown"
        })
        return result

    t_up = parse_time_to_dt(row.get("upstream_fix_time", ""))
    t_down = parse_time_to_dt(row.get("downstream_fix_time", row.get("downstream_time", "")))
    if not t_up or not t_down:
        result.update({"search_status": "error_time_parse", "classification": "unknown"})
        return result

    # 搜索窗口
    start = t_up
    end = t_down + timedelta(hours=1)

    candidates = gh.search_prs(repo_slug, start, end)
    if not candidates:
        result.update({"search_status": "not_found_in_window", "classification": "direct", "candidate_count": 0})
        return result

    valid_candidates = []
    for pr in candidates:
        pr_num = pr.get("number")
        if not pr_num:
            continue
        files = gh.get_pr_files(repo_slug, pr_num)
        if not files:
            continue
        if not any(fn.endswith("Cargo.toml") or fn.endswith("Cargo.lock") for fn in files):
            continue
        valid_candidates.append(pr)

    if not valid_candidates:
        result.update({"search_status": "candidates_filtered_out", "classification": "direct", "candidate_count": 0})
        return result

    # 打分选择
    downstream_dt = t_down
    scored = []
    for pr in valid_candidates:
        scored.append((score_candidate(pr, row.get("upstream_crate", ""), downstream_dt), pr))
    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best_pr = scored[0]

    pr_num = best_pr.get("number")
    detail = gh.get_pr_detail(repo_slug, pr_num) if pr_num else None
    merged_by_login: Optional[str] = None
    if True:
        merged_at = best_pr.get("merged_at")
    if isinstance(detail, dict):
        try:
            merged_by_login = (detail.get("merged_by") or {}).get("login")
        except Exception:
            merged_by_login = None
        merged_at = detail.get("merged_at") or merged_at

    author_login = best_pr.get("user", {}).get("login")
    classification, author_is_bot, merged_by_is_bot = classify(author_login, merged_by_login)

    # 保存候选快照
    snap_path = os.path.join(cache_dir, "snapshots", f"{event.key}.json")
    os.makedirs(os.path.dirname(snap_path), exist_ok=True)
    snapshot = {
        "window": [start.isoformat(), end.isoformat()],
        "repo_slug": repo_slug,
        "candidates": valid_candidates,
        "chosen_pr": best_pr,
        "chosen_detail": detail,
    }
    with open(snap_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f)

    result.update({
        "repo_url": repo_url,
        "pr_url": best_pr.get("html_url"),
        "pr_number": pr_num,
        "pr_title": best_pr.get("title"),
        "pr_merged_at": merged_at,
        "pr_author": author_login,
        "merged_by": merged_by_login,
        "author_is_bot": author_is_bot,
        "merged_by_is_bot": merged_by_is_bot,
        "classification": classification,
        "candidate_count": len(valid_candidates),
        "search_status": "found",
        "match_score": best_score,
        "snapshot_path": snap_path,
    })
    return result


# --- 主程序 ---


def load_input(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def main():
    parser = argparse.ArgumentParser(description="Hop=1 下游修复 PR 抓取与分类")
    parser.add_argument("--input", required=True, help="Hop=1 事件 CSV")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="输出 CSV 路径")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="缓存目录")
    parser.add_argument("--token", help="GitHub Token，不传则用环境变量 GITHUB_TOKEN")
    parser.add_argument("--limit", type=int, default=0, help="仅处理前 N 条，0 为不限制")
    parser.add_argument("--force", action="store_true", help="忽略已存在的输出，重新写入")
    args = parser.parse_args()

    ensure_dirs(args.cache_dir)

    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("需要 GitHub Token (环境变量 GITHUB_TOKEN 或 --token)")
        return

    gh = GitHubClient(token, args.cache_dir)
    crates_client = CratesIOClient(args.cache_dir)
    rows = load_input(args.input)

    # 续跑：读取已处理
    processed_keys = set()
    write_header = True
    completed_status = {"found", "not_found_in_window", "candidates_filtered_out"}
    if os.path.exists(args.output) and not args.force:
        with open(args.output, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                status = (r.get("search_status") or "").strip()
                if status in completed_status:
                    k = f"{r.get('root_rustsec_id','')}|{r.get('downstream_crate','')}|{r.get('downstream_version','')}"
                    processed_keys.add(k)
        write_header = False
        logger.info(f"续跑模式：已有 {len(processed_keys)} 条")

    fieldnames = [
        "root_rustsec_id",
        "root_cve_id",
        "upstream_crate",
        "downstream_crate",
        "downstream_version",
        "upstream_fix_time",
        "downstream_fix_time",
        "repo_url",
        "pr_url",
        "pr_number",
        "pr_title",
        "pr_merged_at",
        "pr_author",
        "merged_by",
        "author_is_bot",
        "merged_by_is_bot",
        "classification",
        "candidate_count",
        "search_status",
        "match_score",
        "snapshot_path",
    ]

    count = 0
    with open(args.output, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()

        for row in rows:
            evt = EventRow(row=row)
            if evt.key in processed_keys:
                continue
            if row.get("hop_distance") and str(row["hop_distance"]) != "1":
                continue
            if args.limit and count >= args.limit:
                break

            res = process_event(gh, crates_client, evt, row.get("repo_url"), args.cache_dir)
            writer.writerow({k: res.get(k, "") for k in fieldnames})
            f.flush()
            count += 1
            logger.info(f"完成 {count}/{len(rows)} -> {res.get('classification')} [{res.get('search_status')}]")

    logger.info("全部完成")


if __name__ == "__main__":
    main()
