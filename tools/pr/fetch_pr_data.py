#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FetchResult:
    url: str
    cache_path: Path
    status: str
    http_status: int | None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fetch GitHub Pull Request JSON by URL and cache to a local directory."
    )
    p.add_argument(
        "--input",
        default="",
        help="Input file (.csv or .txt). If empty, use --url.",
    )
    p.add_argument(
        "--url",
        default="",
        help="Single PR URL (GitHub HTML URL or api.github.com URL).",
    )
    p.add_argument(
        "--url-column",
        default="",
        help="CSV column name containing PR URL (default: auto-detect).",
    )
    p.add_argument(
        "--cache-dir",
        default="pr_cache",
        help="Directory to store cached PR JSON files (default: pr_cache).",
    )
    p.add_argument(
        "--token",
        default="",
        help="GitHub token (default: env GITHUB_TOKEN).",
    )
    p.add_argument(
        "--min-interval-ms",
        type=int,
        default=300,
        help="Minimum delay between requests in milliseconds (default: 300).",
    )
    p.add_argument(
        "--timeout-secs",
        type=int,
        default=30,
        help="HTTP timeout seconds (default: 30).",
    )
    p.add_argument(
        "--max-retries",
        type=int,
        default=6,
        help="Max retries on transient failures (default: 6).",
    )
    p.add_argument(
        "--refresh",
        action="store_true",
        help="Re-fetch and overwrite cache even if file exists.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned cache paths without fetching.",
    )
    return p.parse_args()


def normalize_pr_api_url(raw: str) -> str:
    raw = (raw or "").strip().strip('"').strip("'")
    if not raw:
        raise ValueError("empty url")

    if raw.startswith("https://api.github.com/repos/") or raw.startswith(
        "http://api.github.com/repos/"
    ):
        return raw.replace("http://", "https://", 1)

    if raw.startswith("https://github.com/") or raw.startswith("http://github.com/"):
        u = urllib.parse.urlparse(raw.replace("http://", "https://", 1))
        parts = [p for p in u.path.split("/") if p]
        if len(parts) >= 4 and parts[2] in ("pull", "pulls"):
            owner, repo, _, num = parts[0], parts[1], parts[2], parts[3]
            if not num.isdigit():
                raise ValueError(f"unsupported github PR url: {raw}")
            return f"https://api.github.com/repos/{owner}/{repo}/pulls/{num}"
        raise ValueError(f"unsupported github url: {raw}")

    if raw.startswith("https://api.github.com/"):
        return raw

    raise ValueError(f"unsupported url: {raw}")


def cache_filename_from_api_url(api_url: str) -> str:
    u = urllib.parse.urlparse(api_url)
    parts = [p for p in u.path.split("/") if p]
    if len(parts) >= 5 and parts[0] == "repos" and parts[3] == "pulls":
        owner, repo, num = parts[1], parts[2], parts[4]
        base = f"{owner}_{repo}_pulls_{num}"
    else:
        base = re.sub(r"[^A-Za-z0-9]+", "_", u.netloc + "_" + u.path).strip("_")
    base = re.sub(r"_+", "_", base).strip("_")
    if not base:
        base = "pr"
    return base + ".json"


def iter_urls_from_csv(path: Path, url_column: str) -> Iterable[str]:
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return
        candidates = []
        if url_column:
            candidates.append(url_column)
        candidates.extend(
            [
                "url",
                "pr_url",
                "pull_url",
                "api_url",
                "html_url",
            ]
        )
        candidates = [c for c in candidates if c in set(r.fieldnames)]

        for row in r:
            v = ""
            for c in candidates:
                v = (row.get(c) or "").strip()
                if v:
                    break
            if v:
                yield v


def iter_urls_from_text(path: Path) -> Iterable[str]:
    for line in path.read_text(errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield s


def iter_input_urls(args: argparse.Namespace) -> list[str]:
    urls: list[str] = []

    if args.url:
        urls.append(args.url)

    if args.input:
        p = Path(args.input)
        if p.suffix.lower() == ".csv":
            urls.extend(iter_urls_from_csv(p, args.url_column))
        else:
            urls.extend(iter_urls_from_text(p))

    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        u = u.strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def read_http_error_body(err: urllib.error.HTTPError) -> str:
    try:
        raw = err.read()
        if not raw:
            return ""
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""


def should_retry_http(status: int) -> bool:
    return status in (408, 429, 500, 502, 503, 504)


def is_rate_limited(headers: dict[str, str], body: str) -> bool:
    remaining = (headers.get("X-RateLimit-Remaining") or "").strip()
    if remaining == "0":
        return True
    if "rate limit exceeded" in (body or "").lower():
        return True
    return False


def compute_rate_limit_sleep_seconds(headers: dict[str, str]) -> int:
    reset = (headers.get("X-RateLimit-Reset") or "").strip()
    if reset.isdigit():
        now = int(time.time())
        return max(1, int(reset) - now + 5)
    return 60


def fetch_json(
    api_url: str,
    token: str,
    timeout_secs: int,
    max_retries: int,
    min_interval_ms: int,
) -> tuple[dict, int]:
    last_err: Exception | None = None
    for attempt in range(max_retries + 1):
        if attempt > 0:
            time.sleep(min(60.0, 0.75 * (2**attempt)))

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rustsec-rqx2-pr-cache",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(api_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                return data, status
        except urllib.error.HTTPError as e:
            status = int(getattr(e, "code", 0) or 0)
            h = {k: v for k, v in (getattr(e, "headers", {}) or {}).items()}
            body = read_http_error_body(e)
            if status == 403 and is_rate_limited(h, body):
                time.sleep(compute_rate_limit_sleep_seconds(h))
                last_err = e
                continue
            if should_retry_http(status):
                last_err = e
                continue
            if body:
                raise RuntimeError(f"http {status} body={body[:2000]}") from e
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            continue
        finally:
            if min_interval_ms > 0:
                time.sleep(min_interval_ms / 1000.0)

    if last_err:
        raise last_err
    raise RuntimeError("unknown fetch failure")


def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def fetch_and_cache_one(
    raw_url: str,
    cache_dir: Path,
    token: str,
    timeout_secs: int,
    max_retries: int,
    min_interval_ms: int,
    refresh: bool,
    dry_run: bool,
) -> FetchResult:
    api_url = normalize_pr_api_url(raw_url)
    cache_path = cache_dir / cache_filename_from_api_url(api_url)
    if cache_path.exists() and not refresh:
        return FetchResult(url=api_url, cache_path=cache_path, status="cached", http_status=None)

    if dry_run:
        return FetchResult(url=api_url, cache_path=cache_path, status="planned", http_status=None)

    data, http_status = fetch_json(
        api_url,
        token=token,
        timeout_secs=timeout_secs,
        max_retries=max_retries,
        min_interval_ms=min_interval_ms,
    )
    atomic_write_json(cache_path, data)
    return FetchResult(url=api_url, cache_path=cache_path, status="fetched", http_status=http_status)


def main() -> None:
    args = parse_args()
    token = (args.token or os.environ.get("GITHUB_TOKEN") or "").strip()

    urls = iter_input_urls(args)
    if not urls:
        raise SystemExit("No input URLs. Provide --url or --input.")

    cache_dir = Path(args.cache_dir)

    results: list[FetchResult] = []
    fetched = 0
    cached = 0
    failed = 0
    for raw in urls:
        try:
            r = fetch_and_cache_one(
                raw_url=raw,
                cache_dir=cache_dir,
                token=token,
                timeout_secs=args.timeout_secs,
                max_retries=args.max_retries,
                min_interval_ms=args.min_interval_ms,
                refresh=args.refresh,
                dry_run=args.dry_run,
            )
            results.append(r)
            if r.status == "fetched":
                fetched += 1
            elif r.status == "cached":
                cached += 1
            print(f"{r.status}\t{r.cache_path}\t{r.url}")
        except Exception as e:
            failed += 1
            print(f"failed\t{raw}\t{type(e).__name__}: {e}")

    print(
        f"done: total={len(urls)} fetched={fetched} cached={cached} failed={failed} cache_dir={cache_dir}"
    )


if __name__ == "__main__":
    main()

