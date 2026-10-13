"""自动发现订阅源：搜索 GitHub 上近期活跃的相关仓库，验证后写入 sources_auto.txt"""
import os
import re
from datetime import datetime, timedelta, timezone

import requests

from crawler import fetch

API = "https://api.github.com"
QUERIES = [
    "topic:v2ray",
    "topic:clash",
    "topic:free-nodes",
    "free v2ray subscription in:name,description",
]
MIN_STARS = 20          # 最低星标数，过滤垃圾仓库
ACTIVE_DAYS = 7         # 只看最近 N 天有推送的仓库
MAX_FILES_PER_REPO = 5
MIN_LINKS = 10          # 文件里至少有这么多节点链接才算有效源
MAX_SOURCES = 30

FILE_RE = re.compile(r"(?i)(node|sub|v2ray|vmess|vless|trojan|base64|mix|all|free|config|clash|proxies?)[^/]*\.(txt|ya?ml)$")
EXCLUDE_RE = re.compile(r"(?i)readme|requirements|license|changelog|blacklist|domain|compose|mkdocs|workflow|^\.")

headers = {"Accept": "application/vnd.github+json"}
if os.environ.get("GITHUB_TOKEN"):
    headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"


def gh(path, **params):
    r = requests.get(f"{API}{path}", headers=headers, params=params, timeout=20)
    r.raise_for_status()
    return r.json()


def search_repos():
    since = (datetime.now(timezone.utc) - timedelta(days=ACTIVE_DAYS)).strftime("%Y-%m-%d")
    repos = {}
    for q in QUERIES:
        try:
            data = gh("/search/repositories",
                      q=f"{q} pushed:>{since} stars:>={MIN_STARS}",
                      sort="updated", per_page=20)
        except Exception as e:
            print(f"[search fail] {q}: {e}")
            continue
        for item in data.get("items", []):
            repos[item["full_name"]] = item["default_branch"]
    print(f"找到 {len(repos)} 个候选仓库")
    return repos


def candidate_files(full_name, branch):
    try:
        tree = gh(f"/repos/{full_name}/git/trees/{branch}", recursive=1)["tree"]
    except Exception as e:
        print(f"[tree fail] {full_name}: {e}")
        return []
    files = [
        t["path"] for t in tree
        if t["type"] == "blob"
        and t["path"].count("/") <= 1
        and FILE_RE.search(t["path"])
        and not EXCLUDE_RE.search(t["path"])
        and 500 < t.get("size", 0) < 5_000_000
    ]
    return [f"https://raw.githubusercontent.com/{full_name}/{branch}/{p}"
            for p in files[:MAX_FILES_PER_REPO]]


def main():
    good = []
    for full_name, branch in search_repos().items():
        for url in candidate_files(full_name, branch):
            if len(fetch(url)) >= MIN_LINKS:
                good.append(url)
            if len(good) >= MAX_SOURCES:
                break
        if len(good) >= MAX_SOURCES:
            break

    with open("sources_auto.txt", "w", encoding="utf-8") as f:
        f.write("# 由 discover.py 自动生成，请勿手动编辑\n")
        f.write("\n".join(good) + "\n")
    print(f"有效源 {len(good)} 个，已写入 sources_auto.txt")


if __name__ == "__main__":
    main()
