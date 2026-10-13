import base64
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlencode, urlparse

import requests
import yaml

SCHEMES = ("vmess", "vless", "ss", "trojan", "hysteria2", "hy2", "tuic")
UDP_SCHEMES = {"hysteria2", "hy2", "tuic"}  # UDP 协议无法用 TCP 测活，直接保留
LINK_RE = re.compile(r"(?:%s)://[^\s<>\"'`]+" % "|".join(SCHEMES))
HEADERS = {"User-Agent": "Mozilla/5.0"}
TCP_TIMEOUT = 3
MAX_NODES = 500


def b64decode(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return None


def load_sources(paths=("sources.txt", "sources_auto.txt")):
    urls = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(urls))  # 去重并保持顺序


def _b64(s, urlsafe=False):
    raw = s.encode() if isinstance(s, str) else s
    out = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
    return out.decode().rstrip("=") if urlsafe else out.decode()


def proxy_to_link(p):
    """把 Clash 的单个 proxy 字典转成分享链接，不支持的类型返回 None"""
    t = str(p.get("type", "")).lower()
    server, port = p.get("server"), p.get("port")
    name = quote(str(p.get("name", "node")))
    if not server or not port:
        return None
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    net = p.get("network", "tcp")
    path = ws.get("path") or grpc.get("grpc-service-name") or ""
    host = (ws.get("headers") or {}).get("Host", "")

    if t == "ss":
        if p.get("plugin"):
            return None
        userinfo = _b64(f"{p['cipher']}:{p['password']}", urlsafe=True)
        return f"ss://{userinfo}@{server}:{port}#{name}"

    if t == "vmess":
        obj = {
            "v": "2", "ps": str(p.get("name", "node")), "add": server, "port": str(port),
            "id": p["uuid"], "aid": str(p.get("alterId", 0)), "scy": p.get("cipher", "auto"),
            "net": net, "type": "none", "host": host, "path": path,
            "tls": "tls" if p.get("tls") else "", "sni": p.get("servername", ""),
        }
        return "vmess://" + _b64(json.dumps(obj, ensure_ascii=False))

    if t == "trojan":
        q = {"sni": p.get("sni", ""), "type": net, "path": path, "host": host}
        if p.get("skip-cert-verify"):
            q["allowInsecure"] = "1"
        q = {k: v for k, v in q.items() if v}
        return f"trojan://{quote(str(p['password']))}@{server}:{port}?{urlencode(q)}#{name}"

    if t == "vless":
        ro = p.get("reality-opts") or {}
        q = {
            "encryption": "none", "type": net, "path": path, "host": host,
            "security": "reality" if ro else ("tls" if p.get("tls") else "none"),
            "sni": p.get("servername", ""), "flow": p.get("flow", ""),
            "fp": p.get("client-fingerprint", ""),
            "pbk": ro.get("public-key", ""), "sid": ro.get("short-id", ""),
        }
        q = {k: v for k, v in q.items() if v}
        return f"vless://{p['uuid']}@{server}:{port}?{urlencode(q)}#{name}"

    if t in ("hysteria2", "hy2"):
        q = {"sni": p.get("sni", ""), "obfs": p.get("obfs", ""),
             "obfs-password": p.get("obfs-password", "")}
        if p.get("skip-cert-verify"):
            q["insecure"] = "1"
        q = {k: v for k, v in q.items() if v}
        qs = f"?{urlencode(q)}" if q else ""
        return f"hysteria2://{quote(str(p['password']))}@{server}:{port}{qs}#{name}"

    return None


def clash_to_links(text):
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    proxies = data.get("proxies") if isinstance(data, dict) else None
    links = []
    for p in proxies or []:
        try:
            link = proxy_to_link(p)
        except Exception:
            link = None
        if link:
            links.append(link)
    return links


def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"[fail] {url}: {e}")
        return []
    text = r.text
    links = LINK_RE.findall(text)
    if not links and "proxies:" in text:
        links = clash_to_links(text)
    if not links:
        decoded = b64decode(text)
        if decoded:
            links = LINK_RE.findall(decoded)
    print(f"[ok]   {url}: {len(links)} links")
    return links


def parse(link):
    """返回 (scheme, host, port)，解析失败返回 None"""
    try:
        scheme = link.split("://", 1)[0]
        if scheme == "vmess":
            data = json.loads(b64decode(link[8:]))
            return scheme, data["add"], int(data["port"])
        u = urlparse(link)
        if u.hostname and u.port:
            return scheme, u.hostname, u.port
        if scheme == "ss":  # ss://base64(method:pass@host:port)#name
            dec = b64decode(link[5:].split("#")[0])
            m = re.search(r"@([^:@]+):(\d+)$", dec or "")
            if m:
                return scheme, m.group(1), int(m.group(2))
    except Exception:
        pass
    return None


def tcp_test(item):
    link, (scheme, host, port) = item
    if scheme in UDP_SCHEMES:
        return link, 9999
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return link, int((time.time() - start) * 1000)
    except Exception:
        return link, None


def main():
    raw = []
    for url in load_sources():
        raw.extend(fetch(url))

    seen, nodes = set(), []
    for link in raw:
        info = parse(link)
        if not info or info in seen:
            continue
        seen.add(info)
        nodes.append((link, info))
    print(f"去重后 {len(nodes)} 个节点，开始测活...")

    with ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(tcp_test, nodes))

    alive = sorted((r for r in results if r[1] is not None), key=lambda x: x[1])
    links = [l for l, _ in alive][:MAX_NODES]
    print(f"存活 {len(alive)} 个，输出 {len(links)} 个")

    with open("nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())


if __name__ == "__main__":
    main()
