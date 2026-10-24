#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray Base64订阅聚合、解码、指纹去重、重编码脚本
支持协议：vmess / vless / trojan / ss / ssr / hysteria / hysteria2 / tuic
去重逻辑：忽略节点名称ps，依靠连接核心参数生成指纹
相同指纹判定为重复节点，只保留第一条
输出标准V2Ray base64订阅，适配OpenClash
额外：生成运行摘要，Python内部更新README标记区块
修复：url含特殊Unicode字符打印报ascii编码错误，使用repr安全输出日志
"""
import base64
import re
import requests
import urllib.parse
from typing import Dict, Set, Tuple
from datetime import datetime

# ===================== 配置区 =====================
SOURCE_FILE = "source.txt"
OUTPUT_FILE = "result.txt"
SUMMARY_FILE = "run_summary.log"
README_FILE = "README.md"
MARKER_START = "<!-- START SUMMARY -->"
MARKER_END = "<!-- END SUMMARY -->"
REQ_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
# ==================================================


def safe_b64_decode(raw: str) -> str:
    """
    V2Ray订阅标准base64解码
    自动清理空白字符、自动补全padding
    """
    raw = re.sub(r"\s+", "", raw)
    pad = 4 - len(raw) % 4
    if pad != 4:
        raw += "=" * pad
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return ""


def safe_b64_encode(text: str) -> str:
    """
    编码为V2Ray订阅标准base64
    返回无换行字符串
    """
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def parse_vmess(link: str) -> Tuple[str, Dict]:
    """解析 vmess:// 链接，返回去重指纹"""
    raw = link.removeprefix("vmess://")
    dec = safe_b64_decode(raw)
    try:
        import json
        d = json.loads(dec)
        fp = (
            f"vmess|{d.get('add','')}|{d.get('port','')}|{d.get('id','')}|{d.get('aid','')}|"
            f"{d.get('scy','')}|{d.get('net','')}|{d.get('type','')}|{d.get('host','')}|"
            f"{d.get('path','')}|{d.get('tls','')}"
        )
        return fp, d
    except Exception:
        return "", {}


def parse_vless(link: str) -> Tuple[str, Dict]:
    """解析 vless:// 链接，返回去重指纹"""
    main = link.removeprefix("vless://")
    part_hash = main.split("#", 1)
    main_nohash = part_hash[0]
    try:
        userhost, qs_raw = main_nohash.split("?", 1)
    except ValueError:
        userhost = main_nohash
        qs_raw = ""
    uuid, hostport = userhost.split("@", 1)
    host, port = hostport.split(":", 1)
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = (
        f"vless|{host}|{port}|{uuid}|{get('net')}|{get('host')}|{get('path')}|"
        f"{get('tls')}|{get('security')}|{get('alpn')}|{get('fp')}"
    )
    return fp, {}


def parse_trojan(link: str) -> Tuple[str, Dict]:
    """解析 trojan:// 链接，返回去重指纹"""
    main = link.removeprefix("trojan://")
    main_nohash = main.split("#", 1)[0]
    try:
        passhost, qs_raw = main_nohash.split("?", 1)
    except ValueError:
        passhost = main_nohash
        qs_raw = ""
    password, hostport = passhost.split("@", 1)
    host, port = hostport.split(":", 1)
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = f"trojan|{host}|{port}|{password}|{get('tls')}|{get('alpn')}|{get('fp')}"
    return fp, {}


def parse_ss(link: str) -> Tuple[str, Dict]:
    """解析 ss:// 链接，返回去重指纹"""
    main = link.removeprefix("ss://")
    main_nohash = main.split("#", 1)[0]
    try:
        b64part, hostport = main_nohash.split("@", 1)
    except ValueError:
        return "", {}
    dec = safe_b64_decode(b64part)
    method, pwd = dec.split(":", 1)
    host, port = hostport.split(":", 1)
    fp = f"ss|{host}|{port}|{pwd}|{method}"
    return fp, {}


def parse_ssr(link: str) -> Tuple[str, Dict]:
    """解析 ssr:// 链接，返回去重指纹"""
    raw = link.removeprefix("ssr://")
    dec = safe_b64_decode(raw)
    parts = dec.split(":")
    if len(parts) < 6:
        return "", {}
    host, port, protocol, method, obfs, rest = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
    qs_raw = rest.split("/?", 1)[1] if "/?" in rest else ""
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = f"ssr|{host}|{port}|{get('pass')}|{method}|{obfs}|{get('obfsparam')}|{protocol}|{get('protoparam')}"
    return fp, {}


def parse_hysteria2(link: str) -> Tuple[str, Dict]:
    """解析 hysteria2:// 链接，返回去重指纹"""
    main = link.removeprefix("hysteria2://")
    main_nohash = main.split("#", 1)[0]
    try:
        authpart, qs_raw = main_nohash.split("?", 1)
    except ValueError:
        authpart = main_nohash
        qs_raw = ""
    auth, serverport = authpart.split("@", 1)
    server, port = serverport.split(":", 1)
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = f"hysteria2|{server}|{port}|{auth}|{get('alpn')}|{get('up')}|{get('down')}"
    return fp, {}


def parse_hysteria(link: str) -> Tuple[str, Dict]:
    """解析 hysteria:// 链接，返回去重指纹"""
    main = link.removeprefix("hysteria://")
    main_nohash = main.split("#", 1)[0]
    try:
        serverport, qs_raw = main_nohash.split("?", 1)
    except ValueError:
        serverport = main_nohash
        qs_raw = ""
    server, port = serverport.split(":", 1)
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = f"hysteria|{server}|{port}|{get('auth')}|{get('alpn')}|{get('up')}|{get('down')}"
    return fp, {}


def parse_tuic(link: str) -> Tuple[str, Dict]:
    """解析 tuic:// 链接，返回去重指纹"""
    main = link.removeprefix("tuic://")
    main_nohash = main.split("#", 1)[0]
    try:
        authpart, qs_raw = main_nohash.split("?", 1)
    except ValueError:
        authpart = main_nohash
        qs_raw = ""
    auth, serverport = authpart.split("@", 1)
    uuid, password = auth.split(":", 1)
    server, port = serverport.split(":", 1)
    qs = urllib.parse.parse_qs(qs_raw)
    get = lambda k: qs.get(k, [""])[0]
    fp = f"tuic|{server}|{port}|{uuid}|{password}|{get('alpn')}"
    return fp, {}


def get_fingerprint(link: str) -> str:
    """入口：根据协议分发解析，返回去重指纹；解析失败返回空字符串"""
    link = link.strip()
    if link.startswith("vmess://"):
        fp, _ = parse_vmess(link)
        return fp
    elif link.startswith("vless://"):
        fp, _ = parse_vless(link)
        return fp
    elif link.startswith("trojan://"):
        fp, _ = parse_trojan(link)
        return fp
    elif link.startswith("ss://"):
        fp, _ = parse_ss(link)
        return fp
    elif link.startswith("ssr://"):
        fp, _ = parse_ssr(link)
        return fp
    elif link.startswith("hysteria2://"):
        fp, _ = parse_hysteria2(link)
        return fp
    elif link.startswith("hysteria://"):
        fp, _ = parse_hysteria(link)
        return fp
    elif link.startswith("tuic://"):
        fp, _ = parse_tuic(link)
        return fp
    else:
        return ""


def update_readme_summary(summary_text: str):
    """Python内部替换README标记区块，避免shell/perl转义异常；文件缺失打印警告不终止程序"""
    try:
        with open(README_FILE, "r", encoding="utf-8") as f:
            readme_content = f.read()
        pattern = re.compile(
            re.escape(MARKER_START) + r"\n.*?" + re.escape(MARKER_END),
            re.DOTALL
        )
        new_block = f"{MARKER_START}\n{summary_text}\n{MARKER_END}"
        new_content = pattern.sub(new_block, readme_content)
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(new_content)
        print("[OK] README.md 摘要区块已更新")
    except FileNotFoundError:
        print("[WARN] 未找到README.md，跳过更新README")


def main():
    fail_url_list = []
    # 读取源订阅列表
    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    sub_urls = []
    for l in lines:
        if not l or l.startswith("#"):
            continue
        sub_urls.append(l)
    print(f"[INFO] 读取到 {len(sub_urls)} 个订阅源")

    all_links: list[str] = []
    headers = {"User-Agent": USER_AGENT}
    for url in sub_urls:
        try:
            r = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
            r.raise_for_status()
            sub_raw = r.text
            dec_text = safe_b64_decode(sub_raw)
            if not dec_text:
                # 使用repr处理特殊字符url，防止ascii编码报错
                print(f"[WARN] {repr(url)} base64解码失败，跳过")
                fail_url_list.append(url)
                continue
            links = [x.strip() for x in dec_text.splitlines() if x.strip()]
            all_links.extend(links)
            print(f"[OK] {repr(url)} 解析得到 {len(links)} 条节点")
        except Exception as e:
            # 使用repr处理特殊字符url，防止ascii编码报错
            print(f"[ERR] 获取订阅 {repr(url)} 失败: {str(e)}")
            fail_url_list.append(url)
            continue
    print(f"[INFO] 原始汇总节点总数: {len(all_links)}")

    # 指纹去重
    seen_fp: Set[str] = set()
    unique_links: list[str] = []
    for lk in all_links:
        fp = get_fingerprint(lk)
        if not fp:
            # 无法解析协议的链接原样保留，不丢弃
            unique_links.append(lk)
            continue
        if fp not in seen_fp:
            seen_fp.add(fp)
            unique_links.append(lk)
    print(f"[INFO] 去重后节点总数: {len(unique_links)}")

    # 输出V2Ray base64订阅
    final_text = "\n".join(unique_links)
    final_b64 = safe_b64_encode(final_text)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(final_b64)
    print(f"[OK] 输出写入 {OUTPUT_FILE} 完成！")

    # 生成运行摘要
    now_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    summary_lines = [
        f"- 最后更新时间：{now_utc}",
        f"- 订阅源总数：{len(sub_urls)}",
        f"- 失败订阅源：{len(fail_url_list)}",
        f"- 原始汇总节点：{len(all_links)}",
        f"- 去重后节点：{len(unique_links)}"
    ]
    if fail_url_list:
        summary_lines.append("- 失效源列表：")
        for fu in fail_url_list:
            summary_lines.append(f"  - {fu}")
    summary_text = "\n".join(summary_lines)

    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(summary_text)
    print(f"[OK] 输出写入 {SUMMARY_FILE} 完成！")

    # 更新README
    update_readme_summary(summary_text)


if __name__ == "__main__":
    main()
