#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 curl 复刻 Java 请求，对比 requests 差异"""
import os, re, subprocess, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import des_encrypt, CFG, detect_local_ip

USER_ID = CFG["user_id"]
STB_ID = CFG["stb_id"]
MAC = CFG["mac"]
CUSTOM = CFG["custom_str"]
KEY = CFG["encrypt_key"]
EAS_IP = CFG["eas_ip"]
EAS_PORT = CFG["eas_port"]

local_ip = detect_local_ip()
print("localIp=", local_ip)

# 1. 握手（不带 Accept-Encoding，模仿 Java）
get_url = f"http://{EAS_IP}:{EAS_PORT}/iptvepg/platform/getencrypttoken.jsp?UserID={USER_ID}&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype="
r = subprocess.run([
    "curl", "-s", "-c", "/tmp/zte_cookie.txt", "-H", "Accept-Language: zh-CN,en-US;q=0.8",
    "-H", "X-Requested-With: com.android.smart.terminal.iptv", get_url
], capture_output=True)
hs = r.stdout.decode("utf-8", errors="replace")
ch = re.search(r"GetAuthInfo\('(.*?)'\)", hs)
host = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', hs)
print("challenge:", ch.group(1) if ch else None)
print("epgHost:", host.group(1) if host else None)
if not (ch and host):
    print("HANDSHAKE FAIL", hs[:300]); sys.exit(1)
base = f"http://{host.group(1)}:8080"

# 2. DES + POST（用 Java 风格 UA，不带 Accept-Encoding）
random_num = random.randint(10000000, 99999999)
raw = f"{random_num}${ch.group(1)}${USER_ID}${STB_ID}${local_ip}${MAC}${CUSTOM}"
auth = des_encrypt(raw, KEY)
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={EAS_IP}&ipVersion=4&networkid=1"
data = f"UserID={USER_ID}&Authenticator={auth}&StbIP={local_ip}"
r = subprocess.run([
    "curl", "-s", "-b", "/tmp/zte_cookie.txt", "-c", "/tmp/zte_cookie.txt",
    "-H", "Accept-Language: zh-CN,en-US;q=0.8",
    "-H", "X-Requested-With: com.android.smart.terminal.iptv",
    "-H", "Content-Type: application/x-www-form-urlencoded",
    "-X", "POST", "--data", data, auth_url
], capture_output=True)
body = r.stdout.decode("utf-8", errors="replace")
tok = re.search(r"jsSetConfig\('UserToken','([^']+)'", body) or re.search(r"UserToken=([A-Za-z0-9_.\-]+)", body)
if tok:
    print("CURL SUCCESS UserToken=", tok.group(1))
else:
    err = re.search(r"errorcode=(\d+)", body)
    print("CURL FAIL errorcode=", err.group(1) if err else "?", "len=", len(body))
