#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓取 requests 实际发送的请求头，与 curl -v 对比"""
import os, re, subprocess, random, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import des_encrypt, CFG, detect_local_ip, HEADERS
import requests

USER_ID = CFG["user_id"]; STB_ID = CFG["stb_id"]; MAC = CFG["mac"]
CUSTOM = CFG["custom_str"]; KEY = CFG["encrypt_key"]
EAS_IP = CFG["eas_ip"]; EAS_PORT = CFG["eas_port"]
local_ip = detect_local_ip()

# ---- curl 抓包 ----
get_url = f"http://{EAS_IP}:{EAS_PORT}/iptvepg/platform/getencrypttoken.jsp?UserID={USER_ID}&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype="
r = subprocess.run(["curl", "-sv", "-c", "/tmp/zte_cookie.txt",
                    "-H", "Accept-Language: zh-CN,en-US;q=0.8",
                    "-H", "X-Requested-With: com.android.smart.terminal.iptv", get_url],
                   capture_output=True)
hs = r.stdout.decode("utf-8", errors="replace")
stderr_curl = r.stderr.decode("utf-8", errors="replace")
print("===== CURL HANDSHAKE REQUEST HEADERS =====")
for line in stderr_curl.splitlines():
    if line.startswith("> "):
        print(line)
ch = re.search(r"GetAuthInfo\('(.*?)'\)", hs)
host = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', hs)
base = f"http://{host.group(1)}:8080"
random_num = random.randint(10000000, 99999999)
raw = f"{random_num}${ch.group(1)}${USER_ID}${STB_ID}${local_ip}${MAC}${CUSTOM}"
auth = des_encrypt(raw, KEY)
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={EAS_IP}&ipVersion=4&networkid=1"
data = f"UserID={USER_ID}&Authenticator={auth}&StbIP={local_ip}"
r = subprocess.run(["curl", "-sv", "-b", "/tmp/zte_cookie.txt", "-c", "/tmp/zte_cookie.txt",
                    "-H", "Accept-Language: zh-CN,en-US;q=0.8",
                    "-H", "X-Requested-With: com.android.smart.terminal.iptv",
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "-X", "POST", "--data", data, auth_url], capture_output=True)
print("===== CURL AUTH REQUEST HEADERS =====")
for line in r.stderr.decode("utf-8", errors="replace").splitlines():
    if line.startswith("> "):
        print(line)

# ---- requests 抓包 ----
print("===== REQUESTS HEADERS =====")
s = requests.Session()
s.headers.update(HEADERS)
pr = requests.Request("POST", auth_url, data=data, headers=s.headers)
prep = s.prepare_request(pr)
for k, v in prep.headers.items():
    print(f"> {k}: {v}")
