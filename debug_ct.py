#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小验证：POST 带 Content-Type: application/x-www-form-urlencoded 是否解决鉴权失败"""
import os, re, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import des_encrypt, CFG, detect_local_ip
import requests

USER_ID = CFG["user_id"]; STB_ID = CFG["stb_id"]; MAC = CFG["mac"]
CUSTOM = CFG["custom_str"]; KEY = CFG["encrypt_key"]
EAS_IP = CFG["eas_ip"]; EAS_PORT = CFG["eas_port"]
local_ip = detect_local_ip()

s = requests.Session()
s.headers.update({"Accept-Language": "zh-CN,en-US;q=0.8",
                  "X-Requested-With": "com.android.smart.terminal.iptv"})

get_url = (f"http://{EAS_IP}:{EAS_PORT}/iptvepg/platform/getencrypttoken.jsp"
           f"?UserID={USER_ID}&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
r = s.get(get_url, timeout=8)
body = r.content.decode("utf-8", errors="replace")
ch = re.search(r"GetAuthInfo\('(.*?)'\)", body)
host = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', body)
if not (ch and host):
    print("HANDSHAKE FAIL", body[:300]); sys.exit(1)
base = f"http://{host.group(1)}:8080"

rn = random.randint(10000000, 99999999)
raw = f"{rn}${ch.group(1)}${USER_ID}${STB_ID}${local_ip}${MAC}${CUSTOM}"
auth = des_encrypt(raw, KEY)
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={EAS_IP}&ipVersion=4&networkid=1"
data = f"UserID={USER_ID}&Authenticator={auth}&StbIP={local_ip}"
r = s.post(auth_url, data=data, timeout=8,
           headers={"Content-Type": "application/x-www-form-urlencoded"})
body = r.content.decode("utf-8", errors="replace")
tok = re.search(r"jsSetConfig\('UserToken','([^']+)'", body) or re.search(r"UserToken=([A-Za-z0-9_.\-]+)", body)
if tok:
    print("CT OK UserToken=", tok.group(1))
else:
    err = re.search(r"errorcode=(\d+)", body)
    print("CT FAIL errorcode=", err.group(1) if err else "?", "len=", len(body))
