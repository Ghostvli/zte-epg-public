#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调试 auth.jsp 响应格式"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import ZteEpgClient, log

client = ZteEpgClient()
client.session.headers.update({"User-Agent": os.environ.get("ZTE_UA", "Java/1.8.0")})
log(f"localIp={client.local_ip}")
import requests
from urllib.parse import quote
from collect_epg import des_encrypt, CFG
eas = f"http://{CFG['eas_ip']}:{CFG['eas_port']}"
get_url = (f"{eas}/iptvepg/platform/getencrypttoken.jsp?UserID={quote(CFG['user_id'])}"
           f"&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
handshake = client._get(get_url)
print("=== handshake full ===")
print(handshake[:3000] if handshake else "None")
m = re.search(r"GetAuthInfo\('(.*?)'\)", handshake or "")
m2 = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', handshake or "")
print("challenge:", m.group(1) if m else None)
print("epgHost:", m2.group(1) if m2 else None)
if not (m and m2):
    sys.exit(1)
base = f"http://{m2.group(1)}:8080"
random_num = 12345678
raw = f"{random_num}${m.group(1)}${CFG['user_id']}${CFG['stb_id']}${client.local_ip}${CFG['mac']}${CFG['custom_str']}"
auth = des_encrypt(raw, CFG["encrypt_key"])
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={CFG['eas_ip']}&ipVersion=4&networkid=1"
auth_data = (f"UserID={quote(CFG['user_id'])}&Authenticator={quote(auth)}&StbIP={quote(client.local_ip)}")
r = client.session.post(auth_url, data=auth_data, timeout=8)
body = r.content.decode("utf-8", errors="replace")
print("auth.jsp status:", r.status_code, "len:", len(body))
for kw in ["UserToken", "jsSetConfig", "error", "Error", "location", "location.href", "window.location", "Authenticator"]:
    idx = body.find(kw)
    if idx >= 0:
        print(f"--- {kw} @ {idx} ---")
        print(body[max(0, idx-200):idx+400])
        print()
