#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""深入调试：打印 handshake 与 auth.jsp 全文"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import ZteEpgClient, des_encrypt, CFG, log
from urllib.parse import quote

client = ZteEpgClient()
log(f"localIp={client.local_ip}")
eas = f"http://{CFG['eas_ip']}:{CFG['eas_port']}"
get_url = (f"{eas}/iptvepg/platform/getencrypttoken.jsp?UserID={quote(CFG['user_id'])}"
           f"&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
handshake = client._get(get_url)
print("=== HANDSHAKE FULL (%d) ===" % len(handshake or ""))
print(handshake)
m = re.search(r"GetAuthInfo\('(.*?)'\)", handshake or "")
m2 = re.search(r'<form\s+action="([^"]+)"', handshake or "")
print("=== FORM ACTION ===", m2.group(1) if m2 else None)
m3 = re.search(r'<form[\s\S]*?</form>', handshake or "")
if m3:
    print("=== FORM BLOCK ===")
    print(m3.group(0))
if not (m and m2):
    sys.exit(1)
base = f"http://{m2.group(1).split('/')[2].split(':')[0]}:8080" if '//' in m2.group(1) else f"http://{m2.group(1).split(':')[0]}:8080"
random_num = 12345678
raw = f"{random_num}${m.group(1)}${CFG['user_id']}${CFG['stb_id']}${client.local_ip}${CFG['mac']}${CFG['custom_str']}"
auth = des_encrypt(raw, CFG["encrypt_key"])
print("=== AUTHENTICATOR ===", auth)
print("=== RAW ===", raw)
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={CFG['eas_ip']}&ipVersion=4&networkid=1"
auth_data = (f"UserID={quote(CFG['user_id'])}&Authenticator={quote(auth)}&StbIP={quote(client.local_ip)}")
r = client.session.post(auth_url, data=auth_data, timeout=8)
body = r.content.decode("utf-8", errors="replace")
print("=== AUTH RESP FULL (%d) ===" % len(body))
print(body)
