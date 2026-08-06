#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实验：用握手页面返回的 StbIP 做鉴权"""
import os, re, sys, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import ZteEpgClient, des_encrypt, CFG, log
from urllib.parse import quote

client = ZteEpgClient()
client.session.headers["Accept-Encoding"] = "identity"
eas = f"http://{CFG['eas_ip']}:{CFG['eas_port']}"
get_url = (f"{eas}/iptvepg/platform/getencrypttoken.jsp?UserID={quote(CFG['user_id'])}"
           f"&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
handshake = client._get(get_url)
m = re.search(r"GetAuthInfo\('(.*?)'\)", handshake or "")
m2 = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', handshake or "")
m3 = re.search(r'name="StbIP" value="([^"]+)"', handshake or "")
if not (m and m2):
    log("no challenge/host"); sys.exit(1)
srv_ip = m3.group(1) if m3 else client.local_ip
log(f"server StbIP={srv_ip} (local={client.local_ip})")
base = f"http://{m2.group(1)}:8080"
random_num = random.randint(10000000, 99999999)
raw = f"{random_num}${m.group(1)}${CFG['user_id']}${CFG['stb_id']}${srv_ip}${CFG['mac']}${CFG['custom_str']}"
auth = des_encrypt(raw, CFG["encrypt_key"])
auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={CFG['eas_ip']}&ipVersion=4&networkid=1"
auth_data = (f"UserID={quote(CFG['user_id'])}&Authenticator={quote(auth)}&StbIP={quote(srv_ip)}")
r = client.session.post(auth_url, data=auth_data, timeout=8)
body = r.content.decode("utf-8", errors="replace")
if "50991006" in body or "errorcode" in body:
    log("FAIL: " + re.search(r"errorcode=(\d+)", body).group(1) if re.search(r"errorcode=(\d+)", body) else "fail")
    m5 = re.search(r"jsSetConfig\('UserToken','([^']+)'", body)
    log("UserToken=" + m5.group(1) if m5 else "no UserToken")
else:
    m5 = re.search(r"jsSetConfig\('UserToken','([^']+)'", body)
    log("SUCCESS UserToken=" + (m5.group(1) if m5 else "?"))
    log("len=" + str(len(body)))
