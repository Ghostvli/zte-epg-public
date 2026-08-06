#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变体测试：定位 requests 与 curl 的鉴权差异"""
import os, re, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_epg import des_encrypt, CFG, detect_local_ip
import requests

USER_ID = CFG["user_id"]; STB_ID = CFG["stb_id"]; MAC = CFG["mac"]
CUSTOM = CFG["custom_str"]; KEY = CFG["encrypt_key"]
EAS_IP = CFG["eas_ip"]; EAS_PORT = CFG["eas_port"]
local_ip = detect_local_ip()

VARIANTS = {
    "B_conn_close": {"Connection": "close"},
    "D_curl_ua_close": {"Connection": "close", "User-Agent": "curl/8.7.1"},
    "E_curl_ua": {"User-Agent": "curl/8.7.1"},
    "F_no_ae": {"Accept-Encoding": None},
    "G_no_conn": {"Connection": None},
}

def handshake(s):
    get_url = (f"http://{EAS_IP}:{EAS_PORT}/iptvepg/platform/getencrypttoken.jsp"
               f"?UserID={USER_ID}&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
    r = s.get(get_url, timeout=8)
    if r.status_code != 200:
        return None, None
    body = r.content.decode("utf-8", errors="replace")
    ch = re.search(r"GetAuthInfo\('(.*?)'\)", body)
    host = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', body)
    return (ch.group(1) if ch else None), (host.group(1) if host else None)

def login(s):
    ch, host = handshake(s)
    if not (ch and host):
        return "handshake_fail"
    base = f"http://{host}:8080"
    rn = random.randint(10000000, 99999999)
    raw = f"{rn}${ch}${USER_ID}${STB_ID}${local_ip}${MAC}${CUSTOM}"
    auth = des_encrypt(raw, KEY)
    auth_url = f"{base}/iptvepg/platform/auth.jsp?easip={EAS_IP}&ipVersion=4&networkid=1"
    data = f"UserID={USER_ID}&Authenticator={auth}&StbIP={local_ip}"
    r = s.post(auth_url, data=data, timeout=8)
    body = r.content.decode("utf-8", errors="replace")
    tok = re.search(r"jsSetConfig\('UserToken','([^']+)'", body) or re.search(r"UserToken=([A-Za-z0-9_.\-]+)", body)
    if tok:
        return "OK " + tok.group(1)
    err = re.search(r"errorcode=(\d+)", body)
    return "FAIL " + (err.group(1) if err else "?")

for name, hdrs in VARIANTS.items():
    s = requests.Session()
    s.headers.update({"Accept-Language": "zh-CN,en-US;q=0.8",
                      "X-Requested-With": "com.android.smart.terminal.iptv"})
    for k, v in hdrs.items():
        if v is None:
            s.headers.pop(k, None)
        else:
            s.headers[k] = v
    try:
        res = login(s)
    except Exception as e:
        res = f"EXC {e}"
    print(f"{name}: {res}", flush=True)
    time.sleep(4)
