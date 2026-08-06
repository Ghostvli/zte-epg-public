#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
运营商（山东联通/中兴 IPTV）EPG 公共化采集器
将运营商 EPG（getchannelprogram）拉取后转为标准 XMLTV 格式，供任意支持 XMLTV 的软件使用。

鉴权流程移植自 FongMi/ZTESpider（3 步鉴权：getencrypttoken -> auth.jsp -> funcportalauth）。
凭证通过环境变量注入（GitHub Actions Secrets），绝不硬编码进仓库。

环境变量:
  ZTE_EAS_IP          鉴权网关 IP（默认 124.132.240.38）
  ZTE_EAS_PORT        鉴权网关端口（默认 8080）
  ZTE_ENCRYPT_KEY     DES 加密密钥
  ZTE_USER_ID         用户 ID
  ZTE_STB_ID          机顶盒 ID
  ZTE_MAC             机顶盒 MAC
  ZTE_MODEL           机顶盒型号
  ZTE_CUSTOM_STR      自定义串（默认 $CTC）
  ZTE_OUTPUT_DIR      输出目录（默认当前目录）
  ZTE_DAYS            拉取天数（默认 7）
  ZTE_MAX_CONCURRENCY 并发数（默认 10）
"""
import gzip
import json
import os
import random
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import quote

import requests

from Crypto.Cipher import DES

# ─────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────
CFG = {
    "eas_ip": os.environ.get("ZTE_EAS_IP", "124.132.240.38"),
    "eas_port": os.environ.get("ZTE_EAS_PORT", "8080"),
    "encrypt_key": os.environ.get("ZTE_ENCRYPT_KEY", ""),
    "user_id": os.environ.get("ZTE_USER_ID", ""),
    "stb_id": os.environ.get("ZTE_STB_ID", ""),
    "mac": os.environ.get("ZTE_MAC", ""),
    "model": os.environ.get("ZTE_MODEL", ""),
    "custom_str": os.environ.get("ZTE_CUSTOM_STR", "$CTC"),
    "out_dir": os.environ.get("ZTE_OUTPUT_DIR", "."),
    "days": int(os.environ.get("ZTE_DAYS", "7")),
    "concurrency": int(os.environ.get("ZTE_MAX_CONCURRENCY", "10")),
}
EPG_MAX_SIZE = 50 * 1024 * 1024  # 50MB，超过保留最近 3 天
HEADERS = {
    "Accept-Language": "zh-CN,en-US;q=0.8",
    "X-Requested-With": "com.android.smart.terminal.iptv",
}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def detect_local_ip() -> str:
    """对齐 detectLocalIp：TCP 连接 easIp 拿本地源 IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((CFG["eas_ip"], int(CFG["eas_port"])))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def des_encrypt(s: str, key: str) -> str:
    """对齐 desEncrypt：key 补 0 到 8 字节，PKCS5 填充，DES/ECB/NoPadding，输出大写 hex"""
    while len(key) < 8:
        key += "0"
    key_b = key.encode("utf-8")
    src = s.encode("utf-8")
    length = ((len(src) // 8) + 1) * 8
    pad = length - len(src)
    data = src + bytes([pad]) * pad
    cipher = DES.new(key_b, DES.MODE_ECB)
    return cipher.encrypt(data).hex().upper()


def decode_resp(resp: requests.Response) -> str:
    """按 Content-Type 检测编码（GBK/GB2312），对齐 Java 实现"""
    ct = resp.headers.get("Content-Type", "")
    if "gbk" in ct.lower() or "gb2312" in ct.lower():
        return resp.content.decode("gbk", errors="replace")
    return resp.content.decode("utf-8", errors="replace")


class ZteEpgClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.base = None
        self.user_token = None
        self.local_ip = detect_local_ip()
        self.authed = False
        self._lock = threading.Lock()

    def _get(self, url, timeout=8):
        try:
            r = self.session.get(url, timeout=timeout)
            if r.status_code != 200:
                log(f"GET {url[:120]} -> {r.status_code}")
                return None
            return decode_resp(r)
        except Exception as e:
            log(f"GET error {url[:120]}: {e}")
            return None

    def _post(self, url, data, timeout=8):
        try:
            # requests 对字符串 data 不自动加 Content-Type，运营商服务器缺失即返回 50991006
            r = self.session.post(url, data=data, timeout=timeout,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r.status_code != 200:
                log(f"POST {url[:120]} -> {r.status_code}")
                return None
            return decode_resp(r)
        except Exception as e:
            log(f"POST error {url[:120]}: {e}")
            return None

    def login(self) -> bool:
        """3 步鉴权：getencrypttoken -> auth.jsp -> funcportalauth"""
        eas = f"http://{CFG['eas_ip']}:{CFG['eas_port']}"
        # 1. 握手拿 challengeCode + epgHost
        get_url = (f"{eas}/iptvepg/platform/getencrypttoken.jsp?UserID={quote(CFG['user_id'])}"
                   f"&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=")
        handshake = self._get(get_url)
        if not handshake:
            log("login: handshake failed")
            return False
        m = re.search(r"GetAuthInfo\('(.*?)'\)", handshake)
        if not m:
            log("login: no GetAuthInfo")
            return False
        challenge = m.group(1)
        m2 = re.search(r'<form\s+action="http://([^/]+):\d+/iptvepg/platform/auth\.jsp', handshake)
        if not m2:
            log("login: no auth.jsp host")
            return False
        self.base = f"http://{m2.group(1)}:8080"

        # 2. DES 加密鉴权
        random_num = random.randint(10000000, 99999999)
        raw = f"{random_num}${challenge}${CFG['user_id']}${CFG['stb_id']}${self.local_ip}${CFG['mac']}${CFG['custom_str']}"
        auth = des_encrypt(raw, CFG["encrypt_key"])
        auth_url = f"{self.base}/iptvepg/platform/auth.jsp?easip={CFG['eas_ip']}&ipVersion=4&networkid=1"
        auth_data = (f"UserID={quote(CFG['user_id'])}&Authenticator={quote(auth)}&StbIP={quote(self.local_ip)}")
        auth_resp = self._post(auth_url, auth_data)
        if not auth_resp:
            log("login: auth.jsp failed")
            return False
        if os.environ.get("ZTE_DEBUG"):
            log(f"DEBUG auth.jsp resp: {auth_resp[:500]}")
        m3 = re.search(r"jsSetConfig\('UserToken','([^']+)'", auth_resp)
        if m3:
            self.user_token = m3.group(1)
        else:
            m4 = re.search(r"UserToken=([A-Za-z0-9_.\-]+)", auth_resp)
            if not m4:
                log("login: no UserToken")
                return False
            self.user_token = m4.group(1)
        m5 = re.search(r"window\.location\s*=\s*'(http[^']+)'", auth_resp)
        if m5:
            self._get(m5.group(1))

        # 3. portal 鉴权
        portal_url = f"{self.base}/iptvepg/function/funcportalauth.jsp"
        portal_data = (f"UserToken={quote(self.user_token)}&UserID={quote(CFG['user_id'])}"
                       f"&STBID={quote(CFG['stb_id'])}&stbinfo=&prmid=&easip={quote(CFG['eas_ip'])}"
                       f"&networkid=1&stbtype={quote(CFG['model'])}&drmsupplier=")
        portal_resp = self._post(portal_url, portal_data)
        if portal_resp and ("errorHandler" in portal_resp or "ErrorCode" in portal_resp):
            log("login: portal error")
            return False
        self._get(f"{self.base}/iptvepg/function/frame.jsp")
        self._post(f"{self.base}/iptvepg/function/frameset_judger.jsp", "picturetype=1%2C3%2C5")
        self._get(f"{self.base}/iptvepg/frame205/channel_start.jsp?tempno=-1")
        self.authed = True
        log(f"login ok base={self.base} localIp={self.local_ip}")
        return True

    def get_channel_list_html(self):
        """frameset_builder.jsp 返回频道列表 HTML"""
        self._get(f"{self.base}/iptvepg/function/frame.jsp")
        self._post(f"{self.base}/iptvepg/function/frameset_judger.jsp", "picturetype=1%2C3%2C5")
        data = (f"MAIN_WIN_SRC={quote('/iptvepg/frame205/channel_start.jsp?tempno=-1', safe='')}"
                f"&NEED_UPDATE_STB=1&BUILD_ACTION=FRAMESET_BUILDER&hdmistatus=")
        return self._post(f"{self.base}/iptvepg/function/frameset_builder.jsp", data)

    def parse_channels(self, html):
        """正则解析 jsSetConfig('Channel', ...) 频道条目"""
        channels = []
        pat = re.compile(
            r"jsSetConfig\('Channel','ChannelID=\"([^\"]+)\",ChannelName=\"([^\"]+)\""
            r",UserChannelID=\"([^\"]+)\",ChannelURL=\"([^\"]+)\""
            r",TimeShift=\"([^\"]+)\",ChannelSDP=\"([^\"]*)\""
            r",TimeShiftURL=\"([^\"]*)\""
        )
        cctv5 = 0
        for m in pat.finditer(html):
            ch_id, name, _, url, _, sdp, _ = m.groups()
            if "CCTV5" in name and "CCTV5+" not in name:
                cctv5 += 1
                if cctv5 == 2:
                    name = "CCTV5+"
            rtsp = None
            if sdp:
                for part in sdp.split("|"):
                    if part.startswith("rtsp://"):
                        rtsp = part
                        break
            if rtsp is None and url.startswith("rtsp://"):
                rtsp = url
            if ch_id:
                channels.append({"id": ch_id, "name": name})
        return channels

    def fetch_channel_epg(self, ch_id, date_str):
        """拉单个频道单天 EPG，空则重试一次"""
        url = (f"{self.base}/iptvepg/frame205/action/getchannelprogram.jsp"
               f"?channelcode={quote(ch_id)}&currdate={quote(date_str)}")
        result = self._get(url)
        if not result:
            log(f"epg retry: {ch_id} {date_str}")
            result = self._get(url)
        return result

    def fetch_all_epg(self, channels):
        """并发拉取全部频道 7 天 EPG，返回 {channelId: [programme,...]}"""
        result = {}
        result_lock = threading.Lock()
        today = datetime.now()
        dates = [(today - timedelta(days=6 - i)).strftime("%Y.%m.%d") for i in range(CFG["days"])]
        log(f"fetch_all_epg: {len(channels)} channels x {len(dates)} dates")
        start = time.time()

        def work(ch):
            cc = ch["id"]
            for dt in dates:
                try:
                    raw = self.fetch_channel_epg(cc, dt)
                    if not raw:
                        continue
                    j = fix_js_object_json(raw)
                    obj = json.loads(j)
                    arr = obj.get("prevuelist") or []
                    if arr:
                        with result_lock:
                            result.setdefault(cc, []).extend(arr)
                except Exception as e:
                    log(f"parse error {cc} {dt}: {e}")

        with ThreadPoolExecutor(max_workers=CFG["concurrency"]) as pool:
            futures = [pool.submit(work, ch) for ch in channels]
            try:
                for f in as_completed(futures, timeout=90):
                    try:
                        f.result()
                    except Exception as e:
                        log(f"task error: {e}")
            except TimeoutError:
                log("fetch_all_epg: 90s timeout, partial data")
            # awaitTermination 25s
            for f in futures:
                try:
                    f.result(timeout=25)
                except Exception:
                    pass

        by_date = {}
        for progs in result.values():
            for p in progs:
                bt = p.get("begintime", "")
                if len(bt) >= 10:
                    by_date[bt[:10]] = by_date.get(bt[:10], 0) + 1
        log(f"fetch_all_epg: {len(result)} channels, byDate={dict(sorted(by_date.items()))}, took={time.time()-start:.0f}s")
        return result

    def convert_to_xmltv(self, epg_data, channels):
        """转 XMLTV：channel + programme，时间 yyyyMMddHHmmss +0800"""
        out = ['<?xml version="1.0" encoding="UTF-8"?>\n<tv>\n']
        for ch in channels:
            if not ch["id"]:
                continue
            out.append(f'<channel id="{xml_escape(ch["id"])}">')
            out.append(f'<display-name>{xml_escape(ch["name"])}</display-name>')
            out.append("</channel>\n")
        for ch in channels:
            if not ch["id"]:
                continue
            progs = epg_data.get(ch["id"])
            if not progs:
                continue
            for p in progs:
                bt, et, name = p.get("begintime", ""), p.get("endtime", ""), p.get("prevuename", "")
                if not (bt and et and name):
                    continue
                try:
                    start_dt = datetime.strptime(bt, "%Y.%m.%d %H:%M:%S")
                    stop_dt = datetime.strptime(et, "%Y.%m.%d %H:%M:%S")
                except Exception:
                    continue
                start_str = start_dt.strftime("%Y%m%d%H%M%S") + " +0800"
                stop_str = stop_dt.strftime("%Y%m%d%H%M%S") + " +0800"
                cid = p.get("contentid", "")
                prog = f'<programme start="{start_str}" stop="{stop_str}" channel="{xml_escape(ch["id"])}"'
                if cid:
                    prog += f' ContentID="{xml_escape(cid)}"'
                prog += f'><title lang="zh">{xml_escape(name)}</title></programme>\n'
                out.append(prog)
        out.append("</tv>")
        xmltv = "".join(out)

        if len(xmltv.encode("utf-8")) > EPG_MAX_SIZE:
            log(f"XMLTV too large, keeping recent 3 days")
            recent = [(datetime.now() - timedelta(days=i)).strftime("%Y.%m.%d") for i in range(3)]
            out = ['<?xml version="1.0" encoding="UTF-8"?>\n<tv>\n']
            for ch in channels:
                if not ch["id"]:
                    continue
                out.append(f'<channel id="{xml_escape(ch["id"])}">')
                out.append(f'<display-name>{xml_escape(ch["name"])}</display-name>')
                out.append("</channel>\n")
            for ch in channels:
                if not ch["id"]:
                    continue
                progs = epg_data.get(ch["id"])
                if not progs:
                    continue
                for p in progs:
                    bt, et, name = p.get("begintime", ""), p.get("endtime", ""), p.get("prevuename", "")
                    if not (bt and et and name) or bt[:10] not in recent:
                        continue
                    try:
                        start_dt = datetime.strptime(bt, "%Y.%m.%d %H:%M:%S")
                        stop_dt = datetime.strptime(et, "%Y.%m.%d %H:%M:%S")
                    except Exception:
                        continue
                    cid = p.get("contentid", "")
                    prog = (f'<programme start="{start_dt.strftime("%Y%m%d%H%M%S")} +0800" '
                            f'stop="{stop_dt.strftime("%Y%m%d%H%M%S")} +0800" channel="{xml_escape(ch["id"])}"')
                    if cid:
                        prog += f' ContentID="{xml_escape(cid)}"'
                    prog += f'><title lang="zh">{xml_escape(name)}</title></programme>\n'
                    out.append(prog)
            out.append("</tv>")
            xmltv = "".join(out)
        return xmltv


def fix_js_object_json(s: str) -> str:
    """修复非标准 JS 对象：顶层 key 加引号"""
    s = s.strip()
    if not s.startswith("{") or s.startswith('{"'):
        return s
    fixed = re.sub(r"(\{|,)(\w+)\s*:", r'\1"\2":', s)
    try:
        json.loads(fixed)
        return fixed
    except Exception:
        return s


def xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def count_by_date(xmltv: str) -> dict:
    m = re.findall(r'<programme start="(\d{8})', xmltv)
    d = {}
    for k in m:
        d[k] = d.get(k, 0) + 1
    return dict(sorted(d.items()))


def main():
    if not CFG["encrypt_key"] or not CFG["user_id"]:
        log("ERROR: ZTE_ENCRYPT_KEY / ZTE_USER_ID 未设置")
        sys.exit(2)
    os.makedirs(CFG["out_dir"], exist_ok=True)

    client = ZteEpgClient()
    if not client.login():
        log("ERROR: 鉴权失败")
        sys.exit(1)

    html = client.get_channel_list_html()
    if not html:
        log("ERROR: 频道列表为空")
        sys.exit(1)
    channels = client.parse_channels(html)
    log(f"parsed {len(channels)} channels")
    if not channels:
        log("ERROR: 无频道可拉取")
        sys.exit(1)

    epg_data = client.fetch_all_epg(channels)
    if not epg_data:
        log("ERROR: 未拉取到任何 EPG")
        sys.exit(1)

    xmltv = client.convert_to_xmltv(epg_data, channels)
    out_path = os.path.join(CFG["out_dir"], "epg.xml")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(xmltv)
    with gzip.open(out_path + ".gz", "wt", encoding="utf-8") as f:
        f.write(xmltv)
    log(f"written {out_path} ({len(xmltv.encode('utf-8'))} bytes)")
    by_date = count_by_date(xmltv)
    log(f"programme byDate={by_date}")
    if len(by_date) < CFG["days"]:
        log(f"WARNING: 只有 {len(by_date)}/{CFG['days']} 天数据，不完整")
    else:
        log("OK: 数据完整")


if __name__ == "__main__":
    main()
