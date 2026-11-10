#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""wpsedu - WPS 教学平台 (edu study-platform) 通用刷课工具

账号（多账号，任意账号）
  python wpsedu.py login-browser --account NAME                  # 工具自开浏览器，登录后自动取走 cookie（不用关窗）
  python wpsedu.py import-cookies --from edge --account NAME     # 从已关闭的 Edge/Chrome 直接读登录态
  python wpsedu.py add-account 小明 --cookie-file d:\\ck.json     # 注册一份导出的 cookies.json
  python wpsedu.py accounts                                     # 列出所有账号（含昵称/组织/课程数）
  python wpsedu.py rm-account 小明

刷课
  python wpsedu.py courses   [--account NAME]                   # 我的课程
  python wpsedu.py status    [--account NAME] [--course KW]     # 完成情况
  python wpsedu.py finish    [--account NAME] [--course KW] [--all] [--dry-run]
  python wpsedu.py login     [--account NAME]                   # 刷新 token
  --account NAME 也可写在子命令前: python wpsedu.py --account NAME finish
  login-browser 的 profile 被占用时会自动换一个干净 profile 重开

常用参数
  --account NAME      账号名（省略且只存在一个账号时自动选中）
  --package ID        直接指定 packageId
  --course KW         课程标题关键字
  --skip-types 9      跳过的 resourceType，默认 9 = 可评分/测验（进度上报无效）
  --workers 24        视频并发窗口数
  --log FILE          逐条结果写文件

接口（2026-11 逆向，纯 Cookie + X-Edu-Token，无加密层）
  认证   POST https://api-kos.wps.cn/study/user/account/login  {"identity":null} -> data.token
  课程   POST /study/user/course/roll   {"courseType":1,"courseStatus":1,"pageSize":50}
  课程树 GET  /study/user/course/detail?packageId=N
  上报   POST /study/user/course/resource/progress
         文档  {chapterId, chapterName, resourceType}                一次即完成
         视频  另加 {lastPos, currentPos, speed, duration}
               服务器按 5 秒分片累计"位置覆盖"，单次最多认领 20 秒窗口，
               覆盖率达 80% 时 completed 置位并永久锁定；分片不要求顺序，
               所以把时间轴切成 20 秒窗口并发发出，一两秒顶完整段视频。
状态 learnStatus: 0=未学习 1=已完成 2=学习中
"""
import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://api-kos.wps.cn/study"
ORIGIN = "https://edu.wps.cn"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0")

HERE = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DIR = os.path.join(HERE, "accounts")
DONE = 1
VIDEO = 6
STEP = 20
CALL_CAP = 400
AUTH_DOMAIN_HINTS = ("wps.cn", "kdocs.cn", "qwps.cn")


# ---------------------------------------------------------------- DPAPI / AES

class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_decrypt(data):
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


KEY_FILES = ("Local State", "LocalPrefs.json")


def local_state_key(user_data_dir):
    """cookie 主密钥：DPAPI(Local State / LocalPrefs.json 里 os_crypt.encrypted_key[5:])

    WPS 的 CEF 把同一份结构写在 LocalPrefs.json，而且放在 cache 目录的上层，
    所以从给定目录往上找几层。
    """
    cur = os.path.abspath(user_data_dir)
    for _ in range(6):
        for name in KEY_FILES:
            path = os.path.join(cur, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    state = json.load(f)
            except (OSError, ValueError):
                continue
            enc = (state.get("os_crypt") or {}).get("encrypted_key")
            if not enc:
                continue
            raw = base64.b64decode(enc)
            if raw[:5] == b"DPAPI":
                raw = raw[5:]
            return dpapi_decrypt(raw)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    raise SystemExit("在 %s 及其上层都没找到 os_crypt.encrypted_key" % user_data_dir)


def decrypt_cookie_value(enc, key, host=None):
    """解密 encrypted_value，返回原始字节；无法解密抛 ValueError。

    新版 Chromium 把 host_key 作为 AES-GCM 的 AAD，旧版没有，两种都试。
    """
    if not enc:
        return b""
    if enc[:3] in (b"v10", b"v11"):
        payload = enc[3:]
        if len(payload) < 12 + 16:
            raise ValueError("payload 太短")
        nonce, rest = payload[:12], payload[12:]
        ct, tag = rest[:-16], rest[-16:]
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aead = AESGCM(key)
        aads = []
        if host:
            aads.append(host.encode("utf-8"))
        aads.append(None)
        last = None
        for aad in aads:
            try:
                return aead.decrypt(nonce, ct + tag, aad)
            except Exception as e:                              # noqa: BLE001
                last = e
        raise ValueError("AES-GCM 解密失败（key 不匹配）: %s" % last)
    if enc[:3] == b"v20":
        raise ValueError("v20（App-Bound 加密）无法离线解密，请改用 login-browser")
    if enc[:4] == b"\x01\x00\x00\x00":
        return dpapi_decrypt(enc)
    try:
        return dpapi_decrypt(enc)
    except OSError:
        raise ValueError("未知的 encrypted_value 格式（前缀 %r）" % enc[:3])


def cookie_value_text(raw):
    """Chromium 新版在明文前加了 32 字节绑定头，去掉后取 ASCII 值。"""
    if raw is None:
        return None

    def printable(b):
        return all(0x20 <= c <= 0x7E for c in b)

    if len(raw) > 32 and not printable(raw[:32]) and printable(raw[32:]):
        raw = raw[32:]
    if printable(raw):
        return raw.decode("ascii")
    return None


# ---------------------------------------------------------------- 浏览器 cookies

CHROMIUM_ROOTS = {
    "edge": [r"%LOCALAPPDATA%\Microsoft\Edge\User Data"],
    "chrome": [r"%LOCALAPPDATA%\Google\Chrome\User Data"],
    "brave": [r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"],
    "wps": [r"%APPDATA%\kingsoft\wps_international\addons\data\win-x64\cef"],
}


def expand(p):
    return os.path.expandvars(os.path.expanduser(p))


def find_profiles(family):
    """返回 [(user_data_dir, profile_dir, 标签)]"""
    out = []
    roots = CHROMIUM_ROOTS.get(family, [])
    if family not in CHROMIUM_ROOTS or family == "wps":
        roots = roots + [os.path.abspath(family)]  # 也允许直接给路径
    for root in roots:
        root = expand(root)
        db_cookie = os.path.join(root, "Network", "Cookies")
        if os.path.isfile(db_cookie):                     # 直接给到 profile 目录
            out.append((root, root, os.path.basename(root)))
            continue
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            prof = os.path.join(root, name)
            ck = os.path.join(prof, "Network", "Cookies")
            if os.path.isfile(ck):
                out.append((root, prof, name))
    return out


def read_profile_cookies(user_data_dir, profile_dir, hosts=AUTH_DOMAIN_HINTS):
    key = None
    keyerr = None
    try:
        key = local_state_key(user_data_dir)
    except (SystemExit, OSError, ValueError) as e:
        keyerr = e
    src = os.path.join(profile_dir, "Network", "Cookies")
    if not os.path.isfile(src):
        src = os.path.join(profile_dir, "Cookies")
    tmpdir = tempfile.mkdtemp(prefix="wpsedu-ck-")
    tmp = os.path.join(tmpdir, "Cookies")
    try:
        shutil.copyfile(src, tmp)
    except PermissionError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise SystemExit(
            "读不到 %s（浏览器正独占该文件）。\n"
            "  办法一：完全退出该浏览器后重试\n"
            "  办法二：用  python wpsedu.py login-browser --account NAME "
            "（工具自己开一个独立浏览器让你扫码登录，关窗口即自动取到 cookie）" % src)
    con = sqlite3.connect("file:%s?immutable=1" % tmp.replace("\\", "/"), uri=True)
    rows = con.execute(
        "select host_key,name,value,encrypted_value,path from cookies").fetchall()
    con.close()
    shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)

    out, skipped = [], []
    for host, name, value, enc, path in rows:
        bare = (host or "").lstrip(".")
        if hosts and not any(bare == h or bare.endswith("." + h) for h in hosts):
            continue
        val = None
        if enc:
            try:
                raw = decrypt_cookie_value(bytes(enc), key, host) if key else None
                val = cookie_value_text(raw)
                if not val:
                    skipped.append((host, name, "解密结果非 ASCII（%s）" % (keyerr or "格式未知")))
                    continue
            except ValueError as e:
                skipped.append((host, name, str(e)))
                continue
            except Exception as e:                              # noqa: BLE001
                skipped.append((host, name, "%s: %s" % (type(e).__name__, e)))
                continue
        if not val:
            val = value or ""
        if not val:
            continue
        if any(ord(ch) > 0xFF for ch in val):
            skipped.append((host, name, "值含非 ASCII 字符"))
            continue
        out.append({"name": name, "value": val, "domain": host, "path": path or "/"})
    return out, skipped


# ---------------------------------------------------------------- 账号

class Accounts:
    def __init__(self, root=ACCOUNTS_DIR):
        self.root = root

    def names(self):
        names = []
        if os.path.isdir(self.root):
            for n in sorted(os.listdir(self.root)):
                if os.path.isfile(os.path.join(self.root, n, "cookies.json")):
                    names.append(n)
        legacy = os.path.join(HERE, "cookies.json")
        if os.path.isfile(legacy) and "default" not in names:
            names.insert(0, "default")
        return names

    def cookie_file(self, name):
        if name == "default":
            return os.path.join(HERE, "cookies.json")
        return os.path.join(self.root, name, "cookies.json")

    def token_file(self, name):
        if name == "default":
            return os.path.join(HERE, "edu-token.json")
        return os.path.join(self.root, name, "token.json")

    def save(self, name, cookies):
        d = os.path.join(self.root, name)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "cookies.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cookies, f, ensure_ascii=False, indent=1)
        return path

    def remove(self, name):
        d = os.path.join(self.root, name)
        if name == "default" or not os.path.isdir(d):
            raise SystemExit("不能删除 %s" % name)
        shutil.rmtree(d)
        return d

    def pick(self, want):
        names = self.names()
        if want:
            if want not in names:
                raise SystemExit("没有账号 %r，已有: %s" % (want, ", ".join(names) or "(空)"))
            return want
        if not names:
            raise SystemExit("还没有账号。用 import-cookies 或 add-account 添加一个。")
        if len(names) == 1:
            return names[0]
        print("存在多个账号，请用 --account 指定:")
        for n in names:
            print("   ", n)
        raise SystemExit(1)


# ---------------------------------------------------------------- 请求封装

class Client:
    def __init__(self, cookie_file, token_file):
        self.cookie_file = cookie_file
        self.token_file = token_file
        self._cookies = None
        self.token = None

    def cookies(self):
        if self._cookies is None:
            with open(self.cookie_file, encoding="utf-8") as f:
                self._cookies = json.load(f)
        return self._cookies

    def cookie_header(self, host):
        parts = []
        for c in self.cookies():
            dom = (c.get("domain") or "").lstrip(".")
            if not dom or host == dom or host.endswith("." + dom):
                parts.append("%s=%s" % (c.get("name"), c.get("value")))
        return "; ".join(parts)

    def _send(self, method, url, body=None, token=None, timeout=30):
        host = urllib.parse.urlparse(url).hostname or ""
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
            "Cookie": self.cookie_header(host),
        }
        if token:
            headers["X-Edu-Token"] = token
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            return 0, str(e).encode()

    def login(self, force=True):
        if not force and self.token:
            return self.token
        st, raw = self._send("POST", BASE + "/user/account/login", {"identity": None})
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise SystemExit("login 返回非 JSON（http=%s）: %r" % (st, raw[:200]))
        tok = (data.get("data") or {}).get("token")
        if not tok:
            raise SystemExit("login 失败: %s" % json.dumps(data, ensure_ascii=False)[:300])
        self.token = tok
        try:
            with open(self.token_file, "w", encoding="utf-8") as f:
                json.dump({"token": tok, "ts": time.time()}, f)
        except OSError:
            pass
        return tok

    def load_token(self):
        if self.token:
            return self.token
        try:
            with open(self.token_file, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("token"):
                self.token = d["token"]
                return self.token
        except (OSError, ValueError):
            pass
        return self.login()

    def api(self, method, path, body=None, params=None, retries=2):
        tok = self.load_token()
        url = path if path.startswith("http") else BASE + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        st, j = 0, {}
        for attempt in range(retries + 1):
            st, raw = self._send(method, url, body, tok)
            text = raw.decode("utf-8", "replace")
            try:
                j = json.loads(text)
            except ValueError:
                j = {"_raw": text[:400]}
            bad = st in (401, 403) or (isinstance(j, dict) and j.get("code") in (401, 403))
            if bad and attempt < retries:
                tok = self.login(force=True)
                continue
            return st, j
        return st, j


# ---------------------------------------------------------------- 平台操作

def list_courses(cli):
    st, j = cli.api("POST", "/user/course/roll",
                    body={"courseType": 1, "courseStatus": 1, "pageSize": 50})
    if j.get("code") != 1:
        raise SystemExit("取课程列表失败: %s %s" % (st, json.dumps(j, ensure_ascii=False)[:200]))
    return (j.get("data") or {}).get("list") or []


def course_tree(cli, package_id):
    st, j = cli.api("GET", "/user/course/detail", params={"packageId": package_id})
    if j.get("code") != 1:
        raise SystemExit("取课程树失败: %s %s" % (st, json.dumps(j, ensure_ascii=False)[:200]))
    return j["data"]


def leaves_of(course):
    out = []

    def walk(node, path):
        if node.get("nodeType") == "file":
            out.append({"node": node, "path": path})
            return
        for c in node.get("subsets") or []:
            walk(c, path + [node.get("chapterName") or ""])

    for c in course.get("chapters") or []:
        walk(c, [])
    return out


def summarize(leaves):
    from collections import Counter
    c = Counter(l["node"].get("learnStatus") for l in leaves)
    total = len(leaves)
    done = c.get(DONE, 0)
    return total, done, dict(c)


def progress(cli, node, **extra):
    fi = node.get("fileInfo") or {}
    body = {"chapterId": node["chapterId"],
            "chapterName": node.get("chapterName") or "",
            "resourceType": fi.get("resourceType")}
    body.update(extra)
    st, j = cli.api("POST", "/user/course/resource/progress", body=body)
    return st, j, (j.get("data") or {})


def report_doc(cli, node):
    st, j, d = progress(cli, node)
    ok = st == 200 and j.get("code") == 1
    return ok, json.dumps(d or j, ensure_ascii=False)[:70]


def probe_video(cli, node):
    """返回 (True,None)=已完成 / (False,(总长秒,已看分片)) / (None,错误)"""
    st, j, d = progress(cli, node, lastPos=0, currentPos=STEP, speed=1, duration=STEP)
    if st != 200 or j.get("code") != 1 or not d:
        return None, "探测失败 %s" % json.dumps(j, ensure_ascii=False)[:100]
    if d.get("completed"):
        return True, None
    return False, ((d.get("totalSegments") or 0) * 5, d.get("watchedSegments"))


def bypass_video(cli, node, workers=24, rounds=3):
    total = None
    segs = None
    for _ in range(rounds):
        if total is None:
            ok, info = probe_video(cli, node)
            if ok is None:
                return False, info
            if ok:
                return True, "已完成"
            total, segs = info
            if not total:
                return False, "拿不到 totalSegments"
        wins = [(p, min(p + STEP, total)) for p in range(0, total, STEP)]
        out, lock, ths = [], threading.Lock(), []

        def worker(a, b):
            st, j, d = progress(cli, node, lastPos=a, currentPos=b, speed=1, duration=STEP)
            with lock:
                out.append((st, d))

        for a, b in wins:
            while sum(1 for t in ths if t.is_alive()) >= workers:
                time.sleep(0.01)
            t = threading.Thread(target=worker, args=(a, b))
            t.start()
            ths.append(t)
        for t in ths:
            t.join()
        good = [d for st, d in out if st == 200 and d]
        if good:
            best = max(good, key=lambda d: d.get("watchedSegments") or 0)
            segs = best.get("watchedSegments")
            if best.get("completed"):
                return True, "并发 %s/%s 分片 len=%ss" % (segs, best.get("totalSegments"), total)
            nt = (best.get("totalSegments") or 0) * 5
            if nt > total:
                total = nt
                continue
    return False, "未完成 seg=%s total=%s" % (segs, total)


def walk_video_sequential(cli, node, delay=0.12):
    pos, total, calls = 0, None, 0
    while calls < CALL_CAP:
        nxt = pos + STEP if total is None else min(pos + STEP, total)
        st, j, d = progress(cli, node, lastPos=pos, currentPos=nxt, speed=1, duration=STEP)
        calls += 1
        if st != 200 or j.get("code") != 1 or not d:
            return False, "顺序上报异常 http=%s" % st
        ts = (d.get("totalSegments") or 0) * 5
        if ts and (total is None or ts > total):
            total = ts
        if d.get("completed"):
            return True, "顺序 %d 次 %s/%s" % (calls, d.get("watchedSegments"), d.get("totalSegments"))
        pos = nxt
        if total and pos >= total:
            return False, "到尾未完成 %s/%s" % (d.get("watchedSegments"), d.get("totalSegments"))
        time.sleep(delay)
    return False, "超过调用上限"


def pick_course(cli, args):
    if args.package:
        return args.package
    courses = list_courses(cli)
    if not courses:
        raise SystemExit("该账号下没有进行中的课程")
    if args.course:
        hit = [c for c in courses if args.course in (c.get("title") or "")]
        if not hit:
            raise SystemExit("没有标题含 %r 的课程，可选: %s"
                             % (args.course, " / ".join(c.get("title") or "" for c in courses)))
        if len(hit) > 1:
            print("匹配多门课，用 --package 指定:")
            for c in hit:
                print("   %-6s %s" % (c.get("packageId"), c.get("title")))
            raise SystemExit(1)
        return hit[0]["packageId"]
    if len(courses) == 1:
        return courses[0]["packageId"]
    print("有多门课程，请用 --package 或 --course 指定:")
    for c in courses:
        print("   %-6s %-52s %s 项" % (c.get("packageId"), (c.get("title") or "")[:52], c.get("itemNum")))
    raise SystemExit(1)


# ---------------------------------------------------------------- 命令

def cmd_import(cli_args, acc):
    profiles = find_profiles(cli_args.source)
    if not profiles:
        raise SystemExit("在 %r 下没找到 cookie 库；可用 --from <UserData 路径>"
                         % cli_args.source)
    if cli_args.profile:
        profiles = [p for p in profiles if p[2].lower() == cli_args.profile.lower()]
        if not profiles:
            raise SystemExit("没有名为 %r 的 profile" % cli_args.profile)
    print("候选 profile:")
    for i, (ud, pd, label) in enumerate(profiles, 1):
        print("  %d) %-18s %s" % (i, label, pd))
    pick = profiles[0] if len(profiles) == 1 else None
    if pick is None:
        if cli_args.index:
            pick = profiles[cli_args.index - 1]
        else:
            raise SystemExit("有多个 profile，用 --index N 选一个（上表编号）")

    ud, pd, label = pick
    cookies, skipped = read_profile_cookies(ud, pd)
    print("从 %s 读到 %d 条相关 cookie" % (pd, len(cookies)))
    if skipped:
        print("  跳过 %d 条（无法解密），示例: %s" % (len(skipped), skipped[:3]))
    for want in ("wps_sid", "kso_sid", "csrf", "uid"):
        if not any(c["name"] == want for c in cookies):
            print("  注意: 缺少 %s，可能该 profile 没登录过平台" % want)
    name = cli_args.account or label
    path = acc.save(name, cookies)
    print("已存为账号 %r -> %s" % (name, path))


def cmd_add_account(args, acc):
    with open(args.cookie_file, encoding="utf-8") as f:
        cookies = json.load(f)
    if isinstance(cookies, dict) and "cookies" in cookies:
        cookies = cookies["cookies"]
    path = acc.save(args.account, cookies)
    print("已注册账号 %r（%d 条 cookie）-> %s" % (args.account, len(cookies), path))


def cmd_rm_account(args, acc):
    print("已删除:", acc.remove(args.account))


def cmd_accounts(args, acc):
    names = acc.names()
    if not names:
        print("还没有账号。用法: python wpsedu.py import-cookies --from edge --account NAME")
        return
    for n in names:
        c = Client(acc.cookie_file(n), acc.token_file(n))
        try:
            st, j = c.api("GET", "/user/account/userInfo")
            info = ((j.get("data") or {}).get("userInfo") or {})
            who = "%s / %s" % (info.get("name") or "?", info.get("orgName") or "?")
            st2, j2 = c.api("POST", "/user/course/roll",
                            body={"courseType": 1, "courseStatus": 1, "pageSize": 50})
            cnt = len(((j2.get("data") or {}).get("list") or []))
            extra = "%d 门课程" % cnt
        except SystemExit as e:
            who, extra = "登录失败: %s" % str(e)[:60], ""
        except Exception as e:                                  # noqa: BLE001
            who, extra = "%s: %s" % (type(e).__name__, str(e)[:50]), ""
        print("%-14s %-34s %s" % (n, who, extra))


def cmd_login(cli, args):
    print(cli.login(force=True))


def cmd_courses(cli, args):
    for c in list_courses(cli):
        print("%-6s %-52s %s 项  创建者 %s" % (c.get("packageId"), (c.get("title") or "")[:52],
                                              c.get("itemNum"), c.get("createName")))


def cmd_status(cli, args):
    pkg = pick_course(cli, args)
    course = course_tree(cli, pkg)
    leaves = leaves_of(course)
    total, done, dist = summarize(leaves)
    print("课程: %s  (packageId=%s)" % (course.get("title"), pkg))
    print("资源 %d | 已完成 %d | 未完成 %d | 状态分布 %s" % (total, done, total - done, dist))
    skip = set(args.skip_types)
    rest = [l["node"] for l in leaves if l["node"].get("learnStatus") != DONE]
    for n in rest[:40]:
        rt = (n.get("fileInfo") or {}).get("resourceType")
        print("  [%s] %-6s type=%-3s %s" % ("跳过" if rt in skip else "待办",
                                            n["chapterId"], rt, (n.get("chapterName") or "")[:48]))
    if len(rest) > 40:
        print("  ... 还有 %d 条" % (len(rest) - 40))


def finish_course(cli, pkg, skip_types, workers=24, rounds=3, retry_slow=False,
                  dry_run=False, log=print, on_item=None, should_stop=None):
    """刷完一门课；返回统计 dict。on_item(i, total, node, ok, note) 用于进度回调。"""
    course = course_tree(cli, pkg)
    leaves = leaves_of(course)
    total, done, dist = summarize(leaves)
    log("=== %s (packageId=%s) ===" % (course.get("title"), pkg))
    log("资源 %d | 已完成 %d | 未完成 %d | %s" % (total, done, total - done, dist))

    todo, skipped = [], 0
    for l in leaves:
        n = l["node"]
        if n.get("learnStatus") == DONE:
            continue
        if (n.get("fileInfo") or {}).get("resourceType") in skip_types:
            skipped += 1
            continue
        todo.append(n)
    if skipped:
        log("跳过 %d 条 resourceType %s（评分/测验类，进度上报无效）" % (skipped, sorted(skip_types)))
    log("待处理 %d 条" % len(todo))

    if dry_run:
        for n in todo[:20]:
            log("   - %-6s type=%-3s %s" % (n["chapterId"],
                                            (n.get("fileInfo") or {}).get("resourceType"),
                                            (n.get("chapterName") or "")[:46]))
        if len(todo) > 20:
            log("   ... 还有 %d 条" % (len(todo) - 20))
        return {"title": course.get("title"), "package": pkg, "total": total,
                "done": done, "ok": 0, "todo": len(todo), "stopped": False,
                "dist": dist, "dry_run": True}

    t0, ok, stopped = time.time(), 0, False
    for i, n in enumerate(todo, 1):
        if should_stop and should_stop():
            stopped = True
            log("已取消，剩余 %d 条未处理" % (len(todo) - i + 1))
            break
        rt = (n.get("fileInfo") or {}).get("resourceType")
        good, note = (bypass_video(cli, n, workers, rounds)
                      if rt == VIDEO else report_doc(cli, n))
        if not good and retry_slow and rt == VIDEO:
            good2, note2 = walk_video_sequential(cli, n)
            if good2:
                good, note = True, note2
        if good:
            ok += 1
        log("[%d/%d] %s %-26s %s" % (i, len(todo), "OK" if good else "NG", note,
                                     (n.get("chapterName") or "")[:36]))
        if on_item:
            on_item(i, len(todo), n, good, note)

    course = course_tree(cli, pkg)
    leaves = leaves_of(course)
    total, done, dist = summarize(leaves)
    log("本轮 ok=%d/%d  用时 %.0fs" % (ok, len(todo), time.time() - t0))
    log("复核: 已完成 %d/%d | %s" % (done, total, dist))
    return {"title": course.get("title"), "package": pkg, "total": total, "done": done,
            "ok": ok, "todo": len(todo), "stopped": stopped, "dist": dist}


def cmd_finish(cli, args):
    skip = set(args.skip_types)
    if args.all:
        pkgs = [c.get("packageId") for c in list_courses(cli)]
        if not pkgs:
            raise SystemExit("该账号下没有进行中的课程")
    else:
        pkgs = [pick_course(cli, args)]

    res = []
    for pkg in pkgs:
        res.append(finish_course(cli, pkg, skip, workers=args.workers, rounds=args.rounds,
                                 retry_slow=args.retry_slow, dry_run=args.dry_run,
                                 log=lambda m: print(m, flush=True)))
    if len(pkgs) > 1:
        print("\n合计成功 %d 条" % sum(r["ok"] for r in res))


class CDP:
    """极简 CDP over WebSocket（标准库实现，不依赖第三方 ws 库）"""

    def __init__(self, host, port, path):
        self.sock = socket.create_connection((host, port), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("DevTools 握手断开")
            buf += chunk
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        if b"101" not in head.split(b"\r\n")[0]:
            raise ConnectionError("DevTools 握手失败: %r" % head[:160])
        self.next_id = 0

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("DevTools 连接已关闭")
            self.buf += chunk

    def _send_frame(self, payload):
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytearray([0x81])
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        self.sock.sendall(bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _recv_frame(self):
        self._fill(2)
        op = self.buf[0] & 0x0F
        n = self.buf[1] & 0x7F
        off = 2
        if n == 126:
            self._fill(4)
            n = struct.unpack(">H", self.buf[2:4])[0]
            off = 4
        elif n == 127:
            self._fill(10)
            n = struct.unpack(">Q", self.buf[2:10])[0]
            off = 10
        self._fill(off + n)
        payload = self.buf[off:off + n]
        self.buf = self.buf[off + n:]
        if op == 0x8:
            raise ConnectionError("DevTools 主动关闭")
        return payload

    def call(self, method, params=None, timeout=20):
        self.next_id += 1
        mid = self.next_id
        self._send_frame(json.dumps({"id": mid, "method": method,
                                     "params": params or {}}).encode())
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self._recv_frame().decode("utf-8", "replace") or "{}")
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError("%s: %s" % (method, msg["error"].get("message")))
                return msg.get("result") or {}
        raise TimeoutError("等 %s 超时" % method)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_json(port, path, timeout=3):
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path),
                                    timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def edge_path():
    for cand in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                 r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                 os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe")):
        if os.path.isfile(cand):
            return cand
    return ""


def capture_account(acc, name, url=None, port=0, wait_seconds=600,
                    close=False, log=print):
    """开独立浏览器 + DevTools，登录后自动取走 cookie，写进账号。返回保存路径。"""
    prof = os.path.join(ACCOUNTS_DIR, name, "browser")
    os.makedirs(prof, exist_ok=True)
    url = url or "https://edu.wps.cn/app/study-platform/student/dashboard"
    exe = edge_path()
    if not exe:
        raise RuntimeError("找不到 msedge.exe；请用 import-cookies 导入 cookies.json")

    candidates = [prof] + ["%s-%d" % (prof, i) for i in range(2, 5)]
    proc = None
    used_port = 0
    for idx, prof_i in enumerate(candidates):
        os.makedirs(prof_i, exist_ok=True)
        used_port = port or free_port()
        log("浏览器 profile: %s" % prof_i)
        log("DevTools 端口: %d" % used_port)
        proc = subprocess.Popen([exe, "--user-data-dir=" + prof_i, "--no-first-run",
                                 "--no-default-browser-check", "--new-window",
                                 "--remote-debugging-port=%d" % used_port,
                                 "--remote-allow-origins=*", url])
        ok = False
        for _ in range(24):
            time.sleep(0.5)
            if http_json(used_port, "/json/version"):
                ok = True
                break
            if proc.poll() is not None:
                break
        if ok:
            break
        if idx + 1 < len(candidates):
            log("  该 profile 已被别的窗口占用，换一个干净的继续...")
    else:
        raise RuntimeError("连续几个 profile 都被占用，请先关掉之前的浏览器窗口")

    log("窗口已打开，请在里面登录 WPS 教学平台（扫码或账号密码）。")
    log("登录成功后会自动收走 cookie，窗口不用关。")

    deadline = time.time() + wait_seconds
    cdp = None
    seen = 0
    while time.time() < deadline:
        time.sleep(1.5)
        if proc is not None and proc.poll() is not None:
            raise RuntimeError("浏览器窗口被关掉了（没等到登录）。重跑本命令，窗口里完成登录即可。")
        if http_json(used_port, "/json/version") is None:
            continue
        if cdp is None:
            targets = http_json(used_port, "/json/list") or []
            pages = [t for t in targets
                     if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
            if not pages:
                continue
            ws = urllib.parse.urlparse(pages[0]["webSocketDebuggerUrl"])
            try:
                cdp = CDP(ws.hostname, ws.port, ws.path)
            except (ConnectionError, OSError) as e:
                log("  连 DevTools 失败: %s" % e)
                continue
        try:
            res = cdp.call("Storage.getCookies")
        except (RuntimeError, ConnectionError, TimeoutError):
            try:
                res = cdp.call("Network.getAllCookies")
            except (RuntimeError, ConnectionError, TimeoutError) as e:
                log("  取 cookie 失败: %s" % e)
                continue
        cookies = []
        for c in res.get("cookies") or []:
            host = c.get("domain") or ""
            bare = host.lstrip(".")
            if not any(bare == h or bare.endswith("." + h) for h in AUTH_DOMAIN_HINTS):
                continue
            val = c.get("value") or ""
            if not val or any(ord(ch) > 0xFF for ch in val):
                continue
            cookies.append({"name": c.get("name"), "value": val,
                            "domain": host, "path": c.get("path") or "/"})
        seen = len(cookies)
        if "wps_sid" in {c["name"] for c in cookies}:
            path = acc.save(name, cookies)
            log("已取到 %d 条 cookie -> %s" % (len(cookies), path))
            cdp.close()
            if close and proc is not None:
                try:
                    proc.terminate()
                except OSError:
                    pass
            return path
        if seen:
            log("  已见 %d 条平台 cookie，等 wps_sid 出现..." % seen)
    raise RuntimeError("等待超时（wait_seconds 可调大）。已见 cookie 数: %d" % seen)


def cmd_login_browser(args, acc):
    name = args.account or "default"
    try:
        capture_account(acc, name, url=args.url or None, port=args.port,
                        wait_seconds=args.wait_seconds, close=args.close)
    except RuntimeError as e:
        raise SystemExit(str(e))
    print("验证: python wpsedu.py status --account %s" % name)


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="WPS 教学平台多账号刷课工具")
    ap.add_argument("--account", default="", help="账号名（也可写在子命令后面）")
    sub = ap.add_subparsers(dest="cmd")

    def common(p, need_account=True):
        if need_account:
            p.add_argument("--account", default=argparse.SUPPRESS)
        p.add_argument("--cookie-file", default="")
        p.add_argument("--token-file", default="")

    for name in ("login", "courses", "status", "finish"):
        p = sub.add_parser(name)
        common(p)
        p.add_argument("--package", type=int, default=0)
        p.add_argument("--course", default="")
        p.add_argument("--skip-types", default="9")
        if name == "finish":
            p.add_argument("--all", action="store_true")
            p.add_argument("--dry-run", action="store_true")
            p.add_argument("--workers", type=int, default=24)
            p.add_argument("--rounds", type=int, default=3)
            p.add_argument("--retry-slow", action="store_true")
            p.add_argument("--log", default="")

    p = sub.add_parser("accounts")
    common(p, need_account=False)

    p = sub.add_parser("import-cookies")
    p.add_argument("--from", dest="source", default="edge", help="edge/chrome/brave/wps 或 UserData 路径")
    p.add_argument("--profile", default="", help="如 Default / Profile 1")
    p.add_argument("--index", type=int, default=0, help="候选编号（1 起）")
    common(p)

    p = sub.add_parser("login-browser")
    p.add_argument("--url", default="")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--close", action="store_true", help="取到 cookie 后关掉这个浏览器")
    p.add_argument("--wait-seconds", type=int, default=600)
    common(p)

    p = sub.add_parser("add-account")
    p.add_argument("name", nargs="?", default="")
    p.add_argument("--cookie-file", dest="cookie_file", default="")
    p.add_argument("--account", default="")

    p = sub.add_parser("rm-account")
    p.add_argument("name", nargs="?", default="")
    p.add_argument("--account", default="")

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 1
    acc = Accounts()

    if args.cmd == "accounts":
        cmd_accounts(args, acc)
        return 0
    if args.cmd == "import-cookies":
        args.account = args.account or ""
        cmd_import(args, acc)
        return 0
    if args.cmd == "login-browser":
        cmd_login_browser(args, acc)
        return 0
    if args.cmd == "add-account":
        name = args.account or args.name
        if not name:
            raise SystemExit("用法: add-account NAME --cookie-file PATH")
        args.account = name
        if not args.cookie_file:
            raise SystemExit("需要 --cookie-file")
        cmd_add_account(args, acc)
        return 0
    if args.cmd == "rm-account":
        name = args.account or args.name
        if not name:
            raise SystemExit("用法: rm-account NAME")
        args.account = name
        cmd_rm_account(args, acc)
        return 0

    name = acc.pick(args.account)
    cookie_file = args.cookie_file or acc.cookie_file(name)
    token_file = args.token_file or acc.token_file(name)
    if not os.path.exists(cookie_file):
        raise SystemExit("账号 %r 没有 cookie 文件: %s" % (name, cookie_file))
    args.skip_types = [int(x) for x in str(getattr(args, "skip_types", "9"))
                       .replace(" ", "").split(",") if x]
    cli = Client(cookie_file, token_file)
    if name != "default" or args.account:
        print("[账号: %s]" % name)

    if args.cmd == "login":
        cmd_login(cli, args)
    elif args.cmd == "courses":
        cmd_courses(cli, args)
    elif args.cmd == "status":
        cmd_status(cli, args)
    elif args.cmd == "finish":
        cmd_finish(cli, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
