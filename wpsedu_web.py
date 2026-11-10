#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""wpsedu 简易 Web UI —— 本地单页控制台

  python wpsedu_web.py                # http://127.0.0.1:8765
  python wpsedu_web.py --port 9000 --no-browser

只监听回环地址；所有逻辑复用 wpsedu.py（账号、课程树、并发窗口绕过、扫码取 cookie）。
"""
import argparse
import json
import os
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import wpsedu as W

JOB_LOCK = threading.Lock()


class Job:
    def __init__(self, kind, info=None):
        self.kind = kind
        self.state = "running"          # running | done | error | cancelled
        self.lines = []
        self.error = ""
        self.info = info or {}
        self.stop = False
        self.t0 = time.time()

    def add(self, msg):
        with JOB_LOCK:
            self.lines.append("%s  %s" % (time.strftime("%H:%M:%S"), msg))
            if len(self.lines) > 800:
                del self.lines[:200]

    def snapshot(self, limit=250):
        with JOB_LOCK:
            lines = self.lines[-limit:]
        return {"kind": self.kind, "state": self.state, "error": self.error,
                "info": self.info, "lines": lines,
                "elapsed": round(time.time() - self.t0, 1), "stop": self.stop}


JOB = None


def run_job(job, fn):
    global JOB
    try:
        fn(job)
        job.state = "cancelled" if job.stop else "done"
    except SystemExit as e:
        job.state = "error"
        job.error = str(e)
    except Exception as e:                                   # noqa: BLE001
        job.state = "error"
        job.error = "%s: %s" % (type(e).__name__, e)
        job.add("ERROR " + job.error)
        job.add(traceback.format_exc(limit=3))
    JOB = job


def start_job(kind, targets, info=None):
    global JOB
    if JOB is not None and JOB.state == "running":
        raise RuntimeError("已有任务在跑，请等它结束或先取消")
    job = Job(kind, info)
    JOB = job
    th = threading.Thread(target=run_job, args=(job, targets), daemon=True)
    th.start()
    return job


# ---------------------------------------------------------------- 业务封装

def account_client(name):
    acc = W.Accounts()
    return W.Client(acc.cookie_file(name), acc.token_file(name))


def api_accounts():
    acc = W.Accounts()
    out = []
    for n in acc.names():
        row = {"name": n, "who": "", "courses": [], "error": ""}
        try:
            cli = account_client(n)
            st, j = cli.api("GET", "/user/account/userInfo")
            info = ((j.get("data") or {}).get("userInfo") or {})
            row["who"] = "%s / %s" % (info.get("name") or "?", info.get("orgName") or "?")
            st2, j2 = cli.api("POST", "/user/course/roll",
                              body={"courseType": 1, "courseStatus": 1, "pageSize": 50})
            for c in ((j2.get("data") or {}).get("list") or []):
                row["courses"].append({"package": c.get("packageId"),
                                       "title": c.get("title"),
                                       "items": c.get("itemNum")})
        except BaseException as e:                            # noqa: BLE001
            row["error"] = str(e)[:120]
        out.append(row)
    return out


def api_status(account, package):
    cli = account_client(account)
    course = W.course_tree(cli, package)
    leaves = W.leaves_of(course)
    total, done, dist = W.summarize(leaves)
    pend = []
    for l in leaves:
        n = l["node"]
        if n.get("learnStatus") == W.DONE:
            continue
        fi = n.get("fileInfo") or {}
        pend.append({"id": n["chapterId"], "type": fi.get("resourceType"),
                     "name": (n.get("chapterName") or "")[:80]})
    return {"title": course.get("title"), "package": package, "total": total,
            "done": done, "dist": dist, "pending": pend[:300], "pendingCount": len(pend)}


# ---------------------------------------------------------------- 任务体

def job_login(job, account, url):
    job.add("准备打开浏览器，profile 见下")
    W.capture_account(W.Accounts(), account, url=url or None, log=job.add)


def job_finish(job, account, package, workers, skip_types, dry_run, rounds, retry_slow):
    cli = account_client(account)
    job.info.update({"done": 0, "total": 0, "account": account, "package": package})

    def on_item(i, total, node, ok, note):
        job.info.update({"done": i, "total": total,
                         "current": (node.get("chapterName") or "")[:60], "ok": ok})

    res = W.finish_course(cli, package, set(skip_types), workers=workers, rounds=rounds,
                          retry_slow=retry_slow, dry_run=dry_run, log=job.add,
                          on_item=on_item, should_stop=lambda: job.stop)
    job.info.update(res)


# ---------------------------------------------------------------- HTTP

ROUTES_GET = {"/", "/index.html", "/api/accounts", "/api/status", "/api/job"}


class Handler(BaseHTTPRequestHandler):
    server_version = "wpsedu-web/1.0"

    def log_message(self, fmt, *a):      # 静音访问日志
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                return self._send(200, HTML, "text/html; charset=utf-8")
            if u.path == "/api/accounts":
                return self._send(200, {"accounts": api_accounts()})
            if u.path == "/api/status":
                acc = (q.get("account") or [""])[0]
                pkg = int((q.get("package") or ["0"])[0])
                if not acc or not pkg:
                    return self._send(400, {"error": "需要 account 和 package"})
                return self._send(200, api_status(acc, pkg))
            if u.path == "/api/job":
                if JOB is None:
                    return self._send(200, {"kind": "", "state": "idle", "lines": [], "info": {}})
                return self._send(200, JOB.snapshot())
            return self._send(404, {"error": "not found"})
        except BaseException as e:                            # noqa: BLE001
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        try:
            if u.path == "/api/finish":
                acc = body.get("account") or ""
                pkg = int(body.get("package") or 0)
                if not acc or not pkg:
                    return self._send(400, {"error": "需要 account 和 package"})
                skip = [int(x) for x in
                        str(body.get("skipTypes") or "9").replace(" ", "").split(",") if x]
                job = start_job("finish", lambda j: job_finish(
                    j, acc, pkg, int(body.get("workers") or 24), skip,
                    bool(body.get("dryRun")), int(body.get("rounds") or 3),
                    bool(body.get("retrySlow"))), {"account": acc, "package": pkg})
                return self._send(200, {"started": job.kind})
            if u.path == "/api/login-browser":
                acc = body.get("account") or ""
                if not acc:
                    return self._send(400, {"error": "需要 account"})
                job = start_job("login", lambda j: job_login(j, acc, body.get("url")),
                                {"account": acc})
                return self._send(200, {"started": job.kind})
            if u.path == "/api/cancel":
                if JOB is not None and JOB.state == "running":
                    JOB.stop = True
                    JOB.add("收到取消请求，处理完当前条目就停")
                    return self._send(200, {"ok": True})
                return self._send(200, {"ok": False, "msg": "没有在跑的任务"})
            return self._send(404, {"error": "not found"})
        except BaseException as e:                            # noqa: BLE001
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


HTML = r"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wpsedu 控制台</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e6e9ef;--dim:#8b93a7;--ok:#3ddc97;--warn:#ffb454;--bad:#ff6b6b;--acc:#4c8dff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:20px 18px 60px}
h1{font-size:19px;margin:0 0 4px}
.sub{color:var(--dim);font-size:12px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.card h2{font-size:13px;margin:0 0 12px;color:var(--dim);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
select,input,button{background:#0d1016;color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:7px 10px;font:inherit}
select:hover,input:hover{border-color:#39414f}
button{cursor:pointer;background:#1d2230}
button:hover:not(:disabled){border-color:var(--acc)}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
button.danger{background:#2a1a1e;border-color:#5a2b33;color:#ff9aa5}
button:disabled{opacity:.45;cursor:not-allowed}
.bar{height:8px;background:#0d1016;border-radius:6px;overflow:hidden;margin:10px 0 6px;border:1px solid var(--line)}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#3ddc97,#4c8dff);width:0;transition:width .3s}
.stat{font-size:13px;color:var(--dim)}
.stat b{color:var(--fg);font-size:17px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:11px;color:var(--dim);margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:500}
td.mono{font-family:ui-monospace,Consolas,monospace;color:var(--dim)}
pre#log{margin:0;height:340px;overflow:auto;background:#0a0c11;border:1px solid var(--line);border-radius:8px;
 padding:10px 12px;font:12px/1.55 ui-monospace,Consolas,monospace;white-space:pre-wrap;color:#c9d1d9}
.pill{font-size:11px;padding:2px 8px;border-radius:20px;border:1px solid var(--line);color:var(--dim)}
.pill.run{color:var(--warn);border-color:#5a4a2b}
.pill.done{color:var(--ok);border-color:#2b5a45}
.pill.err{color:var(--bad);border-color:#5a2b33}
.hint{color:var(--dim);font-size:12px;margin-top:8px}
.err{color:var(--bad)}
.scroll{max-height:230px;overflow:auto}
</style></head><body><div class="wrap">
<h1>wpsedu 控制台</h1>
<div class="sub">WPS 教学平台 · 账号 / 课程 / 刷课 &nbsp;·&nbsp; 只监听 127.0.0.1</div>

<div class="card">
  <h2>1. 账号</h2>
  <div class="row">
    <select id="acc" style="min-width:280px"></select>
    <button id="btnReload">刷新账号</button>
    <span style="flex:1"></span>
    <input id="newAcc" placeholder="新账号名，如 NAME" size="14">
    <button id="btnLogin" class="primary">扫码登录并保存</button>
  </div>
  <div class="hint" id="accHint">会打开一个独立浏览器窗口，登录完成后无需关窗，脚本自动取走 cookie。</div>
</div>

<div class="card">
  <h2>2. 课程与进度</h2>
  <div class="row">
    <select id="course" style="min-width:420px"></select>
    <button id="btnStatus">刷新状态</button>
  </div>
  <div class="bar"><i id="bar"></i></div>
  <div class="stat" id="statLine">未选择课程</div>
  <div class="scroll" style="margin-top:10px"><table id="pend"><thead>
    <tr><th style="width:110px">chapterId</th><th style="width:60px">类型</th><th>名称</th></tr>
  </thead><tbody></tbody></table></div>
</div>

<div class="card">
  <h2>3. 执行</h2>
  <div class="row">
    <label class="stat">跳过类型 <input id="skip" value="9" size="6"></label>
    <label class="stat">并发 <input id="workers" value="24" size="4"></label>
    <label class="stat">轮次 <input id="rounds" value="3" size="3"></label>
    <label class="stat"><input type="checkbox" id="dry"> 只试跑</label>
    <span style="flex:1"></span>
    <span class="pill" id="jobPill">空闲</span>
    <button id="btnRun" class="primary">开始刷课</button>
    <button id="btnCancel" class="danger" disabled>取消</button>
  </div>
  <pre id="log">（日志会出现在这里）</pre>
</div>

<script>
const $ = (s) => document.querySelector(s);
let accounts = [], timer = null;

function setPill(st, extra) {
  const p = $('#jobPill');
  p.className = 'pill ' + ({running:'run', done:'done', error:'err', cancelled:'err'}[st] || '');
  p.textContent = {idle:'空闲', running:'进行中', done:'完成', error:'出错', cancelled:'已取消'}[st] || st;
  if (extra) p.textContent += ' · ' + extra;
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({error:'非 JSON 响应'}));
  if (!r.ok || j.error) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}

async function loadAccounts() {
  $('#accHint').textContent = '读取账号...';
  try {
    const j = await api('/api/accounts');
    accounts = j.accounts || [];
    const sel = $('#acc');
    sel.innerHTML = '';
    if (!accounts.length) {
      $('#accHint').innerHTML = '<span class="err">还没有账号，先在右边输入名字点「扫码登录并保存」。</span>';
      return;
    }
    for (const a of accounts) {
      const o = document.createElement('option');
      o.value = a.name;
      const n = a.courses.length;
      o.textContent = a.name + (a.who ? '  ·  ' + a.who : '') + (a.error ? '  ·  ' + a.error : '  ·  ' + n + ' 门课');
      sel.appendChild(o);
    }
    $('#accHint').textContent = '共 ' + accounts.length + ' 个账号。';
    loadCourses();
  } catch (e) { $('#accHint').innerHTML = '<span class="err">' + e.message + '</span>'; }
}

function loadCourses() {
  const name = $('#acc').value;
  const a = accounts.find(x => x.name === name);
  const sel = $('#course');
  sel.innerHTML = '';
  if (!a || !a.courses.length) {
    sel.innerHTML = '<option value="">（该账号没有进行中的课程）</option>';
    return;
  }
  for (const c of a.courses) {
    const o = document.createElement('option');
    o.value = c.package;
    o.textContent = c.title + '  ·  ' + c.items + ' 项';
    sel.appendChild(o);
  }
  loadStatus();
}

async function loadStatus() {
  const account = $('#acc').value, pkg = $('#course').value;
  if (!account || !pkg) return;
  $('#statLine').textContent = '读取中...';
  try {
    const s = await api('/api/status?account=' + encodeURIComponent(account) + '&package=' + pkg);
    const pct = s.total ? (s.done / s.total * 100) : 0;
    $('#bar').style.width = pct.toFixed(1) + '%';
    const LABEL = {'0':'未开始', '1':'已完成', '2':'学习中'};
    const distTxt = Object.keys(s.dist).sort().map(k => (LABEL[k] || ('状态' + k)) + ' ' + s.dist[k]).join(' · ');
    $('#statLine').innerHTML = s.title + ' &nbsp; <b>' + s.done + '</b> / ' + s.total +
      ' 已完成 &nbsp; 待办 <b>' + s.pendingCount + '</b>' +
      ' &nbsp;<span class="tag">' + distTxt + '</span>';
    const tb = $('#pend tbody');
    tb.innerHTML = '';
    for (const p of s.pending.slice(0, 120)) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td class="mono">' + p.id + '</td><td class="mono">' + p.type +
        '</td><td>' + p.name.replace(/</g, '&lt;') + '</td>';
      tb.appendChild(tr);
    }
    if (!s.pendingCount) tb.innerHTML = '<tr><td colspan="3" style="color:#3ddc97">全部完成</td></tr>';
  } catch (e) { $('#statLine').innerHTML = '<span class="err">' + e.message + '</span>'; }
}

async function poll() {
  try {
    const j = await api('/api/job');
    if (j.state === 'idle') { setPill('idle'); return; }
    setPill(j.state, j.info && j.info.total ? (j.info.done + '/' + j.info.total) : null);
    const log = $('#log');
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
    log.textContent = (j.lines || []).join('\n') || '（暂无输出）';
    if (atBottom) log.scrollTop = log.scrollHeight;
    const running = j.state === 'running';
    $('#btnRun').disabled = running;
    $('#btnCancel').disabled = !running;
    if (j.error) log.textContent += '\n\n[错误] ' + j.error;
    if (!running) {
      clearInterval(timer); timer = null;
      $('#btnRun').disabled = false;
      loadStatus();
    }
  } catch (e) { /* 忽略轮询错误 */ }
}

function startPolling() {
  if (timer) clearInterval(timer);
  timer = setInterval(poll, 900);
  poll();
}

async function post(path, body) {
  return api(path, {method:'POST', headers:{'Content-Type':'application/json'},
                    body: JSON.stringify(body || {})});
}

$('#btnReload').onclick = loadAccounts;
$('#acc').onchange = loadCourses;
$('#btnStatus').onclick = loadStatus;

$('#btnLogin').onclick = async () => {
  const name = ($('#newAcc').value || '').trim();
  if (!name) { alert('先填一个账号名'); return; }
  try {
    await post('/api/login-browser', {account: name});
    $('#log').textContent = '浏览器已打开，登录完成后这里会出现 cookie 保存结果...';
    startPolling();
  } catch (e) { alert(e.message); }
};

$('#btnRun').onclick = async () => {
  const account = $('#acc').value, pkg = parseInt($('#course').value || '0', 10);
  if (!account || !pkg) { alert('先选账号和课程'); return; }
  const body = {account, package: pkg, skipTypes: $('#skip').value,
                workers: parseInt($('#workers').value || '24', 10),
                rounds: parseInt($('#rounds').value || '3', 10),
                dryRun: $('#dry').checked};
  try {
    await post('/api/finish', body);
    $('#log').textContent = '';
    startPolling();
  } catch (e) { alert(e.message); }
};

$('#btnCancel').onclick = async () => { try { await post('/api/cancel', {}); } catch (e) { alert(e.message); } };

loadAccounts();
poll();
</script></div></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="wpsedu 简易 Web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    url = "http://%s:%d/" % (args.host, args.port)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("wpsedu 控制台: %s" % url)
    print("账号目录: %s" % W.ACCOUNTS_DIR)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n再见")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
