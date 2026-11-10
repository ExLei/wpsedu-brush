# wpsedu · WPS 教学平台刷课工具

**刷课工具**：WPS 教学平台（`edu.wps.cn/app/study-platform`）的命令行 + 本地 Web 控制台。
多账号、课程进度盘点、批量把「学习任务」置为已完成，视频类任务从"要看完"变成"一两秒"。

只依赖 Python 标准库 + [`cryptography`](https://pypi.org/project/cryptography/)。

## 特性

- **多账号**：每个账号独立目录，cookie / token 分开缓存，`--account` 切换
- **三种取 cookie 的方式**：桌面 WPS 的 CEF 会话、本机 Edge/Chrome 的 profile、工具自开的扫码窗口
- **课程盘点**：资源总数 / 已完成 / 待办明细（`learnStatus` 0/1/2）
- **批量完成**：文档类一次上报即完成；视频类用并发窗口上报，不走播放
- **断点续跑**：幂等，已完成的条目自动跳过；支持取消
- **Web UI**：`127.0.0.1` 单页控制台，实时日志 + 进度条

## 安装

```bash
python -m pip install cryptography
git clone https://github.com/ExLei/wpsedu-brush.git && cd wpsedu-brush
```

Python 3.9+，Windows（cookie 解密用到 DPAPI）。

## 账号

三种来源，任选其一：

```bash
# 1) 桌面 WPS 已登录 → 直接从它的 CEF cookie 库解密（最快，无需扫码）
python wpsedu.py import-cookies --from "%APPDATA%\kingsoft\wps_international\addons\data\win-x64\cef\2\cache" --account NAME

# 2) 本机 Edge/Chrome 已登录且浏览器已退出 → 从 profile 读
python wpsedu.py import-cookies --from edge --account NAME
python wpsedu.py import-cookies --from "C:\...\User Data" --index 2 --account NAME

# 3) 都没有 → 工具自开一个独立浏览器窗口，登录后自动取走 cookie（窗口不用关）
python wpsedu.py login-browser --account NAME

python wpsedu.py accounts        # 列账号：昵称 / 组织 / 课程数
python wpsedu.py rm-account NAME
```

`accounts/` 下每个账号一个目录，`cookies.json` + `token.json`，都在 `.gitignore` 里。

## 命令行

```bash
python wpsedu.py courses   [--account NAME]                       # 我的课程
python wpsedu.py status    [--account NAME] [--course KW]         # 完成情况 + 待办明细
python wpsedu.py finish    [--account NAME] [--package ID] [--dry-run]
python wpsedu.py finish    --all --workers 24                     # 全部课程，视频 24 并发
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--account NAME` | 账号名；只存在一个账号时可省略。写在子命令前后都行 |
| `--course KW` | 按课程标题关键字选课 |
| `--package ID` | 直接指定 packageId |
| `--skip-types 9` | 跳过的 resourceType，默认 `9`（可评分/测验，进度上报不生效） |
| `--workers N` | 视频并发窗口数，默认 24 |
| `--rounds N` | 并发失败时重试轮数 |
| `--retry-slow` | 并发出错时用顺序步进法回补 |
| `--log FILE` | 逐条结果落盘 |

## Web 控制台

```bash
python wpsedu_web.py                # http://127.0.0.1:8765，自动开浏览器
python wpsedu_web.py --port 9000 --no-browser
```

三块：账号（含扫码登录）、课程与进度、执行（并发/轮次/试跑/取消 + 实时日志）。

## 原理摘要

- 进度状态来自课程树接口的 `learnStatus`：`0` 未学习、`1` 已完成、`2` 学习中
- 完成状态由 `POST /user/course/resource/progress` 写入：
  - 文档类 `{chapterId, chapterName, resourceType}` 一次即完成
  - 视频类 `{chapterId, chapterName, resourceType, lastPos, currentPos, speed, duration}`
- 视频按 **5 秒分片**累计"位置覆盖"，单次最多认领 **20 秒**窗口，覆盖率 **≥80%** 时
  `completed` 置位并永久锁定；分片按位置计算、不要求顺序
- 所以把时间轴切成 20 秒窗口并发发出，一条 300~800 秒的视频 1~3 秒即可完成，
  不用播放、不用等待

细节、实测数据和 cookie 解密链路见 [docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md)。

## 已知限制

- `resourceType 9`（可评分 / 测验）不吃进度上报，状态取决于 `completionStatus` +
  `gradeStatus`，需要真实交卷。默认跳过。
- 部分浏览器新版用 `v20`（App-Bound）加密 cookie，离线解不开；改用 `login-browser`。
- 平台改版会使接口失效，届时按 docs 里的方法重新抓一遍即可。

## 文件

```
wpsedu.py         CLI：账号、课程树、进度上报、视频并发、cookie 解密
wpsedu_web.py     本地 Web 控制台（复用 wpsedu.py，无重复实现）
docs/             逆向笔记
```

## 使用范围

工具用在你自己有权访问的账号上。账号凭据只存在本机 `accounts/`，不会外发。
