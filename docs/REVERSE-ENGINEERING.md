# 逆向笔记

目标：WPS 教学平台（前端 `edu.wps.cn/app/study-platform`，后端 `api-kos.wps.cn/study`）。
所有结论来自 2026-11 的线上行为实测，涉及具体 ID 的都用占位符。

## 1. 定位前端

- 平台页面标题 `首页 - 教学平台`，SPA 资源在 `qn.cache.wpscdn.cn/fe/edu/edu-study-platform-prod/`
- 拿到 `assets/index-*.js` 后，里面的路由表直接给出全部页面：

  `/student/dashboard`、`/student/packages`、`/student/packages/:packageId/chapters`、
  `/student/packages/:packageId/chapters/:chapterId` 等

- 开发面板可用时最省事：`document.querySelector('#app').__vue_app__.config.globalProperties.$router.getRoutes()`

## 2. 认证

```
POST https://api-kos.wps.cn/study/user/account/login     {"identity": null}
     -> data.token
```

只要浏览器 Cookie（`wps_sid` 等），不需要密码、不需要签名。
之后每个请求带 `X-Edu-Token: <token>`。实测 `csrf` 缺失也能用。

`GET /study/user/account/userInfo` 返回 `wpsId / name / orgName / classList`，用来给账号命名。

## 3. 课程树

```
POST /study/user/course/roll   {"courseType":1,"courseStatus":1,"pageSize":50}   # 我的课程
GET  /study/user/course/detail?packageId=PACKAGE_ID                              # 整棵树
```

树结构：`chapters[] → subsets[] → ...`，叶子 `nodeType == "file"`，字段：

| 字段 | 说明 |
| --- | --- |
| `chapterId` | 资源 id，上报要用 |
| `fileInfo.resourceType` | 1 文档 / 6 视频 / 9 评分任务 / 11 素材文件 |
| `learnStatus` | 0 未学习、1 已完成、2 学习中 |
| `fileInfo.completedAt` | 完成时间（评分任务会被写入但不改 learnStatus） |

一门 217 资源 = 217 个 `file` 叶子 + 若干 `folder`。

## 4. 完成上报

```
POST /study/user/course/resource/progress
```

**文档类**（`resourceType` 1 / 11 等）：

```json
{"chapterId":"RES_ID","chapterName":"xxx.pptx","resourceType":1}
```

一次即完成，响应 `coverage: 10000, completed: true`。

**视频类**（`resourceType` 6）还必须带位置：

```json
{"chapterId":"RES_ID","chapterName":"xxx.mp4","resourceType":6,
 "lastPos":0,"currentPos":20,"speed":1,"duration":20}
```

响应体带进度：

```json
{"watchedSegments":48,"totalSegments":135,"coverage":3555,
 "completed":false,"watchDurationSeconds":253}
```

## 5. 视频机制（关键）

实测结论：

1. `totalSegments × 5 秒` = 视频时长；分片固定 5 秒
2. 单次上报最多认领 **20 秒**（`currentPos - lastPos > 20` 会被拒，返回 `null`）
   超过当前 `totalSegments` 的越界位置会报「播放位置非法」
3. 每次上报约 +18~20 秒进度、+4 个分片，**与真实时间无关**
   —— 0.2 秒连发 10 次照样每次 +4 分片
4. 覆盖率 ≥ **80%** 时 `completed: true` **一次置位并永久锁定**，之后时长变化不回退
5. 分片按**位置**计，不要求顺序：先发 660→665 也能加分片
6. 因此：把时间轴切成 20 秒窗口，**多线程一次性全部发出**，
   一条 300~800 秒的视频 1~3 秒就 `coverage: 10000`。实测 24 并发、几十条视频零失败

`duration` 是"距上次上报的真实耗时"，服务端并未严格校验它和 `currentPos` 的比值；
真正卡住进度的是"单次 20 秒窗口"这条。

## 6. 评分任务（`resourceType` 9）

- 打过进度上报后 `fileInfo.completedAt` 会写入，但 `learnStatus` 仍是 0/2
- 真实状态在测验侧：`POST /study/user/quiz/page` 里 `completionStatus` / `gradeStatus`
- 只有走过考试客户端（`kps/exam`：`POST /kps/exam/api/oe/sys/session` → 取卷 → 交卷）
  拿到 `FINISH` 才会翻成已完成；同课另一条 0 分也算 `FINISH`
- 结论：这类不吃进度上报，工具默认 `--skip-types 9`

## 7. Cookie 解密

浏览器（Chromium 系，含 Edge/Chrome）：

| 环节 | 做法 |
| --- | --- |
| 主密钥 | `Local State` → `os_crypt.encrypted_key`（base64）→ 去掉 `DPAPI` 前缀 → `CryptUnprotectData` |
| 值 | `v10`/`v11` 前缀 → AES-256-GCM：`nonce = [3:15]`，`ct = [15:-16]`，`tag = [-16:]` |
| AAD | 新版绑 host_key，旧版无；两种都试 |
| 32 字节头 | 明文前有 32 字节绑定头，`cid` 实际明文是 `<32B 二进制>COMPANY_ID`；判据"前 32 字节非可打印且其后全可打印" |
| 加锁 | 浏览器运行时 `Cookies` 被独占，需退出或改用 CDP |
| `v20` | App-Bound 加密，离线解不开 |

WPS 的 CEF 换了存放位置：密钥在
`%APPDATA%\kingsoft\wps_international\addons\data\win-x64\LocalPrefs.json`
（结构与 `Local State` 相同），而 cookie 库在
`...\cef\2\cache\Network\Cookies`。所以密钥文件要从 cache 目录往上找几层。

桌面 WPS 换了账号 → 直接读它这份 cookie 库即可拿到新账号会话，不需要重新扫码。

运行时取 cookie 更稳的方式是 CDP：给浏览器加 `--remote-debugging-port`，
连上后 `Storage.getCookies` 读内存里的（会话 cookie 不落盘，轮询数据库永远读不到）。

## 8. 容易误判的点

`shuc-js.ksord.com` / `shuc-pc-*.ksord.com` 下那堆 `POST /bat/js/cors`、
`dw-protocol: 1.0`、加密 base64 body —— 是 `WebReporter`（`dw` 数据上报 SDK）的遥测，
`sendUrl` 就是那个路径。它没有 cookie/UA，不是业务接口，别在上面浪费时间。

真正相关的域：`edu.wps.cn`（前端）、`api-kos.wps.cn`（业务 API）、
`ewb.wps.cn`（教学空间工作台，另一套 `/ewb/api`）。

## 9. 复现方法

1. 枚举页面上的 JS，挑主 bundle，`grep` 出 `/api/`、`/user/`、`baseURL`
2. 拿不准参数就直接对着接口试：服务端会回「参数不全」「播放位置非法」这类明确错误，
   比读源码快
3. 判断"是否真的需要看视频"只需一次实验：固定位置连发两次，看
   `watchedSegments` 有没有涨
4. 找阈值就一路加到 `completed: true`，记下当时的分片比例
