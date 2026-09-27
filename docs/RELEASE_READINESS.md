# 发布就绪清单

这不是上线公告，也没有日历发布日。仓库不能保证某一天对外。结论只有一句：

**限量单进程版本在下面第 1–3 项成立时可以发布。VISION 里的 10 倍压缩、单次 ≥ 10 亿条、库 ≥ 100GB，以及 `docs/SPEC.md` §6.2 的延迟表，都还不能说已经验收。微服务拆分也不在这个版本里。**

对外进程是 `sotrace-server`（`crates/sotrace-server/src/main.rs`）。`backend/` 里的 FastAPI 不是发布入口。

## 1. 认证（成立）

`POST /api/v1/traces/import` 和 `GET /api/v1/traces/{id}/instructions` 必须带服务器实际校验过的 `Authorization: Bearer`。没有凭证或凭证不对，返回 401。`GET /api/v1/health` 不需要凭证。

实现在 `crates/sotrace-server/src/middleware/auth.rs` 的 `auth_fn`。它只放行与 `AppState.auth_token` 一致的 Bearer。`main` 从环境变量 `SOTRACE_AUTH_TOKEN` 读取这个值；没设置或为空时进程拒绝启动（`crates/sotrace-server/src/app.rs` 的 `build_app`）。中间件不再无条件 `next.run`。

测试夹具 `TEST_BEARER_TOKEN` 只给进程内测试用。启动对外进程时要另设 `SOTRACE_AUTH_TOKEN`，不要把测试字符串当成生产口令。

`/api/v1/auth/login` 仍返回占位 token，不能用来登录。发布用的是启动时配置的 Bearer，不是那条占位登录。

## 2. 保存成功才算落盘（成立）

导入成功只表示内存里可查。`import_trace` 把事件放进 `AppState::event_buffers`。不调用保存就结束进程，磁盘上没有这批事件。

`POST /api/v1/traces/:id/save` 调用 `TraceRepository::save`。成功返回之前，`publish_durable`（`crates/sotrace-engine/src/persistence/mod_part02_part_01.rs`）对临时文件、发布后的 blob、以及 trace 索引做 `sync_all`，并同步父目录。索引走同一条 `publish_durable`。这不是「写完就 rename」。

导入本身不会在返回前 fsync。不要把导入成功说成崩溃安全。

## 3. 指标与打包（成立）

`GET /api/v1/metrics` 返回文本，包含计数器 `sotrace_import_failures_total` 和 `sotrace_save_failures_total`。值为 0 也是这份文档，不是写死的健康字符串。失败的导入（含未授权的导入）和失败的保存会增加对应计数。实现见 `crates/sotrace-server/src/handlers/mod.rs` 的 `metrics`。

服务包定义在 `packaging/sotrace-server/Dockerfile`，入口是 `sotrace-server`，和 `.github/workflows/deploy-website.yml` 不是同一条发布。`packaging/sotrace-server/package.sh` 把已编译的二进制拷出来再启动，启动同样要求 `SOTRACE_AUTH_TOKEN`。

## 仍不能对外宣称的内容

这些项没有改目标数字，也没有被标成完成：

| 项 | 状态 |
|----|------|
| `docs/VISION.md` 相对原始文本 ≥ 10x 压缩 | 未按该标准验收 |
| 单次 trace ≥ 10 亿条 | 未验收 |
| 单个数据库 ≥ 100GB | 未验收 |
| `docs/SPEC.md` §6.2 点查询 / 范围查询延迟 | 不是已验收的 SLA |
| `docs/SYSTEM_ARCHITECTURE.md` 的多进程拆分 | 延后。这个版本是单个 `sotrace-server` 进程 |

写入吞吐仍以 `docs/VISION.md` 的 ≥ 100 万条/秒为门槛。上一轮对 `TraceEngine::feed_events` 的本机测量中位数是 6,599,541 条/秒，那是共享导入路径的数字，不是 10 亿条规模的证明。

## 发布时怎么起

```sh
export SOTRACE_AUTH_TOKEN='<进程启动时生成的口令>'
export SOTRACE_DATA_DIR=/var/lib/sotrace
export SOTRACE_BIND=127.0.0.1:8080
./target/release/sotrace-server
```

导入和指令查询带 `Authorization: Bearer <同一口令>`。要耐久化再调用该 trace 的 save。健康检查和指标不带口令。
