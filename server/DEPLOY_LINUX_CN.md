# Linux 自托管部署

本说明对应 `codex/self-hosted-server` 分支。服务端提供账户、管理员、角色、设备、任务事件统计和原有业务能力；桌面客户端的自有登录与同步接入需要在后续客户端阶段完成。

## 无域名：使用 IPv4 部署

服务器已安装 Git、Python 3、Docker、Compose 插件，并放行 TCP 3001。把下面的 `你的服务器IP` 换成实际 IPv4 地址。

```bash
git clone --single-branch --branch codex/self-hosted-server https://github.com/863563368/eigent.git
cd eigent/server
python3 scripts/init_production.py --http-ip 你的服务器IP
docker compose --env-file .env.production -f docker-compose.production.yml up -d --build
docker compose --env-file .env.production -f docker-compose.production.yml exec api python scripts/manage.py bootstrap-admin --email admin@example.com
```

访问 `http://你的服务器IP:3001/docs`。IP 模式不启用 `edge` profile，不启动 Caddy。HTTP 会明文传输登录信息，先在受控网络中使用。此模式更新或重新启动时也不要添加 `--profile edge`。

已有 `.env.production` 时不要删除或重新生成密钥。若需要从已有 HTTPS 配置切换为 IP 模式，保留密码和密钥，将 `TOKEN_ISSUER`、`CORS_ALLOW_ORIGINS`、`REMOTE_CONTROL_WEB_ORIGIN` 改成 `http://你的服务器IP:3001`，设置 `ALLOW_HTTP_IP_DEPLOYMENT=true`、`API_BIND_ADDRESS=0.0.0.0`，并将两个可信代理设置改为 `127.0.0.1`。先停止原有 Caddy，再按不带 `edge` 的命令重新创建应用容器。更换 issuer 后需重新登录。

## 首次部署

前置条件：Linux 已安装 Git、Python 3、Docker Engine 和 Docker Compose 插件；域名已解析到服务器；公网允许 TCP 80、443。首次构建需要访问镜像仓库、Python 包源及 CAMEL 的 Git 依赖。

以下两个域名需要替换为你的真实域名。Web origin 是未来管理界面或 Web 客户端的来源，可以与 API origin 相同；这里不会自动部署一个 Web 前端。

```bash
git clone --branch codex/self-hosted-server https://github.com/863563368/eigent.git
cd eigent/server

python3 scripts/init_production.py \
  --api-origin https://api.your-domain.com \
  --web-origin https://app.your-domain.com

# 后续命令均在 server/ 目录执行
dc() { docker compose --env-file .env.production -f docker-compose.production.yml "$@"; }

export SERVER_CODE_HASH="$(git log -1 --format=%H -- server/)"
dc --profile edge up -d --build
dc ps -a
dc logs --tail=100 migrate api celery_worker celery_beat caddy
curl -f http://127.0.0.1:3001/ready
```

`migrate` 是一次性迁移服务，成功后显示 `Exited (0)` 属于正常状态。API、Worker、Beat 等待数据库迁移成功后启动。Caddy 自动申请并续期证书，支持 WebSocket，数据库和 Redis 不映射到公网。

初始化脚本生成的 `server/.env.production` 权限为 `0600`，包含独立随机密钥；重跑时会拒绝覆盖已有文件。不要公开此文件或提交到 Git。

生产 Compose 使用独立的 `eigent_*` 数据卷，不会自动接管旧 `server/docker-compose.yml` 的数据库。已有部署必须先备份，再明确迁移数据；不要把这套命令当作旧卷的原地升级。

## 创建首个管理员

```bash
dc exec api python scripts/manage.py bootstrap-admin --email admin@your-domain.com
```

命令交互输入密码及确认密码，不会将密码放入 Shell 历史。密码要求至少 8 个字符、包含字母与数字，且不超过 72 个 UTF-8 字节。数据库中已有管理员时，此命令拒绝再次初始化。

接口文档地址：`https://api.your-domain.com/docs`。管理员使用 Administration 下的登录操作获得管理员令牌；普通账户令牌不能访问管理接口。准确的请求和响应字段以该版本 OpenAPI 文档为准。

管理能力包含账户创建、审批、封禁、授权、重置密码、强制退出、设备撤销、管理员创建和停用、角色维护、审计与任务统计。管理界面尚未实现，当前通过 API 提供这些能力。

## 默认策略与客户端接入

- 生产环境禁用 debug 和免密自动登录，配置校验不通过时服务拒绝启动。
- 默认关闭公开注册。需要开放时，在 `.env.production` 设置 `ALLOW_REGISTRATION=true`，然后重建容器；`REGISTRATION_REQUIRE_APPROVAL=true` 表示新账户先由管理员审批。
- 封禁、改密、授权调整、设备撤销或退出会使旧访问令牌、刷新令牌失效；退出当前实现为账户全部会话退出。
- 普通账户能力为 `tasks:execute`、`models:use`、`sync:write`、`remote:control`。这些约束服务端接口，本机文件或终端仍需客户端自己的权限检查；无法通过服务端禁止用户脱离服务使用本地模型。
- 模型保持用户自配模式；本次没有增加平台模型代理、支付、按量扣费或邮件验证。账户激活采用管理员审批，不能将它视为邮箱所有权验证。
- `/api/v1/sync/capabilities` 显式声明同步能力。已支持事件接收及命令同步；没有声明支持云端历史还原、记忆或文件同步。
- 任务事件接收响应匹配现有本地引擎的事件确认字段，但旧客户端仍受官方域名判断限制。后续客户端需要按 capabilities 接入，不能直接启用包含其他未实现同步能力的整个 CloudSyncWorker。
- 新任务统计以幂等事件汇总，属于设备上报的运营数据，不能当作模型账单。旧 `/user/stat` 保持兼容，但拒绝客户端修改支付和注册计数。
- `PRIVATE_UPLOADS=true` 时截图读取需要账户令牌及资源归属校验；客户端图片展示需要以认证请求获取文件。匿名分享中的私有截图也不会绕过此限制。
- 桌面界面的请求地址与本地 Python 引擎的 `SERVER_URL` 都需改为你的服务。Electron 的 CORS origin 应按最终安装包实际来源加入明确的 allowlist；不要为排查跨域而开启通配来源。

## 更新部署

先备份，然后更新镜像及数据库：

```bash
sh scripts/backup.sh
git pull --ff-only origin codex/self-hosted-server
export SERVER_CODE_HASH="$(git log -1 --format=%H -- server/)"

# 停止写入服务，防止旧版本继续运行时迁移数据库
dc stop api celery_worker celery_beat
dc build api
dc run --rm migrate
dc --profile edge up -d --force-recreate
curl -f http://127.0.0.1:3001/ready
```

迁移失败时先排查 `migrate` 日志，不要继续启动旧代码与新结构混用。启动脚本和迁移服务均在命令失败时退出。

如果旧数据存在仅大小写不同的重复邮箱，本次新增的不区分大小写唯一索引会使迁移停止。应先备份并人工确认重复账户归属，再处理冲突；迁移不会擅自合并账户。

## 日志、备份与持久化

```bash
dc logs -f --tail=100 api celery_worker celery_beat
dc exec api alembic current
sh scripts/backup.sh

# 停止或启动应用，不删除数据卷
dc stop
dc --profile edge up -d
```

备份保存到 `server/backups/<UTC时间>/`，包含 PostgreSQL 自定义格式转储和上传文件压缩包。严格一致性备份应先停止写入；另行安全保存 `.env.production`。恢复时先停写，向匹配版本数据库还原，再恢复上传文件，核对迁移版本后启动。

持久化卷包含 PostgreSQL、Redis、上传文件、应用日志和 Caddy 证书。不要执行 `down -v`，它会删除这些数据。当前备份脚本不自动清理历史备份，需要按服务器容量安排留存及异机备份。

使用已有反向代理时，可以不启用 `edge` profile，将代理指向 `127.0.0.1:3001`，并把 `FORWARDED_ALLOW_IPS`、`REMOTE_CONTROL_TRUSTED_PROXY_HOSTS` 改为真实代理源地址。默认 Caddy 固定使用 `172.30.21.10`；若 `172.30.21.0/24` 与现有网络冲突，需要一起修改 Compose 子网、Caddy 地址和可信代理配置。

本分支默认使用单实例 Celery Beat。客户端离线或电脑休眠时，本地任务不会因服务端在线而自动执行。
