# RustFS 功能清单

对照 `/Users/muxin/workspace/github/rustfs` 当前代码整理，不是 README 宣传表的照抄。状态取自路由注册和处理函数：已实现、部分实现（能存配置但不执行，或只覆盖一部分）、仅占位（路由存在但返回未实现）、不存在。

产品本身是一个进程：S3 兼容对象存储，纠删码落盘，同一进程上还挂着 MinIO 风格的管理 API、内嵌控制台、节点间 gRPC。默认端口：API `:9000`，控制台 `:9001`。工作区版本 `1.0.2`（`Cargo.toml`），Helm / RPM / README 镜像标的是 `1.0.3`。协议 Apache-2.0。

重写时按层看，不要按 crate 目录一比一搬。下面每一节是一块独立能力。

## 1. 部署形态

- 单节点单盘（SNSD，`xl-single`，奇偶为 0）。不能就地扩容，也不能加入已有集群。
- 单节点多盘、多节点多盘。纠删集合 2–16 块盘，默认奇偶随盘数变：2–3 块为 1，4–5 为 2，6–7 为 3，其余为 4。`REDUCED_REDUNDANCY` 把奇偶降到 1。
- 集群成员是静态的。卷列表来自命令行或 `RUSTFS_VOLUMES`，支持省略号展开（`http://rustfs-{0...3}:9000/data/rustfs{0...3}`）。没有 etcd、Consul 或 gossip 发现。
- 扩容只能追加 Pool。Pool 内重平衡、退役（decommission）、取消退役都有管理接口。退役在端点未初始化时返回未实现。
- 节点间通信是 gRPC（tonic）。RPC 密钥来自 `RUSTFS_RPC_SECRET`，或由 root 密钥派生。
- 部署物：Docker / Compose、systemd 单元、Helm（单机与分布式）、Nix flake、RPM spec。
- 启动配置是命令行加环境变量，没有运维手编的配置文件。运行期配置是落在 ECStore 里的 JSON KV。
- 进程内自升级是占位：`POST /v3/update` 明确返回未应用。滚动重启是运维手册。
- 产品许可证是可选 Cargo feature，默认关闭。打开后，没有许可证启动失败。源码协议本身是 Apache-2.0。

## 2. 存储引擎

- 纠删码格式 `format.json`，纠删 V3。分布算法 `SIPMOD+PARITY`，读取兼容 CRCMOD / SIPMOD。
- Reed–Solomon：编码、数据重建、奇偶重建、校验。写法定人数：奇偶为 0 或不小于盘数时要求全部盘；否则写法定人数是数据盘数，数据盘数等于奇偶数时加 1。缺失响应法定人数是总数的一半。
- 对象元数据 `xl.meta`（头 `XL2 `，版本 3，MessagePack）。版本列表、删除标记、内联小对象、转储的 free-version 记录都在里面。能读 MinIO 未加密的 `xl.meta`（meta_ver 1–3）以及 `.metadata.bin` 和 `config/iam/`。
- 默认构建读不了 MinIO 加密对象。`rio-v2` feature 才走 MinIO 盘上格式兼容，且不在 `default` 和 `full` 里。MinIO KES / KMS 插件加密的对象明确不读，文档写的是不打算做。RustFS 的盘也不能被 MinIO 读（`.rustfs.sys` 对 `.minio.sys`）。
- Bitrot：每分片哈希帧。默认 HighwayHash256S，另有 SHA-256、HighwayHash256、BLAKE2b-512、MD5、无。启动自检，可以设严格模式。
- S3 校验和盘上 bitrot 是两套。S3 侧支持 CRC32、CRC32C、CRC64NVME、SHA1、SHA256、SHA512、XXH3、XXH64、XXH128，含尾随校验。
- 落盘压缩按扩展名 / MIME 可选。算法 lz4（默认）、gzip、deflate、zstd、brotli、snappy。上传、拷贝、解压上传、分片上传都走压缩；下载用区间解压。
- 进程内对象体缓存（内存 / moka / 空实现），singleflight，写入后失效。
- 写路径管道 `rio`：加密、压缩、哈希、写盘串在一条异步管道里。
- 对象键含 `.`、`..` 或空路径段返回 400。这是盘上布局约束，不是漏实现。
- 背后盘拒绝 NFS、CIFS、FUSE。这是底层文件系统限制，不是对外提供这些协议。

## 3. S3 数据面：已实现

S3 接口挂在 `s3s` trait 上（`rustfs/src/storage/ecfs.rs`）。没有覆盖的方法默认返回未实现。

桶

- 创建、删除、Head、列出、位置（Location）。
- 桶策略、策略状态（`IsPublic`）。
- 桶与对象标签的读写删。
- CORS：按桶规则（源、方法、头、预检），另加一层全局 `ENV_CORS_ALLOWED_ORIGINS`。
- 网站托管：配置的读写删，以及网站域名上的 GET/HEAD。索引文档、错误文档、全站重定向、路由规则、对象级 `x-amz-website-redirect-location`。
- 通知配置的读写。删除是用空 PUT 清掉，没有单独的 DELETE。
- 加密配置的读写删，作为请求未带 SSE 时的默认。
- 复制配置的读写删。
- 生命周期配置的读写删。
- 公开访问阻断的读写删（执行范围见下面“部分实现”）。
- 桶配额：只有 Hard。超额返回 `QuotaExceeded`。持久化预留协议 v1 和 v2。没有用户配额。

对象

- Put、Get、Head、Delete、DeleteObjects、Copy、GetObjectAttributes。
- POST 表单上传，走 `put_object`。表单上传和 zip 解压上传拒绝 SSE-KMS。
- 分段上传：创建、上传分段、拷贝分段、完成、中止、列出上传、列出分段。
- 范围读、条件读、条件写、条件批量删除（有文档写明的限制）。
- 用户元数据。
- 预签名：SigV4 和 SigV2 查询串。预签名请求上未签名的 `x-amz-*` 头会被拒绝。
- 存储类别写入只接受 `STANDARD` 和 `REDUCED_REDUNDANCY`。Glacier、IA、Intelligent-Tiering 在写入时拒绝；读取时除非对象是生命周期转储过去的，否则归一成 `STANDARD`。
- 对象解压上传（snowball 自动解压）。
- 管理接口上的对象 zip 下载。

版本与锁定

- 桶版本控制：Enabled 与 Suspended。读取时按前缀判断版本状态。版本化桶里的目录标记保持为 null 版本。
- ListObjectVersions、删除标记。
- Object Lock：Governance 与 Compliance。法律保持。默认保留在 Put 时写入。Governance 可以用 `x-amz-bypass-governance-retention` 加 `s3:BypassGovernanceRetention` 绕过；Compliance 不能。
- 保留与法律保持的读写：桶级配置、对象级 retention、对象级 legal hold。

加密

- SSE-S3：AES-256，服务端管理密钥。没有 KMS 时要 `RUSTFS_SSE_S3_MASTER_KEY`，这批对象不能轮换。
- SSE-KMS：Put、Get、分段上传。没有运行中的 KMS 时直接拒绝，不会降级到本地主密钥。
- SSE-C：客户密钥、算法、MD5。拷贝和分段上传必须保持同一模式。可要求 TLS。
- KMS 后端：Local、Static（仅开发测试）、Vault KV2、Vault Transit、AWS KMS。密钥缓存、删除后台任务、备份与恢复。管理接口覆盖创建、描述、列出、启用、停用、轮换、重加密、标签、启停、重载、配置。

生命周期（ILM）

- 当前版本过期删除、非当前版本删除、删除全部版本、删除标记过期、恢复对象过期。
- 中止未完成的分段上传（`DaysAfterInitiation`），在扫描陈旧上传时执行。
- 当前与非当前版本转储到温层。状态写在 `xl.meta`，有远端删除日志和 free-version 恢复。
- 过滤：前缀、标签、大小、Object Lock 边界。
- 执行者是后台 scanner，不是请求路径。

转储与温层

- 温层类型：S3、Wasabi、RustFS、MinIO、阿里云、腾讯、华为、Azure、GCS、R2。
- Azure 的 storage-class 和 service-principal 认证被拒绝。GCS 是默认 feature。
- 转储对象的 RestoreObject 已实现。从归档做 Select 返回未实现。
- 管理接口：层的列出、读、写、删、清空、统计，加上 ILM 转储与恢复。

复制

- 桶复制：规则、过滤、标签。后台复制 Put 和 Delete。已有对象复制、删除标记复制、副本修改。MRF 积压、重同步、带宽限制。
- 站点复制：与桶复制分开。对端状态、HTTP 传输、重试队列、修复、桶与 IAM 广播。站点复制开启时非属主不能改复制配置。管理接口有加、删、信息、状态、加入、编辑、修复、重同步、对端 IAM 和桶元数据。`/v3/site-replication/netperf` 明确不做对端流量。
- 远端复制目标的读写删、指标、差异、MRF。
- 没有按对象的复制差异接口。复制指标在管理接口 `/v3/replicationmetrics`，不是 S3 的 `GetBucketReplicationMetrics`。

S3 Select

- 对 CSV、JSON、Parquet 做 SQL（DataFusion），输出 CSV 或 JSON。部分输入压缩组合被拒绝。

事件

- 桶通知目标：webhook、AMQP、Kafka、MQTT、NATS、Redis、MySQL、Postgres、Pulsar。没有 Elasticsearch 和 NSQ。
- ListenBucketNotification：MinIO 兼容的过滤 SSE 流，在 `s3s` 之前就被路由接走。trait 本身的同名方法仍是默认未实现。

## 4. S3 数据面：部分实现或仅占位

- ACL：Get 返回合成的所有者 ACL。带 XML grant 体的 Put 返回未实现。不带 grant 的 Put 返回成功但什么都不存。授权不走 ACL。
- 公开访问阻断：`BlockPublicPolicy` 拒绝公开桶策略；`RestrictPublicBuckets` 即使策略允许也拒绝匿名访问。`IgnorePublicAcls` 读进来之后丢弃。
- 传输加速：XML 能存能读，没有加速路径。
- 请求方付费：XML 能存能读，默认付费方是桶所有者，没有计费。
- 服务器访问日志：配置存成 `logging.xml` 并能读回，没有投递日志的后台任务。s3tests 仍标为未实现。
- GetObjectTorrent：固定返回 `NoSuchKey`，不是 501。注释写明不实现。
- Object Lambda：只有 MinIO 风格的 GET webhook 代理。`WriteGetObjectResponse` 没有覆盖。
- 批量作业（MinIO batch）：路由识别 replicate、keyrotate、expire，然后返回不支持。没有执行引擎。
- 桶通知、日志、请求方付费、加速的删除：都是空 PUT 清空，没有单独 DELETE。

## 5. S3 数据面：没有实现

这些方法没有覆盖，走 `s3s` 默认的未实现：

- 桶分析、桶指标、桶清单（inventory）的读写删列。
- Intelligent-Tiering 配置。
- Ownership controls。
- 桶 ABAC。
- S3 Metadata 表配置，以及 journal、inventory、annotation 更新。
- 对象 annotation。
- `CreateSession`、`ListDirectoryBuckets`。
- `RenameObject`（`s3s` 编进了 MinIO 的这个能力，RustFS 没有实现）。
- `UpdateObjectEncryption`。
- `WriteGetObjectResponse`。
- Access Point 和 Outpost 作为拷贝源。
- S3 Batch 执行。仓库里名为 batch 的模块是磁盘 IO 扇出，不是 S3 Batch。

## 6. 后台任务

- Scanner：数据用量扫描。对每个对象可以放行修复、套用生命周期、排复制修复队列。可以关掉（`RUSTFS_SCANNER_ENABLED`）。
- Heal：对象、桶、纠删集合、元数据。队列、调度、自动扫描、不清洁关机与根目录恢复、断点续传、MRF 队列。对象修复会重建分片，也可以清掉删除标记。可以关掉（`RUSTFS_HEAL_ENABLED`）。
- 重平衡与数据搬迁：Pool 重平衡工作器，元数据迁移。
- 按需迁移：独立的后台工作器，有管理接口，可以关掉。
- 容量扫描与刷新。
- 完整性任务。
- 模块开关有管理接口：scanner、heal、bitrot 自检、按需迁移。

## 7. 身份与授权

- IAM 用户：创建、列出、查询、删除、启用、停用、轮换密钥。
- 组：列出、查询、删除、状态、加入和移出成员。
- 服务账号：增、改、查、列、删，单个和批量别名。
- 临时账号与 STS 账号：创建、列出、删除、撤销。
- STS `AssumeRole`：SigV4，时长被夹紧，会话策略，MFA 门。
- STS `AssumeRoleWithWebIdentity`。
- 会话令牌是用 root 密钥签名的 JWT。
- Root 凭据：`RUSTFS_ACCESS_KEY` / `RUSTFS_SECRET_KEY`，默认 `rustfsadmin` / `rustfsadmin`。密码修改和完整 MFA 是给 IAM 用户的，不是 root。
- IAM 策略是 AWS 风格的 JSON。条件子集：String、Numeric、Date、Bool、Null、IpAddress、Binary，加 `ForAllValues` / `ForAnyValue` / `*IfExists`。LDAP 和 JWT 的 claim 键被当条件键识别，但没有 LDAP 登录后端。
- 预置策略：`readwrite`、`readonly`、`writeonly`、`diagnostics`、`consoleAdmin`，加上 KMS 模板 `KMSKeyAdministrator` / `KMSKeyUser`。
- 策略绑定到用户或组。IAM 导入导出（zip，含 v2）。
- 鉴权顺序：先 IAM 策略，再桶策略。匿名访问只有桶策略授权时才放行，显式 Deny 先判。
- OIDC：发现、配置、回调、登出、校验。管理接口在 `/v3/oidc/`。Web Identity STS 用它。
- MFA：TOTP、恢复码、管理员重置。IAM 主密钥缺失时注册返回未实现。策略条件 `aws:MultiFactorAuthPresent` 文档写明未实现。
- 外部策略插件：OPA 风格的 HTTP 判定。
- OpenStack Keystone：可选。v3 token、EC2 凭据、角色到策略的映射。
- 每用户 SSH 公钥，给 SFTP 用。
- LDAP：仅占位。管理路由存在，返回未实现。没有 bind 或登录。
- 通用 `idp-config` 的写和删：占位，提示改用 `/v3/oidc/config/{provider_id}`。

## 8. 管理 API

正式前缀 `/rustfs/admin`。`/minio/admin/...` 被改写到这个前缀。路由策略表有 339 条。下面只列能力，不逐条列路径。

已实现

- 集群信息、存储信息、数据用量。
- 实时指标流：NDJSON，最多 120 个样本。不是 Prometheus 文本。
- 配置 KV 与全量配置：读、写、删、帮助、历史、恢复。
- 修复：全局、按桶、按前缀，后台状态、MRF、替换恢复。
- 服务：`restart`、`stop`、`freeze`、`unfreeze`。重启和停止是进程优雅退出，要监管进程再拉起来。
- 锁：当前锁、强制解锁。
- 站点复制、远端复制目标、KMS、温层、桶配额。
- Pool：列出、状态、退役、取消、清除。布局不允许时部分路径返回未实现。
- 重平衡：启动、状态、停止。
- Scanner 状态，用量与周期重置。
- 审计目标、通知目标。
- TLS 证书发布、状态、调试；证书目录与重载。HTTP/3 是可选 feature。
- 集群快照、扩展、插件。
- 桶元数据导出导入、孤儿恢复。
- 按需迁移、桶耐久性、完整性任务。
- 速度测试：磁盘指标、客户端 `/devnull`、节点间网络是真的。对象与站点基准测试不支持。
- 健康检查：`/health` 与 `/health/ready`，API 端口和控制台前缀下都有。就绪要等存储接纳。

部分或占位

- 跟踪：注册的路由把修复和 scanner 事件以 MinIO 形状的 NDJSON 流出来。另一个未注册的 `Trace` 处理函数仍返回未实现。
- `inspect-data`：返回对象字节。加密诊断归档没做。
- 性能分析：进程内 pprof 全部 501。文档指向进程外的 Pyroscope，那是可选 feature。
- 批量作业：见上。
- 进程内升级：见上。

不存在

- 独立的带宽管理路由。桶带宽记账只在复制目标内部使用。
- 原生 Prometheus 抓取端点（没有 `/minio/v2/metrics`）。`PrometheusAdminAction` 只出现在预置策略里。
- `/v3/top/drives` 和 `/v3/top/net`。只有 `/v3/top/locks`。
- 用户配额。

## 9. 可观测性

- 进程内指标用 Prometheus 命名：节点、集群、磁盘、纠删集合、IAM、用量、scanner、ILM、温层、复制、审计、通知、请求、CPU、内存、网络、进程，GPU 可选。
- 导出走 OTLP（指标、追踪、日志）。环境变量 `RUSTFS_OBS_ENDPOINT`。Compose 里 Prometheus 抓的是 collector 的 `:8889`，不是 RustFS 本身。
- 日志：标准输出和轮转文件，可选 OTLP 日志。
- 审计日志：多目标扇出，热重载，目标类型与通知相同，可以关掉。
- 离线日志诊断：`rustfs diagnose`，用规则匹配失败模式。
- 可选的性能分析：Pyroscope、Tokio 运行时遥测（`dial9`）、hotpath。

## 10. 控制台与其他协议

- 控制台不是单独的二进制。静态资源用 `rust-embed` 打进二进制，默认监听 `:9001`，前缀 `/rustfs/console`。这个仓库里没有前端源码：`rustfs/static/` 被 gitignore，构建脚本从 `dl.rustfs.com` 下载 zip。控制台能做什么取决于那个包，不在本仓库可核对。
- 控制台没有自己的 RPC。它是一个 SPA，调管理 API 和 S3 API。
- 本仓库没有 mc 风格的客户端。Nix flake 会另外下载 `rustfs/cli` 的 `rc`。
- 服务器自带的子命令：`server`、`info`、`tls inspect`、`diagnose`、离线 `inspect bucket-meta`、`connect`（注册、许可证、中继、报告、清单、性能、分析、健康、日志、遥测、top、对象检查）。
- FTP：和 FTPS 同一个服务，关掉 TLS 就是明文。默认 `:8021`。
- FTPS：默认 feature，默认 `:8022`。续传和追加不支持。
- WebDAV：默认 feature，默认 `:8080`。
- SFTP：不在默认构建里，要 `sftp` 或 `full` feature。默认 `:2222`。认证用 IAM 用户和 SSH 公钥。
- Swift：不在默认构建里。账户、容器、对象、SLO、DLO、tempurl。
- 这四个协议的授权都走同一套 IAM 和桶策略。
- NFS 作为对外协议：不存在。

## 11. Iceberg / S3 Tables（预览）

- Iceberg REST Catalog 搭在 RustFS 数据平面上，路径 `/iceberg/v1` 和 `/_iceberg/v1`。
- 不是 AWS S3 Tables 控制面的对等，也不覆盖厂商的 Iceberg 扩展。
- 自动化覆盖的客户端：PyIceberg 和 DuckDB。Spark 和 Trino 是手动验证（Trino 只读）。StarRocks、Snowflake 以及 AWS、MinIO AIStor、R2、阿里云 OSS 的配置只是生成器或参考，没有声称实际互通。
- 多表事务：不声称。目录的持久备份与恢复：预览。DuckDB 下删表清理和 Iceberg v3 会失败关闭。

## 12. 重写时建议剔掉的部分

这些在仓库里占着路由或文档位置，但没有行为。用 V 重写时不要当成必做项：

- ACL 授权、桶所有权控制、torrent、传输加速行为、请求方付费计费、服务器访问日志投递。
- S3 分析、指标配置、清单、Intelligent-Tiering 配置、桶 ABAC、S3 Metadata 表、`CreateSession`、`RenameObject`、`UpdateObjectEncryption`、`WriteGetObjectResponse`。
- LDAP 登录、用户配额、进程内 pprof、进程内自升级、MinIO 批量作业、原生 Prometheus 抓取。
- MinIO KES 加密对象的读取。文档写明不打算做。
- 控制台前端。它不在这个仓库里，重写服务端不需要它。
