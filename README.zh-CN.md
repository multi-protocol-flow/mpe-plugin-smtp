# mpe-plugin-smtp

MPE SMTP 协议插件（Sidecar 进程）：提供连接（connect）、发送邮件（send）与断开连接（disconnect）能力。

## 节点

| 节点类型 | 端口 | 功能说明 |
|---|---|---|
| `smtp:connect` | in / true / false | 构建 SMTP 传输通道（隐式 TLS / STARTTLS / 明文），执行 `test_connection` 探测并存入当前执行生命周期的连接池 |
| `smtp:send` | in / true / false | 构建 MIME 邮件（纯文本 / HTML / 附件）并通过指定的连接发送 |
| `smtp:disconnect` | in / out | 释放指定的连接（非阻塞） |

- **分类**: `Email`，**主题色**: `#3b82f6`。
- `smtp:connect` 声明了 `capabilities.single_node: true`，支持通过 CLI 单节点测试（`mpe run-node`）或 GUI 测试连接。

## 构建与测试

```bash
cargo build --release          # 构建 release 二进制 → target/release/mpe_plugin_smtp
cargo test                     # 离线测试（单元测试 + stdio 协议往返测试）
cargo test -- --ignored        # 实时集成测试（需要本地/远程 SMTP 服务）
```

### 实时集成测试

设置 `MPE_SMTP_URI`（默认 `smtp://localhost:587`）指向可用 SMTP 服务：

```bash
MPE_SMTP_URI=smtp://localhost:1025 cargo test --release -- --ignored --test-threads=1
```

## 安装

将构建好的二进制文件放置在 `plugin.json` 指定的路径（默认同级目录 `./mpe_plugin_smtp`），并将插件目录配置到 `MPE_PLUGIN_DIR`。
`capabilities.streaming: true` 使插件进程在执行期间保持常驻，以维持连接池状态。
