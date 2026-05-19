# Security Group Manager (安全组管理器)

#### [English](/README.md) | 简体中文
一个轻量级的守护进程，用于监控主机的公网 IPv4 地址，并在地址发生变化时自动同步阿里云 ECS 安全组规则。

## 特性

- **定时轮询**：以可配置的时间间隔轮询公网 IP 并检测变化。
- **批量同步**：通过单个阿里云 API 调用批量同步规则（每个方向一次）。
- **灵活策略**：支持每条规则配置 `allow` (允许) 和 `drop` (拒绝) 策略。
- **双向覆盖**：覆盖 `ingress` (入站)、`egress` (出站) 和 `all` (双向同时) 的规则组。
- **自动清理**：自动移除配置中已不存在的、由 SGM 管理的过期规则。
- **插件化架构**：基于插件的 IP 检测机制——内置两个插件，易于扩展。
- **环境变量覆盖**：支持通过环境变量覆盖凭证（适合 CI/CD 和容器环境）。
- **历史记录**：基于 SQLite 的 IP 变更历史记录，并提供 CLI 查看器。
- **日志轮转**：支持日志文件轮转，并针对不同平台使用合适的路径。

## 系统要求

- Python 3.11 或更高版本
- [uv](https://docs.astral.sh/uv/) (推荐) 或 pip
- `dig` 命令需在 PATH 环境变量中可用（仅 `DigFromMyIpOpenDns` 插件需要）

## 安装

### 使用 uv 从源码安装

```bash
git clone https://github.com/your-org/SecurityGroupManager.git
cd SecurityGroupManager
uv sync
```

### 作为包安装

```bash
uv pip install .
```

安装后，`sgm` 命令即可在你的环境中使用。

## 配置

复制或编辑 `cfg/sgm.yaml` 文件：

```yaml
plugins:
  ipv4:
    - DigFromMyIpOpenDns   # 按顺序尝试插件；第一个有效的 IPv4 获胜
    - SocketTrick

interval: 60              # 轮询间隔（秒），范围 5 - 86400

aliyun:
  ak: YOUR_ACCESS_KEY_ID
  sk: YOUR_ACCESS_KEY_SECRET

securityGroup:
  - id: sg-xxxxxxxxxxxxxxxx
    region: cn-hangzhou
    ingress:
      allow:
        - proto: tcp
          port: 22
        - proto: tcp
          port: 443
      drop:
        - proto: tcp
          port: 8080
    egress:
      allow:
        - proto: tcp
          port: 80
    all:                  # 同时应用于入站和出站
      allow:
        - proto: icmp
          port: 1
```

### 方向键说明

| 键名 | 应用范围 |
| :--- | :--- |
| `ingress` | 仅入站规则 |
| `egress` | 仅出站规则 |
| `all` | 同时应用于入站和出站 |

### 策略键说明

| 键名 | 阿里云策略 |
| :--- | :--- |
| `allow` | `accept` |
| `drop` | `drop` |

### 规则识别

SGM 创建的每条规则都会被打上 `description: "SGM auto managed"` 的标签。
**没有**此描述的规则永远不会被修改。

## 环境变量覆盖

凭证和时间间隔可以通过环境变量提供，其优先级高于 YAML 文件中的值。

| 变量名 | 配置路径 |
| :--- | :--- |
| `SGM_ALIYUN_AK` | `aliyun.ak` |
| `SGM_ALIYUN_SK` | `aliyun.sk` |
| `SGM_INTERVAL` | `interval` |

**示例：**

```bash
export SGM_ALIYUN_AK=LTAI5xxxxxx
export SGM_ALIYUN_SK=xxxxxxxxxxxxxxxxxxxxxx
sgm run
```

## CLI 使用方法

```
sgm [OPTIONS] COMMAND [ARGS]

Commands:
  run      启动 IP 监控守护进程
  check    执行单次 IP 检查并显示结果
  history  显示 IP 变更历史
```

### run

```bash
# 使用默认配置启动守护进程
sgm run

# 使用自定义配置文件
sgm run -c /etc/sgm/sgm.yaml

# 运行一次后退出 (适合 cron/systemd oneshot)
sgm run --once

# 启用调试日志
sgm run -v
```

### check

```bash
# 打印当前公网 IP 并在变更时同步
sgm check
```

### history

```bash
# 显示最近 10 次 IP 变更 (默认)
sgm history

# 显示最近 50 次变更
sgm history -n 50
```

### version

```bash
sgm --version
```

## 日志文件

日志文件会在达到 10 MB 时轮转，最多保留 5 个备份文件。

| 平台 | 路径 |
| :--- | :--- |
| Linux | `/var/log/sgm/sgm.log` |
| macOS | `~/Library/Logs/sgm/sgm.log` |
| Windows | `%USERPROFILE%\AppData\Local\sgm\sgm.log` |

## 同步逻辑

每次 IP 变更时，针对每个安全组，SGM 最多执行四个 API 调用：

1.  批量撤销旧 IP 的入站规则。
2.  批量撤销旧 IP 的出站规则。
3.  批量授权新 IP 的入站规则。
4.  批量授权新 IP 的出站规则。
5.  查询当前规则，并批量撤销当前配置中不存在的、由 SGM 管理的残留规则（过期规则清理）。

## 内置插件

### DigFromMyIpOpenDns

通过 `dig` 命令向 OpenDNS 解析器查询 `myip.opendns.com`。
需要系统安装 `dig` 二进制文件（`dnsutils` 或 `bind-tools` 软件包）。

### SocketTrick

向 `8.8.8.8:80` 打开一个 UDP 套接字，并读取操作系统选择的本地地址。
无需任何外部命令，但返回的是本地路由 IP 而非实际公网 IP（在大多数无 NAT 层的设置中是准确的）。

## 编写自定义插件

1.  在 `plugins/` 目录下创建一个 Python 文件。
2.  继承 `IpFetcherPlugin` 类并实现 `name` 和 `fetch` 方法。
3.  将类名添加到 `sgm.yaml` 的 `plugins.ipv4` 列表中。

```python
# plugins/my_plugin.py
import urllib.request
from ip_fetcher_plugin import IpFetcherPlugin

class MyPlugin(IpFetcherPlugin):

    @property
    def name(self) -> str:
        return "MyPlugin"

    def fetch(self) -> str | None:
        try:
            with urllib.request.urlopen("https://api4.ipify.org", timeout=5) as r:
                return r.read().decode().strip()
        except Exception as e:
            self.logger.error("MyPlugin error: %s", e)
            return None
```

```yaml
plugins:
  ipv4:
    - MyPlugin
    - DigFromMyIpOpenDns   # 备用方案
```

插件按顺序尝试；第一个返回有效 IPv4 地址的插件获胜。

## 作为 systemd 服务运行

**服务文件 (`/etc/systemd/system/sgm.service`):**

```ini
[Unit]
Description=Security Group Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/sgm/env
ExecStart=/usr/local/bin/sgm run -c /etc/sgm/sgm.yaml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**环境变量文件 (`/etc/sgm/env`):**

```
SGM_ALIYUN_AK=LTAI5xxxxxx
SGM_ALIYUN_SK=xxxxxxxxxxxxxxxxxxxxxx
```

## 开发

```bash
# 安装开发依赖
uv sync --extra dev

# 运行测试
uv run pytest

# 代码检查
uv run ruff check .

# 类型检查
uv run mypy .
```

## 许可证

MIT
