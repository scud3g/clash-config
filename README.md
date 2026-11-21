# clash-config

旁路由 nikki（mihomo）+ FlClash 桌面端的全套配置托管仓库，零敏感信息。

## 仓库文件

| 文件 | 用途 | 部署位置 |
|---|---|---|
| `nikki-skeleton.yaml` | 旁路由 nikki 骨架配置（策略组/规则集/分流规则） | Nikki Profile 订阅（jsDelivr）+ `_ip` 后缀规则集已含 |
| `flclash-script.js` | 电脑 FlClash 扩展脚本（动态分流，订阅手动填） | FlClash 配置脚本模式 |
| `nodeguard.sh` | 节点守护：健康检查 + 自动竞速切换 | 旁路由 `/root/nodeguard.sh`（cron 每 5 分钟） |
| `selfupdate.sh` | nodeguard 每日自动同步（版本哨兵防回滚） | 旁路由 `/root/selfupdate.sh`（cron 05:10） |
| `nodeguard.conf.example` | nodeguard 配置模板（含密钥，仓库只放 example） | 复制为旁路由 `/root/nodeguard.conf` |
| `README-nodeguard.md` | nodeguard 版本变更历史 | - |

## 快速使用

1. **旁路由**：Nikki 添加 Profile，订阅 URL 填 `https://fastly.jsdelivr.net/gh/scud3g/clash-config@main/nikki-skeleton.yaml`，机场订阅走本地 mixin 注入
2. **电脑**：FlClash 配置 → 右键订阅 → 拓展 → 脚本模式 → 选 `flclash-script.js`
3. **守护**：旁路由部署 `nodeguard.sh` + `selfupdate.sh` + `nodeguard.conf`（参考 example），crontab 见 README-nodeguard

> 仓库为公开只读托管，真订阅 token 只存旁路由本地 mixin，绝不上传。
