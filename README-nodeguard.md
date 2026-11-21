# nodeguard 节点守护

mihomo/nikki mihomo API 守护脚本，旁路由（iStoreOS）每 5 分钟 cron 一轮。

## 部署
- `/root/nodeguard.sh`（cron `*/5 * * * *`）+ `/root/nodeguard.conf`（参考 `nodeguard.conf.example`，含密钥不入仓）
- `/root/selfupdate.sh`（cron `10 5 * * *`）每日从本仓库拉最新 nodeguard.sh：语法校验 → 版本哨兵（拒旧版回滚）→ md5 对比 → 抢 nodeguard 单实例锁互斥（运行中顺延）→ 备份部署，保留最近 3 份备份

## v8.1（2026-11-21，第3轮代码审查后小修）
1. **E4 修复**：状态文件非法值（如 `v8:xyz`）会让防抖算术乱算，v8.1 加 `case "$FAIL_N" in ''|*[!0-9]*) FAIL_N=0 ;; esac` 容错归零
2. **selfupdate 加护锁**：selfupdate.sh 部署前抢 nodeguard 单实例锁，nodeguard 运行中（尤其竞速中段）则顺延到明天，解决 05:10 cron 同刻碰撞可能覆写运行中脚本的风险；selfupdate.sh 首次入仓（此前仅存于路由器本地）

## selfupdate v3（2026-11-21，仓库文件三轮审查）
- **版本哨兵**：拉取内容的 `nodeguard.sh vX` 主版本号低于本地版则拒部署（防 CDN 过期缓存回滚线上；实测证明 v2 无此护栏时 v7 权重内容会把 v8.1 回滚）

## flclash-script.js v1.1（2026-11-21，仓库文件三轮审查）
- **缓存互覆修复**：`mrs()` 缓存路径按 behavior 加 `_ip` 后缀，修 geoip/geosite 同名 .mrs 四对碰撞（private/telegram/netflix/cn）；EXCLUDE 补 `剩余|重置` 与 nikki 对齐；Prime Video 统一 🎥；DNS 监听 127.0.0.1；注释计数修正（25 规则集/26 策略组）

## v8（2026-11-21，外部AI评审实测验证后发布）
1. **429 免疫**：Google 429 是限流非污染，不再误触发竞速（旧版 ` [45]` 匹配会误判）
2. **awk 候选解析**：按最后一个冒号分割，节点名含冒号不再碎裂（D5）
3. **排序修复**：busybox `sort -t: -k2 -n` 实测失效（候选顺序随机），改 awk 取末段数值 + `sort -n`
4. **计费节点过滤**：候选排除 倍率/勿跑大流量/过期/失联 节点（旧版会把 5 倍率警示节点送进竞速名单且当选后全家按 5 倍计费）
5. **竞速提速**：TOP_PICK 5→3、测速 6s→4s、204 3s→2s、切换后立即回读，实测全程 90s→25s
6. **状态重启保留**：/root/.nodeguard.state（/tmp 重启丢失问题，D6）
7. 保留 v7 全部机制：Google 三态检测(浏览器UA)/分级触发/池内最快当选+15%平局容差/单实例锁/回读确认/全灭回退

## v7
Google 防污染（浏览器 UA 三态检测）+ 分级触发（重度当轮竞速/轻度2轮防抖）+ 竞速池内最快当选（废除前3保位）+ 平局容差 + 状态文件 v7:N + awk urlencode（修 busybox 无 od）

## v6 及更早
见 git history。
