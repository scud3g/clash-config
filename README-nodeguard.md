# nodeguard - mihomo 节点守护脚本

旁路由（OpenWrt/iStoreOS + Nikki/mihomo）节点健康守护：定时三重巡检（Google 防污染 + 204 连通 + 吞吐测速），分级触发竞速，全程 30-60 秒恢复。零依赖（busybox 自带工具即可），日志写内存盘保护 eMMC。

## 工作流程

```
cron 每 5 分钟
  │
  ├─ 健康检查（三重门）
  │    ① Google 防污染：浏览器 UA 访问 www.google.com
  │       落地 google.cn / 超时 = 污染；落地 google.com(.hk) 200 = 干净
  │       （必须带浏览器 UA：curl 默认 UA 下 Google 对部分污染节点
  │         返回正常跳转，浏览器 UA 下才 302→google.cn/m 404）
  │    ② 204 连通：gstatic generate_204
  │    ③ 吞吐测速：108KB 固定文件（流量可控）
  │    健康要求：三者全部通过。任一不过 → 分级判定
  │
  ├─ 分级触发
  │    重度异常（Google 污染 / 204 失败 / 吞吐 < 15KB/s）
  │      → 当轮立即竞速（坏节点最多停留 5 分钟）
  │    轻度异常（吞吐 15~30KB/s，可能是瞬时抖动）
  │      → 连续 2 轮才竞速（防抖）
  │
  └─ 竞速切换
       ├─ ① 全组并发延迟预筛（mihomo group delay API，排除订阅信息假节点）
       ├─ ② TOP5 + 当前节点逐个过门：Google + 204 两道门 + 吞吐实测
       ├─ ③ 决策——池内最快当选：
       │     只有过两道门的节点才进候选池
       │     池内按吞吐选最高，全部低于及格线也选最高的
       │     当前节点非最快即切（平局容差：与最优差 ≤15% 且及格则维持）
       └─ ④ 切换后回读确认，未生效自动回退
```

## 部署

```sh
# 1. 放脚本
scp nodeguard.sh root@ROUTER:/root/nodeguard.sh
ssh root@ROUTER 'chmod +x /root/nodeguard.sh'

# 2. 建配置（密钥外置，勿上传）
cat > /root/nodeguard.conf <<'EOF'
NG_SECRET="Bearer YOUR_MIHOMO_SECRET"
NG_API="http://127.0.0.1:9090"
NG_GROUP_SEL="🚀 节点选择"
EOF

# 3. 挂 cron
crontab -e
# 追加：
# */5 * * * * /root/nodeguard.sh

# 4. 手动试跑
sh /root/nodeguard.sh && tail -5 /tmp/nodeguard.log

# 5.（可选）自动同步：用 selfupdate.sh 每日从本仓库拉最新版
#    详见 README 仓库首页说明
```

## 参数（脚本内可调）

| 参数 | 默认 | 说明 |
|---|---|---|
| THRESH_BPS | 30720 | 吞吐及格线（30KB/s），低于视为异常 |
| SEVERE_BPS | 15360 | 重度线（15KB/s），低于则当轮立即竞速不防抖 |
| FAIL_TRIGGER | 2 | 轻度异常连续轮数，达到才触发竞速（防抖） |
| TOP_PICK | 5 | 延迟预筛后进入实测的节点数 |
| TIE_PCT | 15 | 平局容差百分比，与最优差距小于此值且及格则维持 |
| SPEED_MAX | 6 | 单次测速超时秒数 |

## 日志

`/tmp/nodeguard.log`（超过 200KB 自动截尾），关键标记：
- `OK  [节点] google=干净 204=... bps=...` —— 常规巡检记录
- `WARN ... 重度异常(...) 当轮立即竞速` —— 三重门重度失败
- `WARN ... 轻度异常... 第 N 轮不切` —— 轻度防抖计数
- `实测: 节点 => Google污染 跳过` —— 竞速门禁拦截
- `ACT 切换 [旧] -> [新]` —— 发生切换（含回读确认）
- `VER 切换后... 204=204 google=干净` —— 切换后验证
- `SKIP 已有实例在运行` —— 上一轮没跑完，本轮跳过

## 迭代史（踩坑记录）

- v1：串行测全量节点，一轮 5 分钟 → 太慢
- v2：加防抖；实测发现测速样本太小摆动大 → 样本固定 108KB
- v3：竞速改预筛 + TOP5；发现节点名含空格被拆碎、切换“成功”实为假象
- v4：IFS 换行遍历保住完整名 + 切换后回读确认；发现 cron 并发偷跑
- v5：flock 单实例锁 + 单次测速 + 6s 封顶；发现弱候选垫底让差节点混进保位
- v6：保位加及格线门槛；上线后发现 204/吞吐对 Google 污染完全失明
- v7（当前）：Google 防污染三重门（浏览器 UA）+ 分级触发 + 池内最快当选；
  修复 od 编码依赖（busybox 无 od applet，改 awk 逐字节）；
  exclude-filter 同步修复（勿跑大流量类节点不再被误杀）
