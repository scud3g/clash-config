# nodeguard - mihomo 节点守护脚本

旁路由（OpenWrt/iStoreOS + Nikki/mihomo）节点健康守护：定时巡检，连续异常自动竞速切换，全程 30-60 秒恢复。零依赖（busybox 自带工具即可），日志写内存盘保护 eMMC。

## 工作流程

```
cron 每 5 分钟
  │
  ├─ 健康检查：204 连通 + 下载测速（108KB 固定文件，流量可控）
  │    健康要求：204 可达 且 吞吐 ≥ 30KB/s
  │
  ├─ 第 1 轮异常 → 只记录，不动节点（防抖）
  │
  └─ 连续 2 轮异常 → 竞速切换
       ├─ ① 全组并发延迟预筛（mihomo group delay API，33 节点约 3 秒）
       ├─ ② TOP5 + 当前节点逐个吞吐实测（每节点 1 次测速，6 秒封顶）
       ├─ ③ 决策：
       │     当前节点吞吐及格且排名前 3 → 维持（减少无谓切换）
       │     否则 → 切换到吞吐第 1 名
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
```

## 参数（脚本内可调）

| 参数 | 默认 | 说明 |
|---|---|---|
| THRESH_BPS | 30720 | 吞吐及格线（30KB/s），低于视为异常 |
| FAIL_TRIGGER | 2 | 连续异常轮数，达到才触发竞速（防抖） |
| TOP_PICK | 5 | 延迟预筛后进入实测的节点数 |
| CUR_KEEP_RANK | 3 | 当前节点守擂名次（且吞吐须及格才保位） |
| SPEED_MAX | 6 | 单次测速超时秒数 |

## 日志

`/tmp/nodeguard.log`（超过 200KB 自动截尾），关键标记：
- `OK  [节点] 204=... bps=...` —— 常规巡检记录
- `ACT 切换 [旧] -> [新]` —— 发生切换（含回读确认）
- `VER 切换后... 204=204` —— 切换后验证
- `SKIP 已有实例在运行` —— 上一轮没跑完，本轮跳过

## 迭代史（踩坑记录）

- v1：串行测全量节点，一轮 5 分钟 → 太慢
- v2：加防抖；实测发现测速样本太小摆动大 → 样本固定 108KB
- v3：竞速改预筛 + TOP5；发现节点名含空格被拆碎、切换“成功”实为假象
- v4：IFS 换行遍历保住完整名 + 切换后回读确认；发现 cron 并发偷跑
- v5：flock 单实例锁 + 单次测速 + 6s 封顶；发现弱候选垫底让差节点混进保位
- v6：保位加及格线门槛（当前版本）
