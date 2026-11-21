#!/bin/sh
# selfupdate.sh - nodeguard.sh 每日自动同步（方案A：GitHub 为唯一权威源）
# 逻辑：从 GitHub raw 拉最新 nodeguard.sh → md5 对比 → 不同才覆盖（先备份旧版）
# 安全性：语法校验失败不部署；拉取失败保持原状；备份保留最近 3 份；
#         部署前抢 nodeguard 单实例锁，nodeguard 运行中则顺延（防 05:10 同刻碰撞覆写运行中脚本）
# cron: 每日 05:10（错开 4:00 nikki 重启与 5 分钟一轮的 nodeguard 整点检查）

RAW_URL="https://raw.githubusercontent.com/scud3g/clash-config/main/nodeguard.sh"
JS_URL="https://cdn.jsdelivr.net/gh/scud3g/clash-config@main/nodeguard.sh"
TARGET=/root/nodeguard.sh
LOG=/tmp/selfupdate.log
TMP=/tmp/nodeguard.new

log() { echo "$(date '+%m-%d %H:%M:%S') $1" >> $LOG; }
[ -f $LOG ] && [ "$(wc -c < $LOG)" -gt 51200 ] && tail -50 $LOG > $LOG.new && mv $LOG.new $LOG

# 依次尝试 raw 直连 / jsDelivr，任一成功即用
curl -fsSL -m 30 "$RAW_URL" -o "$TMP" 2>/dev/null || curl -fsSL -m 30 "$JS_URL" -o "$TMP" 2>/dev/null || {
  log "SKIP 拉取失败(双通道)，保持现版本"
  exit 0
}

# 内容基本校验：文件头必须是 nodeguard 脚本（防止误拉 404 页面）
head -3 "$TMP" | grep -q "nodeguard.sh" || { log "SKIP 拉取内容异常(非脚本)，保持现版本"; rm -f "$TMP"; exit 0; }
# 语法校验
sh -n "$TMP" 2>/dev/null || { log "SKIP 语法校验失败，保持现版本"; rm -f "$TMP"; exit 0; }

NEW_MD5=$(md5sum "$TMP" | cut -d' ' -f1)
OLD_MD5=$(md5sum "$TARGET" 2>/dev/null | cut -d' ' -f1)
[ "$NEW_MD5" = "$OLD_MD5" ] && exit 0   # 无变化，静默退出（不记日志防噪音）

# ---- 部署前护栏：抢 nodeguard 单实例锁 ----
# nodeguard 正在运行（尤其竞速中段）时，其 flock 持有 /tmp/nodeguard.single；
# selfupdate 抢不到锁则顺延到明天（每日低频任务无急迫性），绝不覆写运行中的脚本。
# 抢到锁后持锁完成 cp：碰撞窗口内新启动的 nodeguard 抢锁失败自动 SKIP，下一轮 05:15 起跑新版。
exec 8>/tmp/nodeguard.single
if ! flock -n 8; then
  log "SKIP nodeguard 正在运行，顺延本次更新"
  exit 0
fi

# 部署：备份→覆盖→赋权→首跑校验（失败自动回滚）
BAK="/root/nodeguard.sh.bak.$(date '+%Y%m%d_%H%M')"
cp "$TARGET" "$BAK" || { log "ERR 备份失败，放弃更新"; rm -f "$TMP"; exit 1; }
cp "$TMP" "$TARGET" && chmod +x "$TARGET" || { log "ERR 覆盖失败，回滚"; cp "$BAK" "$TARGET"; rm -f "$TMP"; exit 1; }
log "UPD nodeguard.sh 已更新 ($OLD_MD5 -> $NEW_MD5)，备份 $BAK"

# 保留最近 3 份备份
ls -1t /root/nodeguard.sh.bak.* 2>/dev/null | tail -n +4 | while read f; do rm -f "$f"; done
