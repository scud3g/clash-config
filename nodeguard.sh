#!/bin/sh
# nodeguard.sh v6 - 节点守护：并发预筛 + TOP5实测 + CUR保位带门槛 + 单实例锁
# 配置外置版：密钥/接口地址/策略组名从 /root/nodeguard.conf 读取（见 nodeguard.conf.example），本脚本零敏感信息
# v6 修订（v5 验证发现保位规则漏洞）：
#   BUG: CUR 在弱候选名单里排名前3就保位——差节点被免死金牌留住
#   修: 保位双条件——CUR 吞吐≥及格线(30KB/s) 且 排名前3，两个都满足才维持；
#       CUR 低于及格线（触发竞速的本来就是异常节点）→ 直接切最优
# v5 保留：单实例 flock 锁 / 候选1次测速 / 6s 测速封顶 / 3s 候选204 / 回读确认
#   1. 单实例锁：上一轮还在跑（竞速中）时，cron 本轮直接跳过
#      （曾发现 cron 整点与手动测试并发偷跑，两实例同时切节点互相污染数据）
#   2. 候选测速 2次→1次：冠军有切换后 VER + 下轮健康检查兜底，竞速省约40%
#   3. 测速超时 15s→6s：截断下载 curl 仍输出真实平均速度；
#      30KB/s 及格线下载 108KB 仅需 3.6s，慢于 18KB/s 的必截断且必不合格
#   4. 候选 204 检查 5s→3s：预筛已证明该节点 3s 内应答过
# v4 保留：空格名 IFS 遍历 / 切换回读确认 / CUR 前3保位 / 全灭回退保原状

CONF=/root/nodeguard.conf
[ -f "$CONF" ] || { echo "缺少 $CONF，参考 nodeguard.conf.example 创建" >&2; exit 1; }
. "$CONF"
: "${NG_SECRET:?NG_SECRET 未配置}"
: "${NG_API:?NG_API 未配置}"
: "${NG_GROUP_SEL:?NG_GROUP_SEL 未配置}"

AH="Authorization: $NG_SECRET"
API="$NG_API"

# 策略组名 -> URL 编码（UTF-8，支持中文/emoji/空格）
urlencode() { printf "%s" "$1" | od -An -tx1 | tr -s " " "\n" | grep -v "^$" | while read -r b; do printf "%%%s" "$b"; done; }
SEL="$API/proxies/$(urlencode "$NG_GROUP_SEL")"
GRP="$API/group/$(urlencode "$NG_GROUP_SEL")"
STATE=/tmp/nodeguard.state
LOG=/tmp/nodeguard.log
RACE_RES=/tmp/nodeguard.race
LOCK=/tmp/nodeguard.single
THRESH_BPS=30720
FAIL_TRIGGER=2
TOP_PICK=5
CUR_KEEP_RANK=3
SPEED_MAX=6
SPEED_URL="https://i.ytimg.com/vi/aqz-KE-bpKQ/maxresdefault.jpg"

log() { echo "$(date '+%m-%d %H:%M:%S') $1" >> $LOG; }
[ -f $LOG ] && [ "$(wc -c < $LOG)" -gt 204800 ] && tail -100 $LOG > $LOG.new && mv $LOG.new $LOG

# ---- 单实例锁（上一轮未结束则本轮跳过） ----
if [ -x /usr/bin/flock ]; then
  exec 9>"$LOCK"
  flock -n 9 || { log "SKIP 已有实例在运行，本轮跳过"; exit 0; }
else
  mkdir "$LOCK" 2>/dev/null || { log "SKIP 已有实例在运行，本轮跳过"; exit 0; }
  OLD=$(find "$LOCK" -mmin +10 2>/dev/null)
  [ -n "$OLD" ] && rm -rf "$LOCK" && exec 9>"$LOCK" && flock -n 9
fi

speed_test() { curl -s -o /dev/null -w "%{speed_download}" -m $SPEED_MAX "$SPEED_URL" | cut -d. -f1; }
get_now() { curl -s -m 5 -H "$AH" "$SEL" | sed 's/.*"now":"//;s/".*//'; }
put_node() { curl -s -m 8 -X PUT "$SEL" -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"$1\"}" >/dev/null; }

FAIL_N=0
[ -f $STATE ] && FAIL_N=$(cat $STATE)

curl -s -m 5 -H "$AH" "$API/version" >/dev/null 2>&1 || { log "WARN mihomo 不可达跳过"; exit 0; }

CUR=$(get_now)
[ -z "$CUR" ] && { log "WARN 读节点选择失败跳过"; exit 0; }

# ---- 健康检查：204 + 1次测速（可疑才复测防毛刺） ----
R204=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://www.gstatic.com/generate_204")
BEST_BPS=$(speed_test)
[ -z "$BEST_BPS" ] && BEST_BPS=0
SUSPECT=0
[ "$R204" != "204" ] && SUSPECT=1
[ "$BEST_BPS" -lt "$THRESH_BPS" ] && SUSPECT=1
if [ $SUSPECT -eq 1 ]; then
  B2=$(speed_test)
  [ -n "$B2" ] && [ "$B2" -gt "$BEST_BPS" ] 2>/dev/null && BEST_BPS=$B2
fi

log "OK [$CUR] 204=$R204 bps=$BEST_BPS fail=${FAIL_N}/${FAIL_TRIGGER}"

HEALTHY=1
[ "$R204" != "204" ] && HEALTHY=0
[ "$BEST_BPS" -lt "$THRESH_BPS" ] 2>/dev/null && HEALTHY=0
[ $HEALTHY -eq 1 ] && { echo 0 > $STATE; exit 0; }

FAIL_N=$((FAIL_N+1))
echo $FAIL_N > $STATE
if [ $FAIL_N -lt $FAIL_TRIGGER ]; then
  log "WARN [$CUR] 异常(204=$R204 bps=$BEST_BPS) 第${FAIL_N}轮不切"
  exit 0
fi

log "WARN [$CUR] 连续${FAIL_N}轮异常，竞速开始(预筛+TOP${TOP_PICK}各1次实测+CUR前${CUR_KEEP_RANK}保位)"

# ---- 阶段①: mihomo 全组并发延迟测试（约3秒） ----
DELAY_JSON=$(curl -s -m 30 -H "$AH" "$GRP/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000")

TOPS=$(echo "$DELAY_JSON" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' \
  | grep -E ':[0-9]+$' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '节点' \
  | sort -t: -k2 -n | head -$TOP_PICK \
  | sed 's/:[0-9]*$//')

[ -z "$TOPS" ] && { log "ERR 预筛失败(无应答) 维持[$CUR]"; echo 1 > $STATE; exit 0; }
log "  预筛TOP${TOP_PICK}: $(echo $TOPS | tr '\n' ' ')"

# ---- 阶段②: 实测名单 = TOP5 + CUR(不在名单则追加) ----
echo "$TOPS" | grep -qxF "$CUR" && RACE_LIST="$TOPS" || RACE_LIST="$CUR
$TOPS"

: > $RACE_RES
SAVED_IFS=$IFS
IFS='
'
for N in $RACE_LIST; do
  [ -z "$N" ] && continue
  put_node "$N"
  sleep 1
  ACTUAL=$(get_now)
  [ "$ACTUAL" != "$N" ] && { log "  实测: $N => 切换被拒(实际[$ACTUAL]) 跳过"; continue; }
  C204=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "https://www.gstatic.com/generate_204")
  [ "$C204" != "204" ] && { log "  实测: $N => 204不通 跳过"; continue; }
  CBPS=$(speed_test)
  [ -z "$CBPS" ] && CBPS=0
  log "  实测: $N => ${CBPS}B/s"
  printf '%s\t%s\n' "$CBPS" "$N" >> $RACE_RES
done
IFS=$SAVED_IFS

# ---- 阶段③: 决策——CUR 前3保位，否则切吞吐第1 ----
BEST_LINE=$(sort -t'	' -k1 -nr $RACE_RES | head -1)
BEST_SCORE=$(echo "$BEST_LINE" | cut -f1)
BEST_NODE=$(echo "$BEST_LINE" | cut -f2)

if [ -z "$BEST_NODE" ]; then
  put_node "$CUR"
  log "ERR 实测名单全挂，回退[$CUR]保原状"
  echo 1 > $STATE
  exit 0
fi

CUR_SCORE=$(awk -F'\t' -v n="$CUR" '$2==n{print $1}' $RACE_RES | head -1)
if [ -n "$CUR_SCORE" ]; then
  BETTER=$(awk -F'\t' -v s="$CUR_SCORE" '$1>s' $RACE_RES | wc -l)
  CUR_RANK=$((BETTER+1))
  # v6: 保位双条件——及格线上 + 前3名，否则切最优
  if [ "$CUR_SCORE" -ge "$THRESH_BPS" ] && [ $CUR_RANK -le $CUR_KEEP_RANK ]; then
    put_node "$CUR"
    CONFIRMED=$(get_now)
    echo 0 > $STATE
    if [ "$CONFIRMED" = "$CUR" ]; then
      log "OK CUR[$CUR]成绩${CUR_SCORE}B/s(及格)排名第${CUR_RANK}（前${CUR_KEEP_RANK}保位）维持"
      exit 0
    else
      put_node "$BEST_NODE"
      log "WARN CUR回切被拒(实际[$CONFIRMED])，改切[$BEST_NODE]"
    fi
  elif [ "$CUR_SCORE" -lt "$THRESH_BPS" ]; then
    log "  CUR[$CUR]成绩${CUR_SCORE}B/s低于及格线，无保位资格"
  fi
fi

put_node "$BEST_NODE"
CONFIRMED=$(get_now)
echo 0 > $STATE
if [ "$CONFIRMED" != "$BEST_NODE" ]; then
  put_node "$CUR"
  CONFIRM2=$(get_now)
  log "ERR 切[$BEST_NODE]未生效(实际[$CONFIRMED]) 回退[$CONFIRM2]"
  exit 0
fi

[ "$BEST_NODE" = "$CUR" ] && log "OK 竞速最优仍[$CUR](${BEST_SCORE}B/s)维持" \
  || log "ACT 切换 [$CUR] -> [$BEST_NODE] (${BEST_SCORE}B/s) [已回读确认]"

sleep 2
V=$(curl -s -o /dev/null -w "%{http_code}" -m 6 "https://www.gstatic.com/generate_204")
log "VER 切换后[$BEST_NODE] 204=$V"