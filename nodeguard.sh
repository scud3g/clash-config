#!/bin/sh
# nodeguard.sh v7 - 节点守护：Google防污染 + 分级触发 + 池内最快当选 + 单实例锁
# 配置外置版：密钥/接口地址/策略组名从 /root/nodeguard.conf 读取（见 nodeguard.conf.example），本脚本零敏感信息
# GitHub 仓库 scud3g/clash-config 的 nodeguard.sh；旁路由由 /root/selfupdate.sh 每日自动同步
#
# v7 新增（v6 验证发现 204/吞吐对 Google 污染失明）：
#   1. Google 三态检测：落地 google.cn 或超时 = 污染 → 当轮立即竞速
#      （污染节点 204 正常、吞吐正常，但 Google 302 到死站 google.cn/m）
#      必须带浏览器 UA：curl 默认 UA 下 Google 对部分污染节点返回正常 302，
#      浏览器 UA 下才 302→google.cn/m 404（2026-11-20 实测台湾1/日本cdn1）
#   2. 分级触发：重度异常（Google污染 / 204失败 / 吞吐<重度线15KB/s）当轮立即竞速；
#      轻度异常（吞吐15~30KB/s，可能瞬时抖动）仍连续 2 轮防抖
#   3. 竞速决策改"池内最快当选"：候选须过 Google+204 两道门才入池；
#      池内按吞吐选最高，全池低于及格线也选最高的；CUR 非最快即切（废除前3保位）
#   4. 平局吸收抖动：CUR 与最优差距 ≤15%（且 ≥及格线）视为持平维持，防测速噪声频繁切换
#   5. 状态文件带版本号 v7:N，v6 旧纯数字状态读取时自动重置为 0
# v6 保留：单实例 flock 锁 / 空格名 IFS 遍历 / 切换回读确认 / 全灭回退保原状
#           候选1次测速 / 6s 测速封顶 / 3s 候选204 / 每轮日志瘦身 / 外置 conf
# 修复：urlencode 的 od 依赖（busybox 无 od applet）改 awk 逐字节编码

CONF=/root/nodeguard.conf
[ -f "$CONF" ] || { echo "缺少 $CONF，参考 nodeguard.conf.example 创建" >&2; exit 1; }
. "$CONF"
: "${NG_SECRET:?NG_SECRET 未配置}"
: "${NG_API:?NG_API 未配置}"
: "${NG_GROUP_SEL:?NG_GROUP_SEL 未配置}"

AH="Authorization: $NG_SECRET"
API="$NG_API"

# 策略组名 -> URL 编码（UTF-8，支持中文/emoji/空格；awk 实现，无 od 依赖）
urlencode() {
  printf "%s" "$1" | awk '
  BEGIN { for (i = 0; i < 256; i++) ord[sprintf("%c", i)] = i }
  {
    n = length($0)
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      if (c ~ /[A-Za-z0-9._~-]/) printf "%s", c
      else printf "%%%02X", ord[c]
    }
  }'
}
SEL="$API/proxies/$(urlencode "$NG_GROUP_SEL")"
GRP="$API/group/$(urlencode "$NG_GROUP_SEL")"
STATE=/tmp/nodeguard.state
LOG=/tmp/nodeguard.log
RACE_RES=/tmp/nodeguard.race
LOCK=/tmp/nodeguard.single
THRESH_BPS=30720       # 及格线 30KB/s
SEVERE_BPS=15360       # 重度线 15KB/s（及格线一半）
FAIL_TRIGGER=2         # 轻度异常连续轮数
TOP_PICK=5             # 预筛取前5
TIE_PCT=15             # 平局容差百分比
SPEED_MAX=6            # 单次测速封顶秒数
SPEED_URL="https://i.ytimg.com/vi/aqz-KE-bpKQ/maxresdefault.jpg"
GOOGLE_URL="http://www.google.com/"   # 污染节点 302→google.cn，干净节点 200

log() { echo "$(date '+%m-%d %H:%M:%S') $1" >> $LOG; }
[ -f $LOG ] && [ "$(wc -c < $LOG)" -gt 204800 ] && tail -100 $LOG > $LOG.new && mv $LOG.new $LOG

# ---- 单实例锁（上一轮未结束则本轮跳过） ----
if [ -x /usr/bin/flock ]; then
  exec 9>"$LOCK"
  flock -n 9 || { log "SKIP 已有实例在运行，本轮跳过"; exit 0; }
else
  mkdir "$LOCK"  2>/dev/null || { log "SKIP 已有实例在运行，本轮跳过"; exit 0; }
  OLD=$(find "$LOCK" -mmin +10 2>/dev/null)
  [ -n "$OLD" ] && rm -rf "$LOCK" && exec 9>"$LOCK" && flock -n 9
fi

speed_test() { curl -s -o /dev/null -w "%{speed_download}" -m $SPEED_MAX "$SPEED_URL" | cut -d. -f1; }
get_now() { curl -s -m 5 -H "$AH" "$SEL" | sed 's/.*"now":"//;s/".*//'; }
put_node() { curl -s -m 8 -X PUT "$SEL" -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"$1\"}" >/dev/null; }

# google_check: 输出 2=污染(落地cn/超时) 1=干净 0=接口异常
BROWSER_UA="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
google_check() {
  LOC=$(curl -s -o /dev/null -w "%{url_effective} %{http_code}" -m 6 -L -A "$BROWSER_UA" "$GOOGLE_URL")
  case "$LOC" in
    *"google.cn"* ) echo 2 ;;
    *" "[45]*|*" 000"*) echo 2 ;;
    *google*      ) echo 1 ;;
    *             ) case "$LOC" in
                      *301*|*302*) echo 2 ;;
                      *) echo 0 ;;
                    esac ;;
  esac
}

google_word() { case "$1" in 2) echo 污染;; 1) echo 干净;; *) echo 未知;; esac; }

# ---- 状态初始化（v6 旧纯数字值视为迁移，重置为0） ----
FAIL_N=0
if [ -f $STATE ]; then
  SV=$(cat $STATE)
  case "$SV" in v7:*) FAIL_N=${SV#v7:} ;; esac
fi

curl -s -m 5 -H "$AH" "$API/version" >/dev/null 2>&1 || { log "WARN mihomo 不可达跳过"; exit 0; }

CUR=$(get_now)
[ -z "$CUR" ] && { log "WARN 读节点选择失败跳过"; exit 0; }

# ---- 健康检查：Google + 204 + 1次测速（可疑才复测防毛刺，取较高值） ----
G=$(google_check)
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

GW=$(google_word $G)
log "OK [$CUR] google=$GW 204=$R204 bps=$BEST_BPS fail=${FAIL_N}/${FAIL_TRIGGER}"

# ---- 健康判定 + 分级触发路由 ----
BAD=0
[ "$R204" != "204" ] && BAD=1
[ "$G" = "2" ] && BAD=1
[ "$BEST_BPS" -lt "$THRESH_BPS" ] 2>/dev/null && BAD=1

if [ $BAD -eq 0 ]; then
  echo "v7:0" > $STATE
  exit 0
fi

SEVERE=0
[ "$R204" != "204" ] && SEVERE=1
[ "$G" = "2" ] && SEVERE=1
[ "$BEST_BPS" -lt "$SEVERE_BPS" ] 2>/dev/null && SEVERE=1

if [ $SEVERE -eq 0 ]; then
  FAIL_N=$((FAIL_N+1))
  echo "v7:$FAIL_N" > $STATE
  if [ $FAIL_N -lt $FAIL_TRIGGER ]; then
    log "WARN [$CUR] 轻度异常(google=$GW 204=$R204 bps=$BEST_BPS) 第${FAIL_N}轮不切"
    exit 0
  fi
  log "WARN [$CUR] 轻度异常连续${FAIL_N}轮，竞速开始"
else
  SEV_REASON=""
  [ "$G" = "2" ] && SEV_REASON="${SEV_REASON}Google污染 "
  [ "$R204" != "204" ] && SEV_REASON="${SEV_REASON}204失败 "
  [ "$BEST_BPS" -lt "$SEVERE_BPS" ] 2>/dev/null && SEV_REASON="${SEV_REASON}吞吐${BEST_BPS}B/s<重度线 "
  log "WARN [$CUR] 重度异常(${SEV_REASON}) 当轮立即竞速"
fi

# ---- 阶段①: mihomo 全组并发延迟测试（约3秒） ----
DELAY_JSON=$(curl -s -m 30 -H "$AH" "$GRP/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000")

TOPS=$(echo "$DELAY_JSON" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' \
  | grep -E ':[0-9]+$' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '节点' \
            -e '建议' -e '订阅' -e '官网' -e '剩余' -e '重置' -e '到期' -e '套餐' -e '：' \
  | sort -t: -k2 -n | head -$TOP_PICK \
  | sed 's/:[0-9]*$//')

[ -z "$TOPS" ] && { log "ERR 预筛失败(无应答) 维持[$CUR]"; echo "v7:1" > $STATE; exit 0; }
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
  CG=$(google_check)
  [ "$CG" = "2" ] && { log "  实测: $N => Google$(google_word $CG) 跳过"; continue; }
  CBPS=$(speed_test)
  [ -z "$CBPS" ] && CBPS=0
  log "  实测: $N => google=$(google_word $CG) ${CBPS}B/s"
  printf '%s\t%s\n' "$CBPS" "$N" >> $RACE_RES
done
IFS=$SAVED_IFS

# ---- 阶段③: 决策——池内最快当选（Google+204 门内，全池低也选最高） ----
BEST_LINE=$(sort -t'	' -k1 -nr $RACE_RES | head -1)
BEST_SCORE=$(echo "$BEST_LINE" | cut -f1)
BEST_NODE=$(echo "$BEST_LINE" | cut -f2)

if [ -z "$BEST_NODE" ]; then
  put_node "$CUR"
  log "ERR 实测名单全挂(Google/204/吞吐全灭)，回退[$CUR]保原状"
  echo "v7:1" > $STATE
  exit 0
fi

CUR_SCORE=$(awk -F'\t' -v n="$CUR" '$2==n{print $1}' $RACE_RES | head -1)
if [ -n "$CUR_SCORE" ]; then
  BETTER=$(awk -F'\t' -v s="$CUR_SCORE" '$1>s' $RACE_RES | wc -l)
  CUR_RANK=$((BETTER+1))
  # v7: 平局容差——CUR 与最优差距≤15% 且 CUR≥及格线 → 持平维持（防测速噪声频繁切换）
  NEEDSWITCH=$(awk -v cs="$CUR_SCORE" -v bs="$BEST_SCORE" -v p="$TIE_PCT" 'BEGIN{if(bs*100>cs*(100+p))print 1;else print 0}')
  if [ "$CUR_SCORE" -ge "$THRESH_BPS" ] 2>/dev/null && [ "$NEEDSWITCH" = "0" ]; then
    put_node "$CUR"
    CONFIRMED=$(get_now)
    echo "v7:0" > $STATE
    if [ "$CONFIRMED" = "$CUR" ]; then
      log "OK CUR[$CUR]成绩${CUR_SCORE}B/s(及格)排名第${CUR_RANK}（与最优差≤${TIE_PCT}%持平）维持"
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
echo "v7:0" > $STATE
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
VGG=$(google_check)
log "VER 切换后[$BEST_NODE] 204=$V google=$(google_word $VGG)"
