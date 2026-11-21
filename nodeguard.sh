#!/bin/sh
# nodeguard.sh v8 - 节点守护：Google防污染(429免疫) + awk候选解析 + 竞速提速 + 状态重启保留
# 配置外置版：密钥/接口地址/策略组名从 /root/nodeguard.conf 读取（见 nodeguard.conf.example），本脚本零敏感信息
# GitHub 仓库 scud3g/clash-config 的 nodeguard.sh；旁路由由 /root/selfupdate.sh 每日自动同步
#
# v8 新增（对外部AI评审报告的实测验证结论）：
#   1. D2修复：Google 429 是限流不是污染，从污染判定摘除（浏览器UA下Google对高频探测返回429，
#      旧版 *" [45]* 会把 429 误判为污染），仅 google.cn/301/302/000 判污染；同时删除 -L 下
#      永不触发的 301/302 死代码分支（D3）
#   2. D5修复：delay JSON 解析改 awk 按最后一个冒号分割（节点名内含冒号不再碎裂）
#   3. 排序修复（实测新发现，报告未发现）：busybox sort -t: -k2 -n 在本机完全失效
#      （实测输出 241/215/169/348/352 无序），改 awk 提取末段数值 + sort -n 全局排序，
#      实测 65/67/69/81/82/93 精确有序
#   4. 风险节点过滤（实测新发现）：候选排除 倍率/勿跑大流量/过期/失联 等计费警示节点，
#      旧版会把 5 倍计费节点（台湾1|5倍率）选进竞速名单且当选后全家按 5 倍计费
#   5. D4-C提升竞速速度：busybox sleep 不支持小数（实测 invalid number）、无 usleep（实测），
#      改为切换后立即回读确认（不 sleep），回读不符再 sleep 1 重试至多 2 次，无效候选快速跳过
#   6. D4-B：TOP_PICK 5→3（整组 delay 实测 3 秒；串行实测段下限 90s→45s）
#   7. D7(部分)：候选测速超时 6s→4s、候选204超时 3s→2s（候选阶段快查快弃）
#   8. D6修复：状态文件 /tmp→/root/.nodeguard.state（重启不再丢防抖计数）
# v7 保留：Google 三态检测(浏览器UA) / 分级触发 / 池内最快当选+平局容差 / 单实例 flock 锁 /
#           空格名 IFS 遍历 / 切换回读确认 / 全灭回退保原状 / 每轮日志瘦身 / 外置 conf
# 状态文件版本号升级 v8:N（v7 旧格式读取时自动重置为 0；/tmp 旧状态弃用）

CONF=/root/nodeguard.conf
[ -f "$CONF" ] || { echo "缺少 $CONF，参考 nodeguard.conf.example 创建" >&2; exit 1; }
. "$CONF"
: "${NG_SECRET:?NG_SECRET 未配置}"
: "${NG_API:?NG_API 未配置}"
: "${NG_GROUP_SEL:?NG_GROUP_SEL 未配置}"

AH="Authorization: $NG_SECRET"
API="$NG_API"

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
STATE=/root/.nodeguard.state
LOG=/tmp/nodeguard.log
RACE_RES=/tmp/nodeguard.race
LOCK=/tmp/nodeguard.single
THRESH_BPS=30720       # 及格线 30KB/s
SEVERE_BPS=15360       # 重度线 15KB/s（及格线一半）
FAIL_TRIGGER=2         # 轻度异常连续轮数
TOP_PICK=3             # 预筛取前3（v8: 5→3 竞速提速）
TIE_PCT=15             # 平局容差百分比
SPEED_MAX=4            # 单次测速封顶秒数（v8: 6→4）
CAND_204_TMO=2         # 候选204超时秒数（v8: 3→2）
SWITCH_RETRY=2         # 切换回读不符时重试次数上限
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

# 切换到 $1 并回读确认（含重试）。成功 echo 节点名，失败 echo 空
put_confirm() {
  PUT_N="$1"
  TRY=0
  while [ $TRY -le $SWITCH_RETRY ]; do
    put_node "$PUT_N"
    ACT=$(get_now)
    if [ "$ACT" = "$PUT_N" ]; then
      echo "$PUT_N"
      return 0
    fi
    TRY=$((TRY+1))
    [ $TRY -le $SWITCH_RETRY ] && sleep 1
  done
  echo ""
}

# google_check: 输出 2=污染(落地cn/断流000) 1=干净(落在google域，含429限流) 0=未知(落在他站)
# v8: 429 是 Google 对高频探测的限流（节点仍干净），不再判污染（D2）；
#     -L 跟随后最终码不会是 301/302，死代码分支已删（D3）
BROWSER_UA="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
google_check() {
  LOC=$(curl -s -o /dev/null -w "%{url_effective} %{http_code}" -m 6 -L -A "$BROWSER_UA" "$GOOGLE_URL")
  case "$LOC" in
    *"google.cn"* ) echo 2 ;;
    *" 000"*      ) echo 2 ;;
    *google*      ) echo 1 ;;
    *             ) echo 0 ;;
  esac
}

google_word() { case "$1" in 2) echo 污染;; 1) echo 干净;; *) echo 未知;; esac; }

# ---- 状态初始化（v8 新格式 v8:N；旧 v7:/纯数字/不存在 一律重置为 0） ----
FAIL_N=0
if [ -f $STATE ]; then
  SV=$(cat $STATE)
  case "$SV" in v8:*) FAIL_N=${SV#v8:} ;; esac
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
  echo "v8:0" > $STATE
  exit 0
fi

SEVERE=0
[ "$R204" != "204" ] && SEVERE=1
[ "$G" = "2" ] && SEVERE=1
[ "$BEST_BPS" -lt "$SEVERE_BPS" ] 2>/dev/null && SEVERE=1

if [ $SEVERE -eq 0 ]; then
  FAIL_N=$((FAIL_N+1))
  echo "v8:$FAIL_N" > $STATE
  if [ $FAIL_N -lt $FAIL_TRIGGER ]; then
    log "WARN [$CUR] 轻度异常(google=$GW 204=$R204 bps=$BEST_BPS) 第${FAIL_N}轮不切"
    exit 0
  fi
  log "WARN [$CUR] 轻度异常连续${FAIL_N}轮，竞速开始"
else
  SEV_REASON=""
  [ "$G" = "2" ] && SEV_REASON="${SEV_REASON}Google${GW} "
  [ "$R204" != "204" ] && SEV_REASON="${SEV_REASON}204失败 "
  [ "$BEST_BPS" -lt "$SEVERE_BPS" ] 2>/dev/null && SEV_REASON="${SEV_REASON}吞吐${BEST_BPS}B/s<重度线 "
  log "WARN [$CUR] 重度异常(${SEV_REASON}) 当轮立即竞速"
fi

# ---- 阶段①: mihomo 全组并发延迟测试（实测约3秒） ----
# v8 解析：awk 按最后一个冒号分割（节点名含冒号安全）+ 排除信息节点/组节点/计费警示节点
#   排序：busybox sort -t: -k2 -n 实测失效，改 awk 取末段数值放行首 + sort -n 全局排序
DELAY_JSON=$(curl -s -m 30 -H "$AH" "$GRP/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000")

TOPS=$(echo "$DELAY_JSON" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' \
  | awk -F: 'BEGIN{OFS=":"} NF>1 && $NF ~ /^[0-9]+$/ { d=$NF; NF--; print d "\t" $0 }' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '节点' -e '建议' -e '订阅' \
            -e '官网' -e '剩余' -e '重置' -e '到期' -e '套餐' -e '：' \
            -e '倍率' -e '勿跑' -e '过期' -e '失联' \
  | sort -n | head -$TOP_PICK \
  | cut -f2-)

[ -z "$TOPS" ] && { log "ERR 预筛失败(无应答) 维持[$CUR]"; echo "v8:1" > $STATE; exit 0; }
log "  预筛TOP${TOP_PICK}: $(echo $TOPS | tr '\n' ' ')"

# ---- 阶段②: 实测名单 = TOP3 + CUR(不在名单则追加) ----
echo "$TOPS" | grep -qxF "$CUR" && RACE_LIST="$TOPS" || RACE_LIST="$CUR
$TOPS"

: > $RACE_RES
SAVED_IFS=$IFS
IFS='
'
for N in $RACE_LIST; do
  [ -z "$N" ] && continue
  # v8: 立即回读确认（不 sleep），不符则重试
  ACTUAL=$(put_confirm "$N")
  [ "$ACTUAL" != "$N" ] && { log "  实测: $N => 切换被拒(实际[$ACTUAL]) 跳过"; continue; }
  C204=$(curl -s -o /dev/null -w "%{http_code}" -m $CAND_204_TMO "https://www.gstatic.com/generate_204")
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
  echo "v8:1" > $STATE
  exit 0
fi

CUR_SCORE=$(awk -F'\t' -v n="$CUR" '$2==n{print $1}' $RACE_RES | head -1)
if [ -n "$CUR_SCORE" ]; then
  BETTER=$(awk -F'\t' -v s="$CUR_SCORE" '$1>s' $RACE_RES | wc -l)
  CUR_RANK=$((BETTER+1))
  # 平局容差——CUR 与最优差距≤15% 且 CUR≥及格线 → 持平维持（防测速噪声频繁切换）
  NEEDSWITCH=$(awk -v cs="$CUR_SCORE" -v bs="$BEST_SCORE" -v p="$TIE_PCT" 'BEGIN{if(bs*100>cs*(100+p))print 1;else print 0}')
  if [ "$CUR_SCORE" -ge "$THRESH_BPS" ] 2>/dev/null && [ "$NEEDSWITCH" = "0" ]; then
    CONFIRMED=$(put_confirm "$CUR")
    echo "v8:0" > $STATE
    if [ "$CONFIRMED" = "$CUR" ]; then
      log "OK CUR[$CUR]成绩${CUR_SCORE}B/s(及格)排名第${CUR_RANK}（与最优差≤${TIE_PCT}%持平）维持"
      exit 0
    else
      log "WARN CUR回切被拒(实际[$CONFIRMED])，改切[$BEST_NODE]"
    fi
  elif [ "$CUR_SCORE" -lt "$THRESH_BPS" ]; then
    log "  CUR[$CUR]成绩${CUR_SCORE}B/s低于及格线，无保位资格"
  fi
fi

CONFIRMED=$(put_confirm "$BEST_NODE")
echo "v8:0" > $STATE
if [ "$CONFIRMED" != "$BEST_NODE" ]; then
  RBF=$(put_confirm "$CUR")
  log "ERR 切[$BEST_NODE]未生效(实际[$CONFIRMED]) 回退[$RBF]"
  exit 0
fi

[ "$BEST_NODE" = "$CUR" ] && log "OK 竞速最优仍[$CUR](${BEST_SCORE}B/s)维持" \
  || log "ACT 切换 [$CUR] -> [$BEST_NODE] (${BEST_SCORE}B/s) [已回读确认]"

sleep 2
V=$(curl -s -o /dev/null -w "%{http_code}" -m 6 "https://www.gstatic.com/generate_204")
VGG=$(google_check)
log "VER 切换后[$BEST_NODE] 204=$V google=$(google_word $VGG)"
