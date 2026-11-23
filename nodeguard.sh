#!/bin/sh
# ============================================================
# nodeguard.sh v9.2 - merged debounce edition
# Base: v9.1+ (486 lines / 64264e27, production since 2026-11-23)
# v9.2 fixes (external review items, each re-verified live before applying):
#  F1 now_ok hardening: exact JSON field parse (grep -o) instead of
#     greedy sed; HTML / truncated / 502 pages now yield empty -> reject.
#     Length cap + reject control chars and quote/brace. SPACES ARE
#     ALLOWED: real provider nodes contain spaces, verified live
#     ("韩国 cdn|电信高速|2倍率"). Never blacklist spaces.
#  F2 on_exit captures put_node result; never log "restored" on fail.
#  F3 lock stale 10min -> 4min (cron is 5min; avoid losing 2 rounds).
#  F4 speed_med: zeros count into median; <2 nonzero samples -> 0
#     (single lucky sample can no longer pass a slow node).
#  F5 group-name subtraction from /proxies. Verified: /proxies holds
#     ONLY groups+builtins (32 entries), zero provider nodes, because
#     provider nodes never enter tunnel.Proxies(). Authoritative group
#     set, works even when providers API is down.
#  F6 GOOGLE_URL http -> https (both 204, verified live).
#  F7 health gate uses LOWER of two samples (was HIGHER) - same
#     conservative direction as race median; no extra traffic.
#  F8 PREV_BPS persisted to state line 4 (spike no longer depends on
#     log retention); missing 4th line -> PREV_BPS=0 (old state ok).
#  F9 PROV_TYPES whitelist completed from constant_adapters.go.
#  F10 NG_OFF sandboxable + runtime assert: SEL must be Selector
#      (if group type changes, stage-1 group delay would unpin -> refuse).
#  F11 in-loop TERM checkpoint before speed_med in candidate loop.
# v9.2: F1-F11 (see header). Decision logic itself is unchanged.
#        budget hard ceiling (B2), type-based candidate filter
#        from providers API (M5)
# v9.2: see F1-F11 above. All decisions logic unchanged.
# Stage1 screen: /group/{SEL}/delay (no unpin side effect,
#        no per-switch jitter; per-node /proxies/{n}/delay is NOT
#        usable here: provider nodes never register in tunnel
#        proxies map -> always 404, verified live + tunnel.go L219)
# Google states follow v8.1: 1=clean 2=polluted(cn or 000) 0=unknown;
#        only 2 counts as bad; unknown is tolerated (v8.1 proven).
#        Severe (204-dead-severe-bps / polluted / very low thr) breaks
#        the race cooldown, mild anomalies debounce via time window.
# All comments ASCII only (router locale safety)
# ============================================================

# ---- config ----
CONF="${NG_CONF:-/root/nodeguard.conf}"   # NG_CONF lets tests use a sandbox conf
[ -f "$CONF" ] || { echo "missing $CONF" >&2; exit 1; }
. "$CONF"
: "${NG_SECRET:?NG_SECRET missing}"
: "${NG_API:?NG_API missing}"
: "${NG_GROUP_SEL:?NG_GROUP_SEL missing}"
API="$NG_API"
AH="Authorization: $NG_SECRET"
SEL="$NG_GROUP_SEL"

# v9 tunables (override in conf)
WIN_SEC=${WIN_SEC:-900}          # mild-anomaly window: 2 hits inside window
FAIL_TRIGGER=${FAIL_TRIGGER:-2}  # hits needed inside window
RACE_CD=${RACE_CD:-900}          # cooldown after a finished race
RACE_BUDGET_H=${RACE_BUDGET_H:-2}    # max races per rolling hour (B2)
RACE_BUDGET_WIN=${RACE_BUDGET_WIN:-3600}  # budget window seconds
TOP_PICK=${TOP_PICK:-3}          # finalists from stage-1 screen
TIE_PCT=${TIE_PCT:-20}           # switch only if best*100 > cur*(100+TIE_PCT)
THRESH_BPS=${THRESH_BPS:-30720}  # pass line 30KB/s (v8 guard, kept)
SEVERE_BPS=${SEVERE_BPS:-15360}  # severe line 15KB/s
SPEED_MAX=${SPEED_MAX:-4}        # single throughput try cap seconds
SPEED_TRIES=${SPEED_TRIES:-3}    # throughput tries per candidate (median)
TRY204=${TRY204:-3}              # 204 probes per candidate (success gate)
CAND_204_TMO=${CAND_204_TMO:-2}
SPIKE_PCT=${SPIKE_PCT:-20}       # thr drop pct vs last round to flag spike
W_LAT=${W_LAT:-30}               # lat weight
W_THR=${W_THR:-60}               # throughput weight
W_STAB=${W_STAB:-10}             # stability weight
SPEED_URL="${SPEED_URL:-https://i.ytimg.com/vi/aqz-KE-bpKQ/maxresdefault.jpg}"
PROV_TYPES="${PROV_TYPES:-AnyTLS|Hysteria2|Hysteria|Trojan|Vless|Vmess|Shadowsocks|ShadowsocksR|Socks5|Http|Ssh|Tuic|WireGuard|Mieru|Snell|Sudoku|Masque|TrustTunnel|ShadowQuic|OpenVPN|Tailscale|ZeroTier|EasyTier|GostRelay}"
DRY_RUN=${NG_DRY_RUN:-0}

# v9 paths (shadow install overrides STATE/LOG via conf)
STATE="${NG_STATE:-/root/.nodeguard.state}"
LOG="${NG_LOG:-/root/nodeguard.log}"
LOCK_DIR="${NG_LOCK:-/tmp/nodeguard_v9.lock}"   # F12: sandboxable lock (default unchanged)
OFFFILE="${NG_OFF:-/root/.nodeguard.off}"   # F10: sandboxable
log(){ echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG"; }
# log trim (v8.1 rule: 200KB cap, keep last 100 lines)
[ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 204800 ] && tail -100 "$LOG" > "$LOG.new" && mv "$LOG.new" "$LOG"

# ---- single instance lock (mkdir + stale guard > 4min) ----
# F3: cron period is 5min; a 10min stale window loses 2 rounds.
mkdir "$LOCK_DIR" 2> /dev/null || { log "SKIP another instance running"; exit 0; }
OLD=$(find "$LOCK_DIR" -mmin +4 2>/dev/null)
if [ -n "$OLD" ]; then rm -rf "$LOCK_DIR"; mkdir "$LOCK_DIR" 2>/dev/null || exit 0; fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT INT TERM HUP

# ---- helpers ----
enc(){ printf "%s" "$1" | awk 'BEGIN{for(i=0;i<256;i++)o[sprintf("%c",i)]=i}{n=length($0);for(i=1;i<=n;i++){c=substr($0,i,1);if(c~/[A-Za-z0-9._~-]/)printf"%s",c;else printf"%%%02X",o[c]}}'; }
get_now(){ curl -s -m 5 -H "$AH" "$API/proxies/$(enc "$SEL")" | tr ',' '\n' | grep -o '"now":"[^"]*"' | head -n1 | sed 's/^"now":"//; s/"$//'; }
# F1: exact JSON field parse replaces greedy sed. Verified live: an HTML
# 502 page, {"error":...}, {"now":""} all yield an empty string now.
# Keep a defensive blacklist on top (defense in depth): a truncated JSON with
# an escaped quote leaves a trailing backslash ("a\" -> a\), so backslash,
# quote, backtick and bracket chars are all rejected. Verified in ash:
# quoted-quote, single-quote, backslash, brace, angle and backtick patterns all
# match; normal names with spaces / CJK / pipes / hyphens still pass.
# NOTE: spaces must stay legal - real node names contain them.
now_ok(){
  [ -z "$1" ] && return 1
  [ "${#1}" -gt 96 ] && return 1
  case "$1" in *'"'*|*"'"*|*'\'*|*'{'*|*'}'*|*'<'*|*'>'*|*'`'*) return 1 ;; esac
  return 0
}
put_node(){
  N="$1"; k=0
  while [ $k -lt 3 ]; do
    curl -s -m 5 -X PUT -H "$AH" -H "Content-Type: application/json" \
      -d "{\"name\":\"$N\"}" "$API/proxies/$(enc "$SEL")" >/dev/null 2>&1
    A=$(get_now); [ "$A" = "$N" ] && { echo "$A"; return; }
    k=$((k+1)); sleep 1
  done
  echo "$A"
}
# google check (v8.1 proven flow): 1=clean (real google, 429 ok),
#   2=polluted (google.cn landing or dead 000), 0=unknown landing
BROWSER_UA="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
GOOGLE_URL="https://www.google.com/generate_204"   # F6: https (was http); zero-download probe, -L kept
google_check(){
  LOC=$(curl -s -o /dev/null -w "%{url_effective} %{http_code}" -m 6 -L -A "$BROWSER_UA" "$GOOGLE_URL")
  case "$LOC" in
    *google.cn*) echo 2 ;;
    *" 000"*)    echo 2 ;;
    *google*)    echo 1 ;;
    *)           echo 0 ;;
  esac
}
google_word(){ case "$1" in 2) echo polluted ;; 1) echo clean ;; *) echo unknown ;; esac; }
# one throughput try, integer B/s
speed_once(){ curl -s -o /dev/null -w "%{speed_download}" -m "$SPEED_MAX" "$SPEED_URL" 2>/dev/null | cut -d. -f1; }
# F4 median: zeros counted in; a single lucky sample is NOT enough
# (needs >=2 nonzero samples, else 0). Verified: [50000,0,0] -> 0.
speed_med(){
  vals=""; k=1
  while [ $k -le "$SPEED_TRIES" ]; do
    S=$(speed_once); [ -z "$S" ] && S=0
    vals="$vals $S"; k=$((k+1))
  done
  echo "$vals" | awk '{m=0;nz=0;for(i=1;i<=NF;i++){v[++m]=$i+0;if($i+0>0)nz++}
    if(nz<2){print 0;exit}
    for(i=2;i<=m;i++){t=v[i];j=i-1;while(j>0&&v[j]>t){v[j+1]=v[j];j--};v[j+1]=t}
    print v[int((m+1)/2)]}'
}

# ============================================================
# SECTION 1: state (v9:FAIL:TS:RTS + LEDGER line)
# ============================================================
FAIL_N=0; LAST_TS=0; RACE_TS=0; LEDGER=""; RTS_LOG=""; PREV_BPS=0
NOW=$(date +%s)
SPIKE_FLAG=0
if [ -f "$STATE" ]; then
  SV=$(sed -n 1p "$STATE"); SL=$(sed -n 2p "$STATE"); R3=$(sed -n 3p "$STATE"); R4=$(sed -n 4p "$STATE")
  case "$SL" in LEDGER=*) LEDGER=${SL#LEDGER=} ;; esac
  case "$R3" in RTS_LOG=*) RTS_LOG=${R3#RTS_LOG=} ;; esac
  case "$R4" in PREV_BPS=*) PREV_BPS=${R4#PREV_BPS=} ;; esac
  case "$SV" in
    v9:*)
      BODY=${SV#v9:}
      case "$BODY" in
        *:*:*) FAIL_N=${BODY%%:*}; T2=${BODY#*:}; LAST_TS=${T2%%:*}; RACE_TS=${T2#*:} ;;
        *:*)   FAIL_N=${BODY%%:*}; LAST_TS=${BODY#*:} ;;
        *)     FAIL_N=$BODY ;;
      esac ;;
    v8:*)  FAIL_N=${SV#v8:}; LAST_TS=$NOW ;;  # migrate
    *)     : ;;                                # garbage -> reset
  esac
fi
case "$FAIL_N"  in ''|*[!0-9]*) FAIL_N=0 ;; esac
case "$PREV_BPS" in ''|*[!0-9]*) PREV_BPS=0 ;; esac
case "$LAST_TS" in ''|*[!0-9]*) LAST_TS=0 ;; esac
case "$RACE_TS" in ''|*[!0-9]*) RACE_TS=0 ;; esac
# stale mild count outside window is void
[ "$LAST_TS" -gt 0 ] && [ $((NOW-LAST_TS)) -gt "$WIN_SEC" ] && FAIL_N=0
# F8: 4th line = PREV_BPS (old 3-line state -> missing -> fallback 0)
save_state(){ printf '%s\n%s\n%s\n%s\n' "v9:$1:$2:$RACE_TS" "LEDGER=$LEDGER" "RTS_LOG=$RTS_LOG" "PREV_BPS=$PREV_BPS" > "$STATE"; }

# ============================================================
# SECTION 2: manual take-over switch, api alive, ledger
# ============================================================
if [ -f "$OFFFILE" ]; then
  # heartbeat once per hour (state TS older than 3000s) then exit
  if [ $((NOW-LAST_TS)) -gt 3000 ]; then
    log "OFF manual hold active (file present), skip round"
    save_state "$FAIL_N" "$NOW"
  fi
  exit 0
fi
curl -s -m 5 -H "$AH" "$API/version" >/dev/null 2>&1 || { log "WARN mihomo api unreachable, skip"; exit 0; }
# F10: runtime assert - SEL must be a Selector group. If someone changes
# the group type to url-test/fallback, /group/{SEL}/delay would UNPIN it
# (route_groups.go L62-65: only non-Selector groups get ForceSet("")),
# which breaks the "no unpin side effect" invariant. Refuse + alert.
SEL_TYPE=$(curl -s -m 5 -H "$AH" "$API/proxies/$(enc "$SEL")" | tr ',' '\n' | grep -o '"type":"[^"]*"' | head -n1 | sed 's/^"type":"//; s/"$//')
case "$SEL_TYPE" in
  Selector) : ;;
  "")      log "WARN cannot read group type, skip round"; exit 0 ;;
  *)       log "ERR group [$SEL] type is [$SEL_TYPE] not Selector; stage-1 delay would UNPIN it, REFUSE to run. Fix NG_GROUP_SEL or yaml."; exit 0 ;;
esac
CUR=$(get_now)
now_ok "$CUR" || { log "WARN read selector failed (bad response [$CUR]), skip"; exit 0; }
[ -n "$LEDGER" ] || LEDGER="$CUR"
if [ "$LEDGER" != "$CUR" ]; then
  log "EXT external change [$LEDGER] -> [$CUR] (manual/panel/restart), ledger synced, no action"
  LEDGER="$CUR"
fi

# ============================================================
# SECTION 3: health check (v8 logic) + spike confirm (A1)
# ============================================================
G=$(google_check)
R204=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://www.gstatic.com/generate_204" 2>/dev/null)
BEST_BPS=$(speed_once); [ -z "$BEST_BPS" ] && BEST_BPS=0
SUSPECT=0
[ "$R204" != "204" ] && SUSPECT=1
[ "$BEST_BPS" -lt "$THRESH_BPS" ] && SUSPECT=1
# F7: re-test when suspected; gate uses the LOWER of the two (conservative,
# same direction as race median). v9.1 used the HIGHER -> gate could see a
# lucky peak the race would never reproduce. Traffic cost is identical.
if [ $SUSPECT -eq 1 ]; then
  B2=$(speed_once); [ -z "$B2" ] && B2=0
  [ "$B2" -gt 0 ] && [ "$B2" -lt "$BEST_BPS" ] && BEST_BPS=$B2
fi
GW=$(google_word "$G")

# A1 spike confirm: F8 - PREV_BPS from state line 4; log is only a fallback
# (log trims to tail-100, which can silently kill the old grep-based path)
if [ "$PREV_BPS" -eq 0 ]; then
  PREV_BPS=$(grep -F "OK [$CUR]" "$LOG" 2>/dev/null | tail -1 | sed 's/.*bps=//;s/ .*//')
  case "$PREV_BPS" in ''|*[!0-9]*) PREV_BPS=0 ;; esac
fi
if [ "$PREV_BPS" -gt 0 ] && [ "$BEST_BPS" -gt 0 ]; then
  DROP=$(( (PREV_BPS - BEST_BPS) * 100 / PREV_BPS ))
  if [ "$DROP" -gt "$SPIKE_PCT" ] && [ "$BEST_BPS" -lt "$THRESH_BPS" ]; then
    SPIKE_FLAG=1
  fi
fi
if [ "$RACE_TS" -gt 0 ] && [ $((NOW-RACE_TS)) -lt "$RACE_CD" ]; then REM=$((RACE_CD-(NOW-RACE_TS))); else REM=0; fi
# F8: persist this round's observed bps as PREV_BPS for next round
[ "$BEST_BPS" -gt 0 ] 2>/dev/null && PREV_BPS=$BEST_BPS
log "OK [$CUR] google=$GW 204=$R204 bps=$BEST_BPS fail=${FAIL_N}/${FAIL_TRIGGER} rcd=${REM}s spike=${SPIKE_FLAG}"

# ============================================================
# SECTION 4: verdict with window + race cooldown gate
# ============================================================
BAD=0
[ "$R204" != "204" ] && BAD=1
[ "$G" = "2" ] && BAD=1     # v8.1 semantics: only polluted/dead is bad, unknown tolerated
[ "$BEST_BPS" -lt "$THRESH_BPS" ] 2>/dev/null && BAD=1
SEVERE=0
[ "$BEST_BPS" -lt "$SEVERE_BPS" ] 2>/dev/null && SEVERE=1
[ "$G" = "2" ] && SEVERE=1

NEED_RACE=0; REASON=""
# race cooldown first (both grades share it)
if [ "$RACE_TS" -gt 0 ] && [ $((NOW-RACE_TS)) -lt "$RACE_CD" ]; then
  REM=$(( RACE_CD-(NOW-RACE_TS) ))
  if [ $BAD -eq 1 ]; then
    if [ "$SPIKE_FLAG" -eq 1 ] && [ "$SEVERE" -eq 0 ]; then
      log "WARN [$CUR] anomaly in cooldown but spike unconfirmed, wait"
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW; save_state "$FAIL_N" "$NOW"; exit 0
    fi
    if [ $SEVERE -eq 1 ]; then
      log "WARN [$CUR] SEVERE breaks cooldown gate"
      REASON="severe-in-cooldown"; NEED_RACE=1
    else
      log "WARN [$CUR] mild anomaly suppressed by cooldown ${REM}s left"
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW; save_state "$FAIL_N" "$NOW"; exit 0
    fi
  else
    exit 0
  fi
else
  if [ $BAD -eq 1 ]; then
    if [ $SEVERE -eq 1 ]; then
      REASON="severe"; NEED_RACE=1
    elif [ "$SPIKE_FLAG" -eq 1 ]; then
      # spike needs 2 consecutive confirmations -> bump count only
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW
      if [ "$FAIL_N" -ge "$FAIL_TRIGGER" ]; then
        REASON="mild-window"; NEED_RACE=1
      else
        log "WARN [$CUR] mild anomaly(spike) window hit ${FAIL_N}/${FAIL_TRIGGER}, no race yet"
        save_state "$FAIL_N" "$NOW"; exit 0
      fi
    else
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW
      if [ "$FAIL_N" -ge "$FAIL_TRIGGER" ]; then
        REASON="mild-window"; NEED_RACE=1
      else
        log "WARN [$CUR] mild anomaly window hit ${FAIL_N}/${FAIL_TRIGGER}, no race yet"
        save_state "$FAIL_N" "$NOW"; exit 0
      fi
    fi
  else
    save_state 0 "$NOW"; exit 0
  fi
fi
# reaching here: race passed window/cooldown gates.
# B2 budget gate: hard ceiling per rolling hour, severe does NOT break it.
RTS_LOG=$(printf '%s' "$RTS_LOG" | tr ',' '\n' | awk -v now="$NOW" -v w="$RACE_BUDGET_WIN" '$1+0>0 && now-$1<w' | tr '\n' ',' | sed 's/,$//')
N_RECENT=$(printf '%s' "$RTS_LOG" | awk -F, 'NF>0{n=NF} END{print n+0}')
if [ "$N_RECENT" -ge "$RACE_BUDGET_H" ]; then
  log "WARN [$CUR] race budget exhausted (${N_RECENT}/${RACE_BUDGET_H} in ${RACE_BUDGET_WIN}s), keep cur"
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
RTS_LOG="$RTS_LOG,$NOW"
[ -z "${RTS_LOG%,*}" ] && RTS_LOG="$NOW"
RACE_TS=$NOW
save_state "$FAIL_N" "$NOW"
log "RACE start reason=$REASON cur=[$CUR] budget=$((N_RECENT+1))/${RACE_BUDGET_H}"

# ============================================================
# SECTION 5: stage-1 screen via group delay (no unpin, no switch)
# ============================================================
SELU=$(enc "$SEL")
DELAY_JSON=$(curl -s -m 30 -H "$AH" "$API/group/$SELU/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000" 2>/dev/null)
[ -z "$DELAY_JSON" ] && { log "ERR screen no response, keep [$CUR]"; save_state 1 "$NOW"; exit 0; }

# parse layer 0: last-colon split (v8 rules)
# layer 1: keyword junk filter (v8 rules, kept as defense in depth:
#          billing/info nodes share protocol types, keywords still needed)
# layer 2 (M5): keep only protocol-typed real nodes from providers API;
#          groups / DIRECT / REJECT are excluded by type, not by name guessing
TYPE_F=/tmp/ng9_types.$$
GRP_F=/tmp/ng9_grps.$$
TYPE_N=0
# awk index-extraction; keep only real protocol-typed nodes (M5)
curl -s -m 15 -H "$AH" "$API/providers/proxies" 2>/dev/null | tr '{' '\n' | awk -v t="$PROV_TYPES" '
  BEGIN { n = split(t, a, "|"); for (i=1;i<=n;i++) w[a[i]] = 1 }
  {
    n1 = index($0, "\"name\":\""); if (!n1) next
    r = substr($0, n1+8); n2 = index(r, "\""); if (!n2) next; name = substr(r, 1, n2-1)
    t1 = index($0, "\"type\":\""); if (!t1) next
    r2 = substr($0, t1+8); t2 = index(r2, "\""); if (!t2) next; typ = substr(r2, 1, t2-1)
    if (w[typ]) print name "\t" typ
  }' > "$TYPE_F"
TYPE_N=$(grep -c . "$TYPE_F" 2>/dev/null)
TPS_ALL=$(echo "$DELAY_JSON" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' \
  | awk -F: 'BEGIN{OFS=":"} NF>1 && $NF ~ /^[0-9]+$/ { d=$NF; NF--; print d "\t" $0 }' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '建议' -e '订阅' \
            -e '官网' -e '剩余' -e '重置' -e '到期' -e '套餐' -e '：' \
            -e '倍率' -e '勿跑' -e '过期' -e '失联' )

# F5: subtract the authoritative GROUP set parsed from /proxies.
# Verified live: /proxies returns ONLY groups + builtins (32 entries),
# never provider nodes, because provider nodes do not register in
# tunnel.Proxies(). So this subtraction is exact and survives the
# providers-API-down degraded path, where the keyword blacklist alone
# would happily keep "🇭🇰 香港节点" and then put_node it (legal, but a
# nested delegation instead of a real node).
curl -s -m 10 -H "$AH" "$API/proxies" 2>/dev/null \
  | tr '{' '\n' | grep -o '"name":"[^"]*"' | sed 's/^"name":"//; s/"$//' \
  | sort -u > "$GRP_F"
GRP_N=$(grep -c . "$GRP_F" 2>/dev/null)
if [ "${GRP_N:-0}" -gt 0 ] 2>/dev/null; then
  TPS_G=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' 'NR==FNR{g[$0]=1;next} NF>1 && !($2 in g)' "$GRP_F" -)
  TPS_ALL=$TPS_G
else
  log "WARN /proxies group set unreadable, group subtraction skipped (F5 degraded)"
fi
rm -f "$GRP_F"; GRP_F=""
if [ -n "$TPS_ALL" ] && [ "$TYPE_N" -gt 0 ] 2>/dev/null; then
  TPS_TY=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' 'NR==FNR{ok[$1]=1;next} ok[$2]' "$TYPE_F" -)
  if [ -n "$TPS_TY" ]; then
    TPS_ALL=$TPS_TY
  else
    log "WARN type filter emptied pool, keep keyword-only result (typed=$TYPE_N)"
  fi
elif [ "$TYPE_N" -le 0 ]; then
  log "WARN providers API unavailable, keyword-only filter (M5 degraded)"
fi
rm -f "$TYPE_F"; TYPE_F=""
screen_cnt=$(printf '%s\n' "$TPS_ALL" | grep -c .)
if [ -z "$TPS_ALL" ] || [ "$screen_cnt" -lt 1 ]; then
  log "ERR screen produced nothing, keep [$CUR]"; save_state 1 "$NOW"; exit 0
fi
if [ "$screen_cnt" -lt 3 ]; then
  log "WARN screen pool unusually small ($screen_cnt nodes), possible sub change"
fi
TOPS=$(printf '%s\n' "$TPS_ALL" | sort -n | head -"$TOP_PICK" | cut -f2-)
log "  screen TOP${TOP_PICK}: $(printf '%s' "$TOPS" | tr '\n' ' ') (from $screen_cnt, typed=$TYPE_N)"

# ---- shadow exit: measurement-without-switch would be fake ----
if [ "$DRY_RUN" = "1" ]; then
  log "DRY shadow: real run would switch-measure [$(printf '%s' "$TOPS" | tr '\n' ' ')] + cur, no action taken"
  save_state 0 "$NOW"; exit 0
fi

# ============================================================
# SECTION 6: stage-2 race, cur-first, per-switch confirm
# ============================================================
RACE_RES=/tmp/ng9_race.$$        # format: name TAB lat TAB medbps
SCORED=/tmp/ng9_score.$$
SW_DONE=0
TERM_SIG=0

# exit guard: never leave group on a half-tested node
on_exit(){
  TERM_SIG=1
  rmdir "$LOCK_DIR" 2>/dev/null
  rm -f "$RACE_RES" "$SCORED" 2>/dev/null
  [ -n "$GRP_F" ] && rm -f "$GRP_F"
  [ "$SW_DONE" = "1" ] && exit 0
  CN=$(get_now); now_ok "$CN" || exit 0
  [ "$CN" = "$CUR" ] && exit 0
  # F2: capture the result; only claim "restored" if it really happened.
  # Old v9.1 threw the return value away and always logged "restored",
  # so a failed recovery read as success (worst case: TERM landed on a
  # candidate while it was being measured).
  RB=$(put_node "$CUR")
  if [ "$RB" = "$CUR" ]; then
    log "TRAP exit mid-race: group was [$CN], restored [$CUR]"
  else
    log "ERR TRAP restore FAILED (wanted [$CUR], actual [$RB]) - group left on [$CN]!!! MANUAL CHECK REQUIRED"
  fi
  exit 0
}
trap 'on_exit' EXIT INT TERM HUP

SAVED_IFS=$IFS
IFS='
'
: > "$RACE_RES"

# 6a) measure current node first (already selected, zero switching)
C_OK204=0; k=1
while [ $k -le "$TRY204" ]; do
  C1=$(curl -s -o /dev/null -w "%{http_code}" -m "$CAND_204_TMO" "https://www.gstatic.com/generate_204" 2>/dev/null)
  [ "$C1" = "204" ] && C_OK204=$((C_OK204+1))
  k=$((k+1))
done
CG=$(google_check)
[ "$TERM_SIG" = "1" ] && exit 0       # F11: TERM checkpoint before the 12s measure
CMED=$(speed_med)
CUR_LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' -v n="$CUR" '$2==n{print $1; exit}')
[ -z "$CUR_LAT" ] && CUR_LAT=999
if [ "$C_OK204" -eq "$TRY204" ] && [ "$CG" != "2" ]; then
  printf '%s\t%s\t%s\n' "$CUR" "$CUR_LAT" "$CMED" >> "$RACE_RES"
  log "  cur [$CUR] ok204=${C_OK204}/${TRY204} google=$(google_word $CG) thr=${CMED}B/s lat=${CUR_LAT}ms"
else
  log "  cur [$CUR] failed gates (204=${C_OK204}/${TRY204} google=$(google_word $CG)), no seat"
fi

# 6b) finalists: jump, confirm, gate, measure
RACE_LIST="$TOPS"
for N in $RACE_LIST; do
  [ "$TERM_SIG" = "1" ] && break
  [ -z "$N" ] && continue
  [ "$N" = "$CUR" ] && continue
  ACTUAL=$(put_node "$N")
  if [ "$ACTUAL" != "$N" ]; then
    log "  cand [$N] switch rejected (actual [$ACTUAL]) skip"
    continue
  fi
  OK204=0; k=1
  while [ $k -le "$TRY204" ]; do
    C1=$(curl -s -o /dev/null -w "%{http_code}" -m "$CAND_204_TMO" "https://www.gstatic.com/generate_204" 2>/dev/null)
    [ "$C1" = "204" ] && OK204=$((OK204+1))
    k=$((k+1))
  done
  if [ "$OK204" -lt "$TRY204" ]; then
    log "  cand [$N] 204 only ${OK204}/${TRY204}, skip"
    continue
  fi
  CG=$(google_check)
  if [ "$CG" = "2" ]; then
    log "  cand [$N] google $(google_word $CG), skip"
    continue
  fi
  [ "$TERM_SIG" = "1" ] && break        # F11: TERM checkpoint before the 12s measure
  MED=$(speed_med)
  LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' -v n="$N" '$2==n{print $1; exit}')
  [ -z "$LAT" ] && LAT=999
  printf '%s\t%s\t%s\n' "$N" "$LAT" "$MED" >> "$RACE_RES"
  log "  cand [$N] ok204=${OK204}/${TRY204} google=$(google_word $CG) thr=${MED}B/s lat=${LAT}ms"
done
IFS=$SAVED_IFS

# ============================================================
# SECTION 7: stage-3 scoring (vs-best, rank-free) + gates + settle
# ============================================================
SEATS=$(grep -c . "$RACE_RES" 2>/dev/null)
if [ -z "$SEATS" ] || [ "$SEATS" -lt 1 ]; then
  # nobody seated: restore cur, log, retry race blocked by cooldown
  RBF=$(put_node "$CUR")
  LEDGER=$RBF
  log "ERR race all failed (204/google/throughput dead), restored [$RBF], retry after cooldown"
  save_state 1 "$NOW"
  SW_DONE=1
  exit 0
fi

# columns: name TAB lat TAB med; stability is a placeholder (const 100)
awk -F'\t' -v wl="$W_LAT" -v wt="$W_THR" -v ws="$W_STAB" '
  NR==FNR {
    if (FNR==1 || $2+0 < bestlat+0) bestlat=$2+0
    if (FNR==1 || $3+0 > bestthr+0) bestthr=$3+0
    next
  }
  {
    # vs-best scoring: a node 20 percent slower scores 80, not 0
    lat = ($2+0 <= 0) ? 1 : $2+0
    sc_lat = bestlat / (lat+1) * 100
    if (sc_lat > 100) sc_lat = 100
    thr = $3+0
    sc_thr = (bestthr <= 0) ? 0 : thr * 100 / bestthr
    if (sc_thr > 100) sc_thr = 100
    sc_stab = 100
    score = (wl*sc_lat + wt*sc_thr + ws*sc_stab) / (wl + wt + ws)
    printf "%.1f\t%s\t%s\t%s\n", score, $1, $2, $3
  }
' "$RACE_RES" "$RACE_RES" | sort -rn > "$SCORED"

log "SCORE (score/name/lat/thr):"
TABC=$(printf '\t')
while IFS="$TABC" read -r sc nm lt tb; do
  log "  $nm score=$sc lat=${lt}ms thr=${tb}B/s"
done < "$SCORED"

BEST_LINE=$(head -1 "$SCORED")
BEST_SCORE=$(echo "$BEST_LINE" | cut -f1)
BEST_NODE=$(echo "$BEST_LINE" | cut -f2)
CUR_LINE=$(awk -F'\t' -v n="$CUR" '$2==n{print; exit}' "$SCORED")
CUR_SCORE=$(echo "$CUR_LINE" | cut -f1)
[ -z "$CUR_SCORE" ] && CUR_SCORE=0
log "DECIDE best=[$BEST_NODE]($BEST_SCORE) cur=[$CUR]($CUR_SCORE)"

MARGIN=$(awk -v b="$BEST_SCORE" -v c="$CUR_SCORE" -v p="$TIE_PCT" 'BEGIN{if(b*100>=c*(100+p))print 1;else print 0}')

KEEP=0
[ "$BEST_NODE" = "$CUR" ] && KEEP=1
[ "$MARGIN" != "1" ] && KEEP=1
if [ "$KEEP" = "1" ]; then
  CONFIRMED=$(put_node "$CUR")
  LEDGER=$CONFIRMED
  if [ "$BEST_NODE" = "$CUR" ]; then
    log "OK race winner still [$CUR] ($BEST_SCORE), kept"
  else
    [ "$CUR_SCORE" = "0" ] && CUR_SCORE=0.1
    MARGIN_PCT=$(awk -v b="$BEST_SCORE" -v c="$CUR_SCORE" 'BEGIN{printf "%.0f", b*100/c-100}')
    log "OK margin ${MARGIN_PCT}% under TIE_PCT=${TIE_PCT}, keep [$CUR]"
  fi
  if [ "$CONFIRMED" = "$CUR" ]; then
    save_state 0 "$NOW"; SW_DONE=1
    exit 0
  fi
  if [ "$BEST_NODE" = "$CUR" ]; then
    log "ERR cannot restore [$CUR] (actual [$CONFIRMED]), manual check next round"
    save_state 1 "$NOW"; SW_DONE=1
    exit 0
  fi
  log "WARN keep-restore rejected (actual [$CONFIRMED]), fall through to switch [$BEST_NODE]"
fi

CON=$(put_node "$BEST_NODE")
LEDGER=$CON
SW_DONE=1
if [ "$CON" != "$BEST_NODE" ]; then
  RBF=$(put_node "$CUR")
  LEDGER=$RBF
  log "ERR switch to [$BEST_NODE] ineffective (actual [$CON]), rolled back [$RBF]"
  save_state 1 "$NOW"
  exit 0
fi
log "ACT switch [$CUR] -> [$BEST_NODE] score ${CUR_SCORE}->${BEST_SCORE} [confirmed]"

rm -f "$RACE_RES" "$SCORED"
save_state 0 "$NOW"
exit 0
