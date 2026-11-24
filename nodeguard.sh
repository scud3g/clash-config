#!/bin/sh
# ============================================================
# nodeguard.sh v9.7 - pre-race liveness precheck (F22)
# Base: v9.6 (F1-F21 all retained; 660 non-blank lines / 4DB507F0, 2026-11-24)
# v9.7 fix (F22):
#  F22 (P3) A >=3 delay pool still checked one thing only: SIZE. The
#     old path committed the budget slot and armed the cooldown BEFORE
#     anyone had proved a single TOPS member was reachable. 3 dead nodes
#     -> all gates fail -> SEATS<1 -> slot burned for a race that never
#     measured anything real; worst case inside an hour this is the F13
#     hole again. Now SECTION 5a pre-probes each TOPS member once with a
#     single 204 (-m CAND_204_TMO, ~6s for TOP_PICK=3) BEFORE the budget
#     commit; if EVERY probe fails it is an infrastructure-grade fault -
#     same semantics as F13/F18 screen faults: no FAIL_N write, no slot,
#     no cooldown, just log and exit. cur is NOT pre-probed here - it
#     only enters if all TOPS are dead, and is measured in stage 2 anyway.
# v9.6 fixes (F16-F21, found by a line-by-line read of v9.5):
#  F16 (P4) Log trim ran BEFORE the instance lock and used a fixed temp
#     name ($LOG.new). Two overlapping cron rounds could both tail+mv; the
#     mv is atomic but the loser keeps writing into an already-unlinked
#     inode, silently losing the lines it logs afterwards. Trim moved below
#     the lock (single writer), temp name now carries $$.
#  F17 (P3) Healthy round INSIDE the cooldown exited without save_state,
#     so the PREV_BPS refreshed earlier that round (next round's spike
#     baseline) and any stale FAIL_N were dropped. The healthy path outside
#     cooldown already saved; this makes both consistent. A node that
#     recovers during cooldown is the normal case, not an edge case.
#  F18 (P3) A failed screen (no response / empty / pool <3) wrote
#     FAIL_N=1, nudging the next mild anomaly over FAIL_TRIGGER and racing
#     for something nothing had measured - the same half-accounting F13
#     removed from the budget side. These paths now keep FAIL_N untouched;
#     a screen fault is infrastructure, not node health.
#  F20 (P3) When cur was missing from the group-delay pool, CUR_LAT fell
#     back to a punitive 999ms. cur had already passed the 204 and google
#     gates, so it IS a real node; only its delay sample was missing. At
#     999ms sc_lat collapses to ~70/100 even when cur's true latency was
#     the best, which can push a healthy cur past TIE_PCT and cause a
#     needless switch. Now: cur's latency is estimated as the pool median
#     (neutral); 999 only when the pool has no usable delay at all.
#  F21 (P3) In the keep branch, [ "$CUR_SCORE" = "0" ] could never be true:
#     the score column is printed with "%.1f", so it is always "0.0". With
#     CUR_SCORE=0.0 the next awk did b*100/0 -> empty output -> a log line
#     "margin % under TIE_PCT". The guard now lives inside awk (c+0<=0).
#  F19 (P3, v9.7: FIXED by F22) S4's pool floor checks POOL SIZE, not the
#     number of live candidates; a >=3 pool could still seat nobody and only
#     found out at the SEATS<1 branch, after the slot was spent. F22 (v9.7)
#     adds a one-204 precheck per TOPS member BEFORE the budget commit, so
#     the all-dead path no longer burns slot/cooldown. SEATS<1 can still
#     fire mid-race (node dies between precheck and its gates) - that is
#     genuinely measured traffic, the slot was earned by a live precheck.
# Behaviour note: F18 and F20 change what gets written to state and how one
# scoring input is derived. Decision weights, gates and thresholds are
# unchanged. Rejected in this pass: "stability score is fake" (N2 already
# made it real, min/max of the 3 samples) and "budget window hardcoded"
# (B2 already passes -v w=; no literal 3600 outside the conf default).
# v9.5 retained (deferred budget commit + honest version log):
#  F13 (P2) Race budget and cooldown were committed in SECTION 4, which
#     runs BEFORE the stage-1 screen. An empty screen or a <3 node pool
#     (S4 floor) then exited with RACE_TS already armed (full RACE_CD
#     window) and one budget slot burned, for a race that never ran. Two
#     such rounds inside the budget window blocked every real race for the
#     rest of that hour, and mild anomalies were suppressed by a
#     cooldown that nothing had earned. Commit moved to SECTION 5a, after
#     the screen proves a real pool; DRY_RUN still exits before it.
#  F14 (P2) The per-round log line still printed "RUN v9.3" inside v9.4,
#     which defeats E1 (logging the build id is only useful if it names
#     the build actually running). Now prints v9.6.
#  F15 (P3) Log trim window 100 -> 400 lines (200KB byte cap kept). A round
#     writes 5-15 lines, so tail -100 held only ~10-30 rounds and the A1
#     PREV_BPS log fallback could miss the previous "OK [cur]" line.
#  Reviewed and REJECTED in this pass (no change made):
#   - B2 "budget window hardcoded": false. In v9.4 the awk call at L356
#     already passed -v w="$RACE_BUDGET_WIN"; grep of the whole file shows
#     no literal 3600 outside the conf default.
#   - "TIE_PCT keeps an unseated cur": false. With CUR_SCORE=0 the awk
#     test b*100 >= 0*(100+p) is true -> MARGIN=1 -> KEEP stays 0, so the
#     script switches away correctly. Traced by hand, not assumed.
#  Decision logic is unchanged: same weights, same gates, same scoring.
# v9.4 retained (S-series lock/floor hardening):
#  S3 stale-lock cleanup now runs even when mkdir fails. Old v9.3
#     exited on mkdir failure, so a lock left by a crashed round made
#     every later round "SKIP another instance" forever - the -mmin +8
#     reclaim was never reached. Now mkdir-fail still checks stale and
#     reclaims. (Real P2 found while reading v9.3.)
#  S4 pool floor: a 1-2 node screen (<3) now bails without racing
#     (was: WARN and continue). TOP_PICK=3 can never fill, and a race
#     over a tiny pool usually re-validates the current node while
#     burning budget. Keep current, log, exit.
# v9.3 retained (N/E series from deep review + external research):
#  N1 save_state atomic: write STATE.tmp then mv (2 lines). Old '>'
#     truncates first; a killed round left a half/empty state which
#     zeroed FAIL_N/PREV_BPS/RACE_TS and silently bypassed cooldown
#     and hourly budget on the next round.
#  N2 stability score is now REAL: min/max ratio of the 3 throughput
#     samples (speed_med already collects them). [120000,60000,30000]
#     -> 25, [100000,98000,99000] -> 98. Placeholder const 100 is
#     gone. Set W_STAB=0 in conf to disable (score only records).
#     NOTE: stability now needs SPEED_TRIES>=3 to be meaningful;
#     with 2 samples the ratio is coarse (0 or ~near-100). Default 3.
#  N3 F7 side effect documented: health gate stores the LOWER of two
#     samples as PREV_BPS, so the spike detector sees a shrunken
#     baseline. Conservative direction, accepted; just be aware when
#     tuning SPIKE_PCT. (comment-only change)
#  N4 screen_cnt warning threshold raised: group delay fires one
#     goroutine per member with NO concurrency cap (mihomo
#     adapter_outboundgroup_groupbase.go L237-263; provider
#     healthcheck has SetLimit(10), group delay does not). 53 members
#     = 53 concurrent probes. >80 gets a WARN line now.
#  E1 mihomo version logged each round (1 line): /version response
#     kept in the log, so a future API behavior change (see mihomo
#     commit 85c1798f which moved provider nodes out of /proxies)
#     can be attributed from the log instead of guessing.
#  S1 lock stale 4min -> 8min: worst-case round path was measured
#     ~265s (4.4min) > 4min stale threshold, so a slow-but-alive
#     round could be stolen by the next cron tick (concurrency race).
#     8min sacrifices at most 1 round on a really stuck lock instead.
#  S2 EXT path stops polluting the baseline: on external change the
#     old code fell through to the PREV_BPS persist line and overwrote it
#     round's measurement, shrinking the spike detector baseline for
#     a node nobody evaluated. Now: sync ledger, zero PREV_BPS
#     (fresh baseline next round), save, exit.
# All F1-F12 from v9.2 retained. Decision logic unchanged except
# the real stability column (same weights: W_LAT=30 W_THR=60 W_STAB=10).
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
# log trim (v8.1 rule: 200KB cap). F15: keep last 400 lines instead of
# 100 - a round writes 5-15 lines, so 100 lines only covered ~10-30 rounds
# and the A1 PREV_BPS fallback (grep the previous "OK [cur]" line) could
# miss. 400 lines is ~40KB, still far under the 200KB cap.
# F16 (v9.6): the trim moved BELOW the lock (was above it) and the temp
# name carries $$. Above the lock two overlapping cron rounds could both
# run tail+mv; the mv is atomic but the loser then keeps writing into an
# already-unlinked inode, silently losing its own log lines. Inside the
# critical section there is only one writer, and $$ avoids a name clash.

# ---- single instance lock (mkdir + stale guard > 8min) ----
# S1: worst-case round path ~265s (4.4min) > old 4min threshold, so a
# slow-but-alive round could be stolen by the next cron tick. 8min it is.
# S3: stale cleanup must run EVEN when mkdir fails. Old code exited on
# mkdir failure (old v9.3 exited here), so a stale lock (left by a crashed round) made
# every later round "SKIP another instance" forever, and the -mmin +8
# cleanup below was NEVER reached. Now: mkdir fails -> still check stale
# -> reclaim if old enough -> only then give up.
if ! mkdir "$LOCK_DIR" 2> /dev/null; then
  if [ -n "$(find "$LOCK_DIR" -mmin +8 2>/dev/null)" ]; then
    rm -rf "$LOCK_DIR" 2>/dev/null
    mkdir "$LOCK_DIR" 2>/dev/null || { log "SKIP lock contention after stale reclaim"; exit 0; }
  else
    log "SKIP another instance running"
    exit 0
  fi
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT INT TERM HUP
# F16: log trim runs inside the critical section (see note above).
[ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 204800 ] && tail -400 "$LOG" > "$LOG.$$.new" && mv "$LOG.$$.new" "$LOG"

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
# N2: also outputs a stability score = min/max of the samples * 100,
# as a SECOND field (tab separated). [100000,98000,99000] -> 98;
# [120000,60000,30000] -> 25; <2 nonzero samples -> 0.
# With SPEED_TRIES=2 the ratio is coarse; default 3 recommended.
speed_med(){
  vals=""; k=1
  while [ $k -le "$SPEED_TRIES" ]; do
    S=$(speed_once); [ -z "$S" ] && S=0
    vals="$vals $S"; k=$((k+1))
  done
  echo "$vals" | awk '{m=0;nz=0;for(i=1;i<=NF;i++){v[++m]=$i+0;if($i+0>0)nz++}
    if(nz<2){print 0"\t"0;exit}
    for(i=2;i<=m;i++){t=v[i];j=i-1;while(j>0&&v[j]>t){v[j+1]=v[j];j--};v[j+1]=t}
    print v[int((m+1)/2)] "\t" int(v[1]*100/v[m])}'
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
# N1: atomic write - a killed round must not leave a truncated state
# (half-written line 1 zeroes FAIL_N and resets cooldown/budget).
save_state(){ printf '%s\n%s\n%s\n%s\n' "v9:$1:$2:$RACE_TS" "LEDGER=$LEDGER" "RTS_LOG=$RTS_LOG" "PREV_BPS=$PREV_BPS" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"; }

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
# E1: keep the mihomo version in the log (once per round, cheap) - if a
# future mihomo commit changes /proxies structure (85c1798f precedent:
# provider nodes were moved out of /proxies), the log answers "why did
# F5/F10 suddenly behave differently" without guesswork.
VER_RESP=$(curl -s -m 5 -H "$AH" "$API/version" 2>/dev/null)
[ -z "$VER_RESP" ] && { log "WARN mihomo api unreachable, skip"; exit 0; }
NG_VER=$(printf '%s' "$VER_RESP" | tr ',' '\n' | grep -o '"version":"[^"]*"' | head -n1 | cut -d'"' -f4)
case "$NG_VER" in ""|*[!-.A-Za-z0-9+]*) NG_VER=unreadable ;; esac
log "RUN v9.7 mihomo=$NG_VER"
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
  # S2: do NOT fall through to the PREV_BPS persist line - that
  # polluted the spike baseline with a measurement of a node nobody
  # evaluated. Sync ledger, zero the baseline, let next round re-seed.
  log "EXT external change [$LEDGER] -> [$CUR] (manual/panel/restart), ledger synced, baseline reset, no action"
  LEDGER="$CUR"; PREV_BPS=0
  save_state "$FAIL_N" "$NOW"
  exit 0
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
# N3 side effect (documented, accepted): the lower sample is what gets
# persisted as PREV_BPS, so the spike detector baseline shrinks a bit -
# when tuning SPIKE_PCT remember DROP is measured against the lower bar.
if [ $SUSPECT -eq 1 ]; then
  B2=$(speed_once); [ -z "$B2" ] && B2=0
  [ "$B2" -gt 0 ] && [ "$B2" -lt "$BEST_BPS" ] && BEST_BPS=$B2
fi
GW=$(google_word "$G")

# A1 spike confirm: F8 - PREV_BPS from state line 4; log is only a fallback
# (log trims to tail-400, which can still silently kill the old grep-based path)
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
    # F17 (v9.6): healthy round inside cooldown. Old code exited without
    # saving, so the PREV_BPS refreshed by the F8 persist line (spike
    # baseline for the next round) and any stale FAIL_N were both dropped.
    # The healthy path outside cooldown (bottom of SECTION 4) already does
    # save_state 0; this makes both consistent. A recovered node inside
    # cooldown is the NORMAL case, not an edge case.
    save_state 0 "$NOW"; exit 0
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
# F13: budget + cooldown are NOT committed here. They are committed in
# SECTION 5a, after the stage-1 screen has proved a real pool exists, so
# a failed or too-small screen no longer arms RACE_CD or burns a slot.

# ============================================================
# SECTION 5: stage-1 screen via group delay (no unpin, no switch)
# ============================================================
SELU=$(enc "$SEL")
DELAY_JSON=$(curl -s -m 30 -H "$AH" "$API/group/$SELU/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000" 2>/dev/null)
[ -z "$DELAY_JSON" ] && { log "ERR screen no response, keep [$CUR]"; save_state "$FAIL_N" "$NOW"; exit 0; }

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
# F18 (v9.6): screen failure no longer writes FAIL_N=1.
# A screen that returned nothing means the API/group probe wobbled, i.e. an
# INFRASTRUCTURE fault, not evidence that the current node degraded. Writing
# FAIL_N=1 nudged the next mild anomaly over FAIL_TRIGGER and raced for a
# reason nothing had measured - the same half-accounting F13 removed from the
# budget/cooldown side. Keep the counter untouched and just log.
if [ -z "$TPS_ALL" ] || [ "$screen_cnt" -lt 1 ]; then
  log "ERR screen produced nothing, keep [$CUR]"; save_state "$FAIL_N" "$NOW"; exit 0
fi
# S4: pool floor - a 1-2 node screen is too small to race meaningfully
# (TOP_PICK=3 can never fill, and a race over a tiny pool has a high
# chance of just re-validating the current node while burning budget).
# Keep current, log clearly, don't race. Only <1 (empty) was guarded
# before; now <3 bails too.
# NOTE (F19, v9.7: fixed by the F22 precheck below in SECTION 5a): this
# floor checks POOL SIZE, not LIVE-CANDIDATE count. The pool is built from
# group-delay replies, and stage-2 still re-gates every candidate on 204 +
# google. A >=3 pool can still yield zero seats (all TOPS dead); before v9.7
# that path was only caught at the SEATS<1 branch - after the budget slot was
# already spent. The F22 precheck now re-probes each TOPS member once BEFORE
# the budget commit, so the all-dead case exits without burning a slot;
# SEATS<1 mid-race (node dying after its precheck passed) still spends the
# slot, but then real measurement traffic was generated - the slot was earned.
if [ "$screen_cnt" -lt 3 ]; then
  log "WARN screen pool too small to race ($screen_cnt nodes < 3), keep [$CUR]"
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
# N4: group delay fires one goroutine per member, NO concurrency cap
# (mihomo groupbase.go URLTest L237-263; provider healthcheck has
# SetLimit(10), group delay does not). Big pools = big probe bursts.
if [ "${screen_cnt:-0}" -gt 80 ] 2>/dev/null; then
  log "WARN screen pool very large ($screen_cnt nodes) - group delay probes all concurrently, consider narrowing the group"
fi
TOPS=$(printf '%s\n' "$TPS_ALL" | sort -n | head -"$TOP_PICK" | cut -f2-)
log "  screen TOP${TOP_PICK}: $(printf '%s' "$TOPS" | tr '\n' ' ') (from $screen_cnt, typed=$TYPE_N)"

# ---- shadow exit: measurement-without-switch would be fake ----
# NOTE (F13): DRY_RUN exits here, i.e. BEFORE the budget commit, so a
# shadow round never consumes a budget slot or arms the cooldown.
if [ "$DRY_RUN" = "1" ]; then
  log "DRY shadow: real run would switch-measure [$(printf '%s' "$TOPS" | tr '\n' ' ')] + cur, no action taken"
  save_state 0 "$NOW"; exit 0
fi

# ============================================================
# SECTION 5a: race budget + cooldown commit (F13: after screen)
# ============================================================
# Budget is a hard ceiling per rolling window; severe does NOT break it.
# Committing here (not in SECTION 4) means only a race that will really
# run costs a slot or starts the cooldown clock.
# ---- F22 (v9.7): pre-race liveness precheck ----
# One 204 probe per TOPS member BEFORE the budget commit. If EVERY probe
# fails the race has nothing to measure - infrastructure-grade fault, same
# semantics as F13/F18 screen faults: no FAIL_N write, no budget slot, no
# cooldown; distinct log tag ("ERR precheck") so its rate can be counted.
# Cost when healthy: TOP_PICK x CAND_204_TMO = 3 x 2s = 6s extra worst
# case, still inside the S1 265s + margin. cur is NOT pre-probed: it only
# matters when all TOPS are dead, and stage 2 measures it under the old
# gates anyway.
PC_OK=0
PC_TOT=0
for N in $(printf '%s' "$TOPS" | tr '\n' ' '); do
  [ -z "$N" ] && continue
  PC_TOT=$((PC_TOT+1))
  C1=$(curl -s -o /dev/null -w "%{http_code}" -m "$CAND_204_TMO" "https://www.gstatic.com/generate_204" 2>/dev/null)
  [ "$C1" = "204" ] && PC_OK=$((PC_OK+1))
done
if [ "${PC_TOT:-0}" -lt 1 ] 2>/dev/null; then
  log "ERR precheck no TOPS member to probe, keep [$CUR]"
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
if [ "$PC_OK" -lt 1 ]; then
  log "ERR precheck all TOPS dead (0/$PC_TOT), keep [$CUR] - infra fault, no slot spent"
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
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
# SECTION 6: stage-2 race, cur-first, per-switch confirm
# ============================================================
RACE_RES=/tmp/ng9_race.$$        # format: name TAB lat TAB medbps TAB stab
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
CMED_STAB=$(speed_med)
CMED=$(printf '%s\n' "$CMED_STAB" | cut -f1)
CSTAB=$(printf '%s\n' "$CMED_STAB" | cut -f2)
CUR_LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' -v n="$CUR" '$2==n{print $1; exit}')
# F20 (v9.6): cur missing from the pool must NOT cost it the latency vote.
# cur already cleared the 204 and google gates this round, so it is a REAL
# node; the only thing missing is its delay sample. The pool can miss it when
# cur is not a member of SEL (cross-group pick) or when that one group-delay
# probe timed out (groupbase.go URLTest only maps err==nil). Old code fell
# back to a punitive 999ms, and with sc_lat = bestlat/(lat+1)*100 that drops
# cur to ~70/100 even when its true latency was the best, which can push a
# healthy cur past TIE_PCT and cause a needless switch.
# New behaviour: estimate cur's latency as the pool's median delay (neutral,
# neither rewarded nor punished). 999 only if the pool has no usable delay.
if [ -z "$CUR_LAT" ]; then
  CUR_LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' 'NF>1 && $1 ~ /^[0-9]+$/{print $1}' \
    | sort -n | awk '{a[NR]=$1} END{ if(NR>0) print a[int((NR+1)/2)]; else print 999 }')
  [ -z "$CUR_LAT" ] && CUR_LAT=999
  log "  cur [$CUR] not in delay pool, lat estimated at pool median ${CUR_LAT}ms (F20)"
fi
if [ "$C_OK204" -eq "$TRY204" ] && [ "$CG" != "2" ]; then
  printf '%s\t%s\t%s\t%s\n' "$CUR" "$CUR_LAT" "$CMED" "$CSTAB" >> "$RACE_RES"
  log "  cur [$CUR] ok204=${C_OK204}/${TRY204} google=$(google_word $CG) thr=${CMED}B/s stab=${CSTAB} lat=${CUR_LAT}ms"
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
  MED_STAB=$(speed_med)
  MED=$(printf '%s\n' "$MED_STAB" | cut -f1)
  STB=$(printf '%s\n' "$MED_STAB" | cut -f2)
  LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' -v n="$N" '$2==n{print $1; exit}')
  [ -z "$LAT" ] && LAT=999
  printf '%s\t%s\t%s\t%s\n' "$N" "$LAT" "$MED" "$STB" >> "$RACE_RES"
  log "  cand [$N] ok204=${OK204}/${TRY204} google=$(google_word $CG) thr=${MED}B/s stab=${STB} lat=${LAT}ms"
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

# columns: name TAB lat TAB med TAB stab. N2: stability is real now
# (min/max ratio of the 3 throughput samples, 0-100). W_STAB=0 in
# conf disables its vote (ratio still recorded in the log table).
awk -F'\t' -v wl="$W_LAT" -v wt="$W_THR" -v ws="$W_STAB" '
  NR==FNR {
    if (FNR==1 || $2+0 < bestlat+0) bestlat=$2+0
    if (FNR==1 || $3+0 > bestthr+0) bestthr=$3+0
    if (FNR==1 || $4+0 > beststab+0) beststab=$4+0
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
    # N2: real stability = own ratio vs best ratio (never above 100);
    # with ws=0 the stab vote vanishes and scores match v9.2 exactly
    stab = $4+0
    sc_stab = (beststab <= 0) ? 0 : stab * 100 / beststab
    if (sc_stab > 100) sc_stab = 100
    score = (wl*sc_lat + wt*sc_thr + ws*sc_stab) / (wl + wt + ws)
    printf "%.1f\t%s\t%s\t%s\t%s\n", score, $1, $2, $3, stab
  }
' "$RACE_RES" "$RACE_RES" | sort -rn > "$SCORED"

log "SCORE (score/name/lat/thr/stab):"
TABC=$(printf '\t')
while IFS="$TABC" read -r sc nm lt tb st; do
  log "  $nm score=$sc lat=${lt}ms thr=${tb}B/s stab=${st}"
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
    # F21 (v9.6): guard the division inside awk. The old shell test
    # [ "$CUR_SCORE" = "0" ] could never fire, because the score column is
    # printed with "%.1f" and is therefore always "0.0", never the literal
    # "0". With CUR_SCORE=0.0 the next awk divided b*100/0 -> empty output ->
    # a log line reading "margin % under TIE_PCT". Guarding on c+0<=0 fixes
    # it regardless of how the string happens to be formatted.
    MARGIN_PCT=$(awk -v b="$BEST_SCORE" -v c="$CUR_SCORE" 'BEGIN{ if(c+0<=0) c=0.1; printf "%.0f", b*100/c-100 }')
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
