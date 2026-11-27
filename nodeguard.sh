#!/bin/sh
# ============================================================
# nodeguard.sh v9.14 - visible config failures + one lock domain
# Base: v9.13 (1800 lines). All v9.13 (F31) and earlier fixes retained.
# v9.14 changes (two defects found by the R/S robustness rounds):
#  F32 CONFIG FAILURES WERE INVISIBLE UNDER CRON. Every fatal config path
#     (missing conf file, unbalanced quote in conf, missing NG_SECRET /
#     NG_API / NG_GROUP_SEL) died with a message on STDERR only. Cron discards
#     stderr, so a broken conf = the guard silently stopped and nobody could
#     tell: the round log stayed empty, `log()` was not even defined yet, and
#     there was no marker anywhere. Measured: conf with NG_GROUP_SEL="a"b"
#     -> rc=2, stdout empty, zero log lines.
#     Fix: a cfg_fatal() helper defined BEFORE the conf is sourced. It writes
#     one FATAL line into the round log (path taken from the conf when it was
#     readable and NG_LOG is parseable, else /root/nodeguard.log), echoes the
#     same line to stderr, and raises a syslog entry via logger when available.
#     A pure syntax pre-check (sh -n on the conf) turns the one failure mode
#     that would kill the shell before cfg_fatal() could run (a sourced file
#     with a syntax error aborts the CURRENT shell at parse time, verified on
#     ash) into an ordinary fatal path. NG_LOG is also read up front from the
#     conf text with a cheap grep, because the conf may not be sourceable.
#  F33 SELFUPDATE AND NODEGUARD USED DIFFERENT LOCK DOMAINS. nodeguard guarded
#     its round with mkdir /tmp/nodeguard_v9.lock; /root/selfupdate.sh guarded
#     its deploy with flock on /tmp/nodeguard.single and documented that
#     "nodeguard's flock holds /tmp/nodeguard.single". nodeguard never touched
#     that file (grep: NOT FOUND), so the two guards could never see each
#     other. Measured: with a round in flight, `flock -n
#     /tmp/nodeguard.single` was acquired instantly. Consequence: at 05:10 the
#     daily sync can cp a new nodeguard.sh over the file while the running
#     shell is still reading it, i.e. execute a mix of old and new code, and a
#     mixed body is exactly the state that can switch nodes on a bad verdict.
#     Fix: nodeguard now ALSO holds flock -n on /tmp/nodeguard.single for the
#     whole round (same file, same lock type as selfupdate). The mkdir lock
#     stays as the primary single-instance gate, so behaviour is unchanged if
#     flock is missing (checked: absent -> devnull fd, the round proceeds).
#     selfupdate's existing guard now works unchanged.
# ------------------------------------------------------------------------
# nodeguard.sh v9.13 - subscription self-heal (boot-order fallout guard)
# Base: v9.12 (1625 lines). All v9.12 fixes (F28/F29/F30) retained.
# v9.13 changes (one additive guard, no gate/scoring change):
#  F31 SUBSCRIPTION SELF-HEAL. The 2026-11-27 incident: /etc/init.d/nikki
#     fetched the subscription INSIDE start_service, i.e. before the core and
#     tproxy existed, so curl left the box unproxied, hit the CDN real IP and
#     was blocked - boot took 67s and finished with success=0, leaving the
#     panel with a stale profile. The init.d side is now fixed (fetch deferred
#     until the hijack is live; a PRESENT file no longer re-downloads on boot),
#     but init.d is NOT opkg-managed on this box, so any future nikki reinstall
#     silently restores the old order. This guard is the fallback: once per
#     round, AFTER the API proved alive, if uci success=0 (or the value is
#     missing/garbage) re-run the same update_subscription OUT OF BAND
#     (detached, hard 120s cap). Design constraints honoured:
#       - never blocks the round: the refresh is backgrounded, the round goes
#         on to screen/race immediately (a 67s CDN stall must not delay it);
#       - rate limited by the cron tick itself (5min) plus a "near success"
#         skip (success=1 and update within 6h -> do nothing), so a broken CDN
#         costs 3 attempts per 15min at worst, not a hot loop;
#       - purely additive: no state line change (still 4 lines), no new file,
#         no scoring/gate impact. On success the panel's next scheduled
#         restart (04:00) picks the fresh profile up; nothing restarts here,
#         so a heal can never drop the LAN's connectivity mid-round.
#     NOTE the deliberate non-goal: we do NOT touch a healthy subscription.
#     A successful fetch only rewrites the stored file; the RUNNING config is
#     untouched until a restart, so an unnecessary refetch is harmless but a
#     refetch storm is not - hence the 6h near-success skip.
# ------------------------------------------------------------------------
# nodeguard.sh v9.12 - common-vote margin + honest ceilings
# Base: v9.11 (1487 lines). All v9.11 fixes (F24/F25/F26/F27) retained.
# v9.12 changes (bug fixes, NOT additive):
#  F28 common-vote margin. v9.11's score used a PER-ROW denominator: a row
#     with jit=-1 (the NO-DATA marker) dropped the jitter term from its own
#     numerator AND denominator, so rows with different data availability were
#     compared on DIFFERENT vote sets. Two concrete damages, both verified in
#     the sandbox:
#      dmg1: jitter-only weights + cur carrying jit=-1: cur scored the -1.0
#            sentinel, the single candidate scored 100.0, MARGIN fired on a
#            sentinel-vs-real comparison and the round switched cur off for
#            having NO DATA (repro: repro_nometric_mixed.sh).
#      dmg2: default weights: cur (always jit=-1, one S3 sample) is scored on
#            105/115th of the vote mass a full-data candidate enjoys, so a
#            candidate collects up to ~13pp of "participation bonus". A
#            jit=200ms candidate still beat cur on an otherwise tied pool
#            (defect_scan.sh S4: 99.7 vs 96.4), silently loosening TIE_PCT=20
#            down to an effective threshold of a few percent.
#     The fix: the score awk now emits a SECOND column, score3 = the weighted
#     score on the lat/thr/stab votes ONLY (all three are always live: every
#     seated row has a real latency, a real median, a real stability rating).
#     The BEST-vs-CUR margin test then compares on the COMMON vote set:
#       - cur jit >= 0 and BEST jit >= 0: compare the FULL scores (jitter
#         included) - both rows have the data, the vote is honest;
#       - otherwise: compare score3 for both (and if BEST carries no jitter
#         data but some OTHER row did, that other row is not in a margin pair
#         against cur anyway - only BEST is).
#     Sort/DECIDE/best-row selection keeps using the FULL per-row score: a
#     jitter-rich candidate still legitimately outranks a jitter-less twin
#     for the winner PICK; what changed is only the KEEP-vs-SWITCH margin
#     arithmetic for the node cur actually is.
#     If even score3 is unavailable (all four weights zero is already forced
#     to defaults by the existing guard, so this needs W_LAT=W_THR=W_STAB=0
#     with only W_JIT live AND no jitter data anywhere - the F27 world), the
#     existing NO_METRIC branch keeps cur (unchanged).
#  F29 JIT_NEUTRAL WARN. The knob was removed in v9.11 (the -1 marker replaced
#     it) but a stale conf line was IGNORED silently, which reads as "the knob
#     still works" to an operator who never read the changelog. One log line
#     per round when the deprecated key is present. Log layer only.
#  F30 serial /proxies refetch removed (ceiling 94s -> 84s). S5 fires three
#     GETs in parallel and writes the /proxies group set to GRP_F; the old
#     code then refetched $API/proxies SERIALLY (-m10) into the SAME variable,
#     so the parallel result was never used and the serial fetch owned up to
#     10s of the ceiling by itself. v9.10's parallelisation was thus only
#     2/3 effective on paper. Both fetches returned the same bytes (same
#     read-only GET, no side effects), so dropping the serial one loses
#     nothing. Also: the SCREEN_NORESP early exit now removes the S5 temp
#     files (TYPE_F/GRP_F/DLY_F already handled) so no /tmp leak remains.
#  r1 note (housekeeping, no behaviour): the audit's "94s -> 84s" figure
#     counts the dropped serial fetch as a pure -10s; the committed cost model
#     (cost_v910.py) keeps PROXY_T inside the S5 parallel max(15,15,10)=15s,
#     so its 94s was ALREADY leak-free and stays the derivation of record.
#     The -10s the audit saw was only correct for the OBSERVED serialized
#     execution (busybox waits do not preempt); on the router the two S5 curls
#     overlap, so the real saving is small and the 84s figure is the safe
#     documented bound, not a promise of 10s faster rounds.
# ------------------------------------------------------------------------
# nodeguard.sh v9.11 - intra-round loss/jitter scoring + capped-EMA baseline
# Base: v9.10 (1233 lines; F24/F25/F26 port ideas from mihomo PR #2711 Smart)
# v9.11 changes (additive to gates; score gains one dimension, baseline smarter):
#  F24 loss column: every seated row records loss100 = the 204-miss share
#     of its TRY204 probes (gate unchanged; with TRY204=3 a passing node has
#     loss=0, the column generalises to TRY204=5 via conf where 4/5 seats
#     with loss100=20). Ported spirit: mihomo's confidence gate - a node that
#     fails the gate never seats, so no seated node is punished on thin data.
#  F25 jitter column: the TRY204 probes now also record %{time_total}; the
#     span (max-min, ms, integer) goes into the score. Lower is better;
#     sc_jit = (bestjit+1)/(jit+1)*100 (the +1 keeps a legitimate 0ms span
#     from zeroing the whole vote). A row with NO measurable span carries the
#     marker jitter=-1 and is excluded from the jitter vote entirely (term
#     dropped from numerator AND denominator) - never rewarded, never punished.
#     W_JIT (default 15) joins the weighted sum; W_JIT=0 restores v9.10's
#     ranking for seats whose other columns are unchanged.
#  F26 capped-EMA PREV_BPS: v9.10 overwrote the spike baseline with the newest
#     sample, so a one-off burst (speedtest next door) raised next round's
#     bar by up to 300 percent and manufactured fake "spikes". Now the EMA
#     moves slowly: new = (old*EMA_A + capped*(100-EMA_A))/100 where capped is
#     old*EMA_CAP% on the way UP only; samples > old*EMA_SPIKE% are SPIKES and
#     do not touch the baseline at all (logged). PREV_BPS=0 seeds directly.
#     A confirmed switch to a different node zeroes the baseline (re-seed next
#     round), so old-node history can never pin a fast new node in spike jail.
#     v9.10 behaviour (plain overwrite) is available via EMA_A=0 EMA_CAP=10000
#     EMA_SPIKE=1000000 (and is then bit-identical on the keep path).
#  NOT shipped (deliberate): dual-source 204 probing, cross-round per-node
#     loss windows, SpeedObserver passive speed (blocked by the 4-line state
#     rule / no-daemon architecture; see design doc).
# ------------------------------------------------------------------------
# nodeguard.sh v9.10 - racing ceiling trim to <=100s (scheme B, accepted precision loss)
#     v9.11 keeps the 94s ceiling; v9.12 lowers it to 84s (F30, see below).
# Base: v9.9 (V1-V6; 1209 lines at v9.10 edit start)
# v9.10 changes (NOT additive: user accepted semantic changes, but the
# architectural constraints stay - single-file sh + cron no daemon, 4-line
# state, ASCII-only comments, 100% verifiable answers, no cloud deploy/push):
#  V7 per-phase timing, OFF by default. NG_TIMING=1 logs a cumulative
#     wall-clock line "t:<phase>=<Ns>" for S2/S3/S5/6a/6b (T0 set in SECTION 1).
#  B-racecost ceiling cut from v9.9's 281s to 94s (scheme B), then to 84s in
#     v9.12 (F30: the serial /proxies refetch removed; the parallel S5 block
#     already produces that file, and a redundant serial -m10 fetch alone was
#     worth 10s of the old 94s bound). Precision loss (v9.10, retained):
#      B1 SPEED_TRIES 3->2 (2 samples = mean, no true median)
#      B2 TOP_PICK    3->2 (comparison pool shrinks)
#      B3 group delay -m30->-m15 (slow groups may screen SCREEN_NORESP)
#      B4 PUT retries 3->2 + rollback single-shot (weaker API: lower success)
#      B5 6a reuses S3 samples for cur (no fresh re-probe; stab=100 neutral)
#     Parallelism that makes it cheap (all `&`+`wait`, no semantic change):
#      S2 version + type/now both fire (same /proxies response parses CUR)
#      S3 google/204/speed three probes parallel
#      S5 delay + providers + proxies three requests parallel
#      6b google + speed_med parallel per candidate
#     v9.9's 281s bound below is kept AS HISTORY; the current upper bound is 84s.
# ------------------------------------------------------------------------
# v9.9 changes (the file below this block is the v9.9 changelog, retained as
#   history; v9.10 supersedes the ceiling figure, NOT the behavioural notes):
# v9.9 changes (ADDITIVE ONLY: no threshold, gate, weight or decision
# rule is touched; the v9.8 sandbox baseline stays directly comparable):
#  V1 redundant-PUT elimination. GROUP_NOW tracks the group's actual
#     landing point and is updated ONLY from real get_now readbacks
#     (put_node's PUT_RET global IS the readback), never guessed. put_node
#     returns immediately when the requested target equals GROUP_NOW: no
#     PUT is sent and the target itself is the confirmed value.
#     MECHANISM (v9.9 fix): put_node reports through the GLOBALS PUT_RET
#     and GROUP_NOW, NOT through stdout. The first cut used $(put_node ..)
#     and lost every GROUP_NOW assignment to the command-substitution
#     subshell: the parent stayed on the SECTION 2 seed value, so a restore
#     after an all-rejected 6b looked like a no-op and was SKIPPED while the
#     group actually sat on the last measured candidate (sandbox c3/c11/c12
#     failed exactly this way). Every call site is now "put_node X; Y=$PUT_RET".
#     Failure
#     direction: a stale GROUP_NOW would skip a PUT that should have
#     happened - but staleness can only come from an external change,
#     which the next round's SECTION 2 EXT check catches anyway, and
#     every skippable PUT is a defensive re-assert (keep branch) or a
#     rollback the readback already proved unnecessary. on_exit resyncs
#     GROUP_NOW from its own fresh readback BEFORE restoring, so the
#     TERM path can never mis-skip. Saving is REAL but CONDITIONAL: a PUT
#     is skippable only when a readable readback already proves the group
#     sits on the target. Two sites qualify in practice - the keep-branch
#     re-assert when every 6b candidate was rejected (the group never left
#     cur) and a rollback to a node a rejected PUT demonstrably left the
#     group on. Each such skip saves the SUCCESSFUL put cost (10s).
#     The 281s all-timeout ceiling is NOT reduced: when every probe times
#     out the readback is unreadable, GROUP_NOW is cleared, and every PUT
#     still goes out. So the ceiling stays 281s and V1 is a latency win on
#     the common path, not a ceiling win.
# V2 failure cause codes. Every failure/skip log line ends with a
#     stable grep-able "cause=<CODE>" uppercase token:
#       API_DOWN GROUP_TYPE READ_FAIL EXT_CHANGE SCREEN_NORESP
#       SCREEN_EMPTY SCREEN_SMALL BUDGET COOLDOWN_MILD SPIKE_WAIT
#       MILD_WINDOW G204_FAIL GOOGLE_POLLUTED PUT_REJECTED PUT_UNKNOWN
#       ALL_DEAD RESTORE_FAIL KEEP_REJECTED SWITCH_ROLLBACK
#       NO_METRIC (F27, v9.11 r1) NO_COMMON_METRIC (F28, v9.12)
#     Log layer only; no judgement logic changed.
#  V3 read-only self-check. "NG_CHECK=1" env or a bare "--check" argv
#     runs a pre-lock, pre-write check: API reachability, group type,
#     current selection, mihomo version, providers API answer, cooldown
#     remaining, budget balance, static cost ceilings. NG_CHECK_DEEP=1
#     additionally fires ONE stage-1 group-delay call and reports the
#     RAW entry count (unfiltered; the filtered pool only exists in a
#     full round). Touches no lock, no state, no log, no group.
#     Exits 1 if any core check fails.
#  V4 egress trace, OFF by default. NG_EGRESS=1 logs one cdn-cgi/trace
#     fetch (ip=/loc=) after a settled round (keep-confirm or confirmed
#     switch). NG_TRACE_URL overrides. Diagnostic aid only - NOT a
#     gate; not yet verified on a real router.
#  V5 version probe in check mode: reports the mihomo version string
#     and whether /providers/proxies answers, making the M5/F5 degraded
#     paths visible from check output. Deliberately NO minimum-version
#     gate: no source basis exists for a hard floor number; hardcoding
#     one would be a guess.
#  V6 single version constant NG_VERSION, printed by the per-round log
#     (was a literal "v9.8" at the log site - the F14 class of bug:
#     v9.6 shipped logging "v9.3"). mihomo's version keeps its own
#     variable name NG_VER (distinct).
# Time-cost note (v9.9 supersedes EVERY older figure in this file):
#     the v9.8 header carried three stale derivations (195s trade-off 2,
#     360s S1, 265s legacy S1); all three added mutually exclusive paths
#     or missed the settle rollback. Corrected arithmetic:
#       healthy round ceiling   34s (real 3-8s; SECTION 2+3 only)
#       racing round ceiling  281s = 34 + 55 + 24 + 102 + 66
#         (S2+S3 / S5 screen / 6a cur / 6b 3x max(34,33) / 7 settle)
#         V1 does not lower this ceiling (see V1 above: all-timeout means
#         unreadable readbacks -> no skip). It lowers real rounds only.
#       worst hourly occupation 2 x 281s = 16%
#       8min lock threshold margin 480 - 281 = 199s
#     Corrected in place below; old numbers are quoted AS HISTORY only
#     where a note explains they were superseded.
# (v9.8 changelog follows)
# nodeguard.sh v9.8 - retract F22 precheck, deferred budget commit (F23)
# Base: v9.7 (F1-F22 code state; 41015 bytes / 812 total lines / 783 non-blank, 2026-11-24)
# v9.8 fix (F23 + F22 retraction):
#  F22 RETRACTED (v9.7 -> v9.8). The v9.7 precheck loop issued
#     "curl ... https://www.gstatic.com/generate_204" inside a
#     "for N in $(...)" loop but the curl command line never referenced
#     $N. Every iteration therefore measured whatever node the selector
#     already pointed at (traffic leaves through the transparent proxy;
#     see delivery doc section I), i.e. cur - not the TOPS members.
#     Consequences were exactly inverted from the intent:
#       - cur healthy -> PC_OK=3 always, precheck filtered nothing and
#         cost 6s of dead time plus 3 extra 204 probes aimed at cur;
#       - cur dead    -> PC_OK=0 -> "ERR precheck all TOPS dead" -> exit
#         WITHOUT racing. The one case a liveness guard must handle was
#         the one it blocked, every 5 minutes, forever.
#     Root cause is an implementation bug, NOT an API limitation: the
#     curl inside the loop never referenced $N, so every iteration probed
#     whatever the selector already pointed at. A per-member probe IS
#     available on this API: GET /providers/proxies/{provider}/{name}/
#     healthcheck exists and reuses the same getProxyDelay handler
#     (route/provider.go L30-38 -> proxies.go L106-148, which also parses
#     the "expected" query at L116). Only the PLAIN /proxies/{name}/delay
#     form is 404 for provider nodes, because provider members never
#     register in tunnel.Proxies() (proxies.go L46-60, tunnel.go L219).
#     So v9.7 could have worked had it used the right URL and passed $N;
#     it used neither. The precheck is still removed in v9.8 rather than
#     patched, because F23 makes it redundant. Decision (v9.9 candidate,
#     declined): a correct precheck would use the provider-scoped
#     healthcheck and would only trim the all-dead round, whose ceiling is
#     195s but is usually far shorter (see trade-off 2). In exchange it
#     adds a second probe path that must stay in sync with the stage-2
#     gates (204 x TRY204, google state, throughput) and would need the
#     provider name per node, which the screen does not currently carry.
#     Not worth it: F23 already removed the only real harm (a wasted
#     slot). F23 supplies the real fix for F19's goal.
#  F23 (P3, real fix for F19) Budget slot and cooldown are now committed
#     at the FIRST real seat instead of before the race (SECTION 5a
#     check only). A race that seats nobody leaves RACE_TS and RTS_LOG
#     untouched, so an all-dead pool costs neither a cooldown window nor
#     a budget slot - which is what F19 was reaching for and what F22
#     failed to deliver. A race that seats >=1 node did generate real
#     measurement traffic, so its slot is earned.
#     Accepted trade-off: a round killed by a signal between its first
#     seat and the following save_state can lose that commit, and the
#     next round races again. TERM inside a multi-minute round is rare,
#     and the failure direction is one extra race, never a stuck guard.
#     Accepted trade-off 2 (cost derived from the script's own timeout
#     constants, NOT measured on a real box; arithmetic v9.9-corrected:
#     the original 195s figure added mutually exclusive paths - put_node
#     failure and measurement never run in the same candidate iteration -
#     and missed the settle rollback PUT): when cur is dead AND every
#     TOPS member is also dead, v9.8 runs the full stage-2 race where
#     v9.7 bailed early. Worst case, every probe hitting its -m ceiling:
#       S2+S3 always-on : 5+5+5 + 6+5+4+4                =  34s
#       S5 screen       : 30 + 15 + 10                  =  55s
#       6a cur          : 3x2(204) + 6(google) + 3x4     =  24s
#       6b per cand     : max(34 switch-ok, 33 put-fail) =  34s
#       6b x TOP_PICK 3                                      = 102s
#       7 settle        : max(33 keep, 66 switch-fail)   =  66s
#       racing ceiling                                       = 281s
#     (v9.9 V1 trims a provably redundant PUT when - and only when - a
#     readable readback proves the group never moved. In the all-timeout
#     case this ceiling spends, so it stays 281s; real rounds are
#     shorter by up to 2 x 10s in the rejected-candidate sub-case.)
#     That 281s is an UPPER BOUND, not a duration: a dead endpoint usually
#     answers 000 in milliseconds on TCP reset / DNS failure, so a real
#     round is normally far shorter. No sandbox number is quoted here
#     because the mock returns instantly and would prove nothing.
#     This cost is NOT avoidable: distinguishing "all dead" from "cur dead
#     but a TOPS member alive" is exactly the C2 case v9.7 got wrong, and
#     the only way to tell them apart is to actually enter the race.
#     Probes that fail this way move no billable traffic (204/speed
#     requests that never complete), so the real cost is wall time and API
#     calls, not quota. Consequence to expect in the log: an all-dead
#     subscription
#     produces one full stage-2 round every cron tick (ceiling 281s, real
#     time normally much shorter) and never arms the
#     cooldown, i.e. it keeps retrying until the pool recovers. That is
#     the intended behaviour - a guard that stops trying when every node
#     is down is worse than one that keeps trying.
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
#  F19 (P3, v9.8: FIXED by F23) S4's pool floor checks POOL SIZE, not the
#     number of live candidates; a >=3 pool could still seat nobody and only
#     found out at the SEATS<1 branch, after the slot was spent. v9.7 tried
#     to fix this with the F22 precheck and the attempt was a no-op that
#     inverted the behaviour (see F22 RETRACTED at the top). v9.8 fixes it
#     properly by moving the commit itself: SECTION 5a now only CHECKS
#     budget/cooldown, and the slot is written at the first real seat
#     (F23 below). An all-dead pool therefore leaves RACE_TS and RTS_LOG
#     untouched.
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
#  S1 lock stale 4min -> 8min: the worst-case round path was put at
#     ~265s (4.4min) when S1 was introduced, which is > the old 4min
#     stale threshold, so a slow-but-alive round could be stolen by the
#     next cron tick (concurrency race). NOTE (v9.9): neither that 265s
#     figure nor the later 360s v9.8 re-derivation is reproducible - both
#     added mutually exclusive paths. The v9.9-corrected racing ceiling
#     is 281s (4.7min), still > 4min, so the 8min threshold still holds
#     with 199s of margin even if every single probe times out fully
#     (upper bound, not a duration).
#     (v9.10 supersedes, v9.12 F30 lowers: ceiling now 84s -> margin 396s; see header block.)
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
#        proxies map -> always 404, verified live + tunnel.go L219.
#        NOTE: that 404 applies ONLY to the plain /proxies/{n}/delay
#        form. The provider-scoped form
#        /providers/proxies/{provider}/{name}/healthcheck is a different
#        route and does work for provider members (route/provider.go L30-38).)
# Google states follow v8.1: 1=clean 2=polluted(cn or 000) 0=unknown;
#        only 2 counts as bad; unknown is tolerated (v8.1 proven).
#        Severe (204-dead-severe-bps / polluted / very low thr) breaks
#        the race cooldown, mild anomalies debounce via time window.
# All comments ASCII only (router locale safety)
# ============================================================

# ---- config ----
CONF="${NG_CONF:-/root/nodeguard.conf}"   # NG_CONF lets tests use a sandbox conf
# F32: a fatal config problem used to die on STDERR only, which cron throws
# away, so a broken conf made the guard disappear silently. cfg_fatal() is
# defined BEFORE the conf is read so every one of those paths leaves a line in
# the round log (and in syslog when logger exists).
# NG_LOG is pre-read from the conf TEXT (grep, no sourcing) because a conf can
# be unparseable; until then the default log path is assumed.
NG_LOG_PRE=$(grep -m1 '^[[:space:]]*NG_LOG=' "$CONF" 2>/dev/null | sed 's/^[[:space:]]*NG_LOG=//; s/^"//; s/"$//')
NG_BOOTLOG="${NG_LOG_PRE:-${NG_LOG:-/root/nodeguard.log}}"
cfg_fatal(){
  # $1 = reason (ASCII, becomes part of the log line)
  _cf_msg="FATAL $1"
  printf '%s %s\n' "$(date '+%m-%d %H:%M:%S')" "$_cf_msg" >> "$NG_BOOTLOG" 2>/dev/null
  logger -t nodeguard "$_cf_msg" 2>/dev/null
  printf '%s: %s\n' "${0:-nodeguard}" "$_cf_msg" >&2
  exit 2
}
[ -f "$CONF" ] || cfg_fatal "missing conf $CONF (no round ran, guard is DOWN until this is fixed)"
# F32: a syntax error inside a SOURCED file aborts the current shell at parse
# time, so no in-shell guard can catch it. sh -n is a pure parse (nothing is
# executed) and therefore the only reliable gate.
sh -n "$CONF" 2>/dev/null || cfg_fatal "conf $CONF has a shell syntax error (check quotes), guard is DOWN"
. "$CONF"
[ -n "${NG_SECRET:-}" ]    || cfg_fatal "NG_SECRET missing in $CONF, guard is DOWN"
[ -n "${NG_API:-}" ]       || cfg_fatal "NG_API missing in $CONF, guard is DOWN"
[ -n "${NG_GROUP_SEL:-}" ] || cfg_fatal "NG_GROUP_SEL missing in $CONF, guard is DOWN"
API="$NG_API"
AH="Authorization: $NG_SECRET"
SEL="$NG_GROUP_SEL"

# V6 (v9.9): single version constant - the per-round log prints this.
# (v9.6 F14 shipped logging "v9.3": a literal at the log site is how
# that happens. The mihomo version keeps its own name NG_VER.)
NG_VERSION=v9.14

# v9 tunables (override in conf)
WIN_SEC=${WIN_SEC:-900}          # mild-anomaly window: 2 hits inside window
FAIL_TRIGGER=${FAIL_TRIGGER:-2}  # hits needed inside window
RACE_CD=${RACE_CD:-900}          # cooldown after a finished race
RACE_BUDGET_H=${RACE_BUDGET_H:-2}    # max races per rolling hour (B2)
RACE_BUDGET_WIN=${RACE_BUDGET_WIN:-3600}  # budget window seconds
TOP_PICK=${TOP_PICK:-2}          # finalists from stage-1 screen (v9.10: 3->2)
TIE_PCT=${TIE_PCT:-20}           # switch only if best*100 > cur*(100+TIE_PCT)
THRESH_BPS=${THRESH_BPS:-30720}  # pass line 30KB/s (v8 guard, kept)
SEVERE_BPS=${SEVERE_BPS:-15360}  # severe line 15KB/s
SPEED_MAX=${SPEED_MAX:-4}        # single throughput try cap seconds
SPEED_TRIES=${SPEED_TRIES:-2}    # throughput tries per candidate (median) (v9.10: 3->2)
TRY204=${TRY204:-3}              # 204 probes per candidate (success gate)
# v9.11: TRY204 became a DIVISOR (the LOSS share at the probe loop). A conf
# typo of TRY204=0 used to be harmless in v9.10 (only compared, never divided);
# now it would abort the whole round with "divide by zero" mid-race, which is
# strictly worse than a bad gate. Clamp it to >=1: one probe is the smallest
# meaningful gate and the loop/gate/score all stay well defined.
case "$TRY204" in ''|*[!0-9]*) TRY204=3 ;; esac
[ "$TRY204" -lt 1 ] && TRY204=1
# F24 (v9.11): how many 204 misses a seat may absorb. 0 = v9.10's all-204 rule
# (bit-identical default); raise to 1..TRY204-1 to let a near-clean node seat
# with a non-zero LOSS share recorded (mihomo confidence spirit).
LOSS_MAX=${LOSS_MAX:-0}
case "$LOSS_MAX" in ''|*[!0-9]*) LOSS_MAX=0 ;; esac
[ "$LOSS_MAX" -ge "$TRY204" ] && LOSS_MAX=$(( TRY204 - 1 ))
[ "$LOSS_MAX" -lt 0 ] && LOSS_MAX=0
CAND_204_TMO=${CAND_204_TMO:-2}
SPIKE_PCT=${SPIKE_PCT:-20}       # thr drop pct vs last round to flag spike
W_LAT=${W_LAT:-30}               # lat weight
W_THR=${W_THR:-60}               # throughput weight
W_STAB=${W_STAB:-10}             # stability weight
# F25 (v9.11): jitter weight. 0 reproduces v9.10's ranking exactly (the only
# score change is this term); 15 default keeps lat+thr dominant.
W_JIT=${W_JIT:-15}               # jitter weight (v9.11)
# v9.11: all four weights are now DIVISORS of the weighted sum, so a conf with
# every weight at 0 (or a typo that makes one non-numeric) would abort the
# score awk with "Division by zero" and leave SCORED empty - after which
# BEST_NODE is empty and the round tries to "switch" to nothing. Numeric guard
# first, then an all-zero fallback to the shipped defaults.
case "$W_LAT"  in ''|*[!0-9]*) W_LAT=30  ;; esac
case "$W_THR"  in ''|*[!0-9]*) W_THR=60  ;; esac
case "$W_STAB" in ''|*[!0-9]*) W_STAB=10 ;; esac
case "$W_JIT"  in ''|*[!0-9]*) W_JIT=15  ;; esac
if [ $(( W_LAT + W_THR + W_STAB + W_JIT )) -eq 0 ]; then
  W_LAT=30; W_THR=60; W_STAB=10; W_JIT=15
fi
# F26 (v9.11): capped-EMA constants for the PREV_BPS baseline
EMA_A=${EMA_A:-80}               # old-sample weight in percent (0.8 -> 80)
EMA_CAP=${EMA_CAP:-125}          # up-step cap in percent (1.25 -> 125)
EMA_SPIKE=${EMA_SPIKE:-300}      # sample above old*this%% is a spike, ignored
# v9.11: EMA_A doubles as a WEIGHT, so a value above 100 makes the blend
# extrapolate backwards - the new sample gets a NEGATIVE weight and a fast node
# would push the baseline DOWN, manufacturing a fake spike next round. Clamp to
# the meaningful range 0..100 (non-numeric values are re-guarded at the use site
# too, so an old conf with garbage still degrades to the default).
case "$EMA_A" in ''|*[!0-9]*) EMA_A=80 ;; esac
[ "$EMA_A" -gt 100 ] && EMA_A=100
# v9.11 r1: EMA_CAP is an UP-ONLY cap, so a value below 100 silently turns it
# into a DOWN step. Worked example (verified in the sandbox): PREV=30000 and a
# sample EQUAL to the baseline, EMA_CAP=50 -> CAP_LIM=15000, SAMPLE clipped to
# 15000, new baseline 27000. A flat node would then look 10 percent slower next
# round, i.e. the cap manufactures the very spike it was meant to suppress.
# Clamp to >=100 (100 lets a slower sample HOLD the baseline, never lift it;
# the shipped default 125 is untouched). EMA_SPIKE below 100 classes every
# ordinary sample as a spike and freezes the baseline forever, so it gets the
# same floor.
case "$EMA_CAP"   in ''|*[!0-9]*) EMA_CAP=125   ;; esac
[ "$EMA_CAP" -lt 100 ] && EMA_CAP=100
case "$EMA_SPIKE" in ''|*[!0-9]*) EMA_SPIKE=300 ;; esac
[ "$EMA_SPIKE" -lt 100 ] && EMA_SPIKE=100
# v9.11 r1: the remaining numeric knobs were guarded only implicitly (a
# non-numeric value makes [ -lt ] fail silently). That is mostly harmless, but
# four of them stop the round doing any real work while looking healthy:
# SPEED_TRIES or SPEED_MAX non-numeric/0 -> speed_med loops zero times -> every
# throughput reads 0; TOP_PICK non-numeric -> "head -2x" errors -> no finalist
# is ever raced; CAND_204_TMO 0 -> every probe times out instantly. Coerce to
# the shipped default first, then apply the floor. Values that legitimately
# mean "switch this off" (RACE_BUDGET_H=0, FAIL_TRIGGER=0, TIE_PCT=0,
# THRESH_BPS=0) are deliberately left alone.
case "$WIN_SEC"        in ''|*[!0-9]*) WIN_SEC=900      ;; esac
case "$FAIL_TRIGGER"   in ''|*[!0-9]*) FAIL_TRIGGER=2   ;; esac
case "$RACE_CD"        in ''|*[!0-9]*) RACE_CD=900      ;; esac
case "$RACE_BUDGET_H"  in ''|*[!0-9]*) RACE_BUDGET_H=2  ;; esac
case "$RACE_BUDGET_WIN" in ''|*[!0-9]*) RACE_BUDGET_WIN=3600 ;; esac
case "$TOP_PICK"       in ''|*[!0-9]*) TOP_PICK=2       ;; esac
case "$TIE_PCT"        in ''|*[!0-9]*) TIE_PCT=20       ;; esac
case "$THRESH_BPS"     in ''|*[!0-9]*) THRESH_BPS=30720 ;; esac
case "$SEVERE_BPS"     in ''|*[!0-9]*) SEVERE_BPS=15360 ;; esac
case "$SPEED_MAX"      in ''|*[!0-9]*) SPEED_MAX=4      ;; esac
case "$SPEED_TRIES"    in ''|*[!0-9]*) SPEED_TRIES=2    ;; esac
case "$CAND_204_TMO"   in ''|*[!0-9]*) CAND_204_TMO=2   ;; esac
case "$SPIKE_PCT"      in ''|*[!0-9]*) SPIKE_PCT=20     ;; esac
[ "$TOP_PICK" -lt 1 ]    && TOP_PICK=1
[ "$SPEED_TRIES" -lt 1 ] && SPEED_TRIES=1
[ "$SPEED_MAX" -lt 1 ]   && SPEED_MAX=1
[ "$CAND_204_TMO" -lt 1 ] && CAND_204_TMO=1
SPEED_URL="${SPEED_URL:-https://i.ytimg.com/vi/aqz-KE-bpKQ/maxresdefault.jpg}"
# F25 (v9.11): any row with no measurable probe span (cur, which gets a single
# S3 204 sample; or a candidate whose probes returned no time_total) is written
# as jitter=-1, the NO DATA marker. The score awk then removes the jitter term
# from BOTH numerator and denominator for that row. A small fixed "neutral"
# number cannot do that job: any span near 0 scores ~100 against a real span,
# so the row would be REWARDED for having no data. There is deliberately no
# JIT_NEUTRAL knob any more - the -1 marker replaced it; an old conf that
# still sets JIT_NEUTRAL is ignored (v9.12 F29: and now WARNed about once per
# round, so a stale conf reads as stale instead of silently doing nothing).
PROV_TYPES="${PROV_TYPES:-AnyTLS|Hysteria2|Hysteria|Trojan|Vless|Vmess|Shadowsocks|ShadowsocksR|Socks5|Http|Ssh|Tuic|WireGuard|Mieru|Snell|Sudoku|Masque|TrustTunnel|ShadowQuic|OpenVPN|Tailscale|ZeroTier|EasyTier|GostRelay}"
DRY_RUN=${NG_DRY_RUN:-0}
# V4 (v9.9): egress trace, OFF by default. NG_EGRESS=1 logs one trace
# fetch (ip=/loc=) after a settled round. Diagnostic aid only - NOT a
# gate; not yet verified on a real router. NG_TRACE_URL overrides.
NG_EGRESS=${NG_EGRESS:-0}
NG_TRACE_URL="${NG_TRACE_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
# V7 (v9.10): per-phase timing, OFF by default. NG_TIMING=1 logs the wall
# clock spent in each racing phase (S2/S3/S5/6a/6b/S7) as "t:phase=Ns" lines.
# Diagnostic aid only - nothing gates on it. Gives the first REAL distribution
# of a race round's cost, which the static ceiling (--check) cannot provide.
NG_TIMING=${NG_TIMING:-0}

# v9 paths (shadow install overrides STATE/LOG via conf)
STATE="${NG_STATE:-/root/.nodeguard.state}"
LOG="${NG_LOG:-/root/nodeguard.log}"
LOCK_DIR="${NG_LOCK:-/tmp/nodeguard_v9.lock}"   # F12: sandboxable lock (default unchanged)
OFFFILE="${NG_OFF:-/root/.nodeguard.off}"   # F10: sandboxable
log(){ echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG"; }
# F29 (v9.12): one WARN per round if the conf still carries the
# removed JIT_NEUTRAL key (parsed earlier, up in the conf section).
# Sits here, AFTER log() - a POSIX sh function must be defined
# before its first call or the WARN would die with log: not found.
if [ -n "${JIT_NEUTRAL:-}" ]; then
  log "WARN conf key JIT_NEUTRAL=[${JIT_NEUTRAL}] is deprecated (removed in v9.11: the jitter column uses the -1 NO-DATA marker) and is ignored (F29)"
fi
# V7 (v9.10): per-phase race timing. NG_TIMING=1 logs the cumulative wall
# clock at each racing phase boundary as "t:phase=Ns" (seconds since T0,
# which is set at SECTION 1). Default OFF: healthy rounds and timing-off
# rounds add no extra log lines. Diagnostic aid only - nothing gates on it.
T0=""
tlog(){ [ "$NG_TIMING" = "1" ] && [ -n "$T0" ] && log "t:$1=$(( $(date +%s) - T0 ))s"; }

# ------------------------------------------------------------
# F31 (v9.13): subscription self-heal.
# Called ONCE per round, AFTER the API answered (i.e. the core is up and
# therefore tproxy is up - the exact condition whose absence broke the boot
# fetch). Never blocks: the fetch runs detached with a hard 120s cap, so a
# stalling CDN cannot stretch the round.
# Skip rules (all cheap, all read-only):
#   - off switch: NG_SUBHEAL=0
#   - not a subscription profile -> nothing to do
#   - uci success=1 AND update within NG_SUBHEAL_OK_WIN -> healthy, skip
#   - a heal is already in flight ($SUBHEAL_LOCK present) -> skip (belt and
#     braces: cron already serialises rounds via the main lock, but a slow
#     detached fetch can outlive its round)
# Any uci read failure is treated as "unknown" and we heal - a missing
# success key is exactly the state a broken init.d leaves behind.
# Concurrency: the lock is a DIRECTORY (atomic mkdir) shared with the init.d
# side, so a boot-time refresh and a nodeguard heal can never run the same
# fetch twice. Two fetches would NOT be harmless: update_subscription stages
# into a FIXED tmpfile ($TEMP_DIR/<section>.yaml), so a second run would
# overwrite the first one's staging file mid-move.
# Staleness is judged by AGE (10min), not by PID: a SIGKILL leaves a lock with
# no owner, and pid reuse on a busy box can keep a dead pid alive. The worst
# case inside update_subscription is curl -m 120 --retry 3 per request, well
# under 10min, so age alone is a safe reclaim rule.
# ------------------------------------------------------------
SUBHEAL_LOCK="${NG_SUBHEAL_LOCK:-/var/run/nikki/sub.heal.lock}"
SUBHEAL_BACKOFF="${NG_SUBHEAL_BACKOFF:-/var/run/nikki/sub.heal.next}"
# F31c: the subscription FILE is the thing the core actually loads, so uci
# bookkeeping alone cannot prove health. update_subscription writes uci only
# AFTER a successful mv, but the file can still vanish later (manual rm, a
# failed mv on a full overlay, a truncated restore from backup). Default path
# matches SUBSCRIPTIONS_DIR in /etc/nikki/scripts/include.sh.
NG_SUB_DIR="${NG_SUB_DIR:-/etc/nikki/subscriptions}"
NG_SUBHEAL=${NG_SUBHEAL:-1}
NG_SUBHEAL_OK_WIN=${NG_SUBHEAL_OK_WIN:-21600}   # 6h
NG_SUBHEAL_STALE_MIN=${NG_SUBHEAL_STALE_MIN:-10}
NG_SUBHEAL_MIN_WAIT=${NG_SUBHEAL_MIN_WAIT:-900}    # 15min first retry
NG_SUBHEAL_MAX_WAIT=${NG_SUBHEAL_MAX_WAIT:-21600}  # cap at 6h
case "$NG_SUBHEAL_OK_WIN"    in ''|*[!0-9]*) NG_SUBHEAL_OK_WIN=21600 ;; esac
case "$NG_SUBHEAL_STALE_MIN" in ''|*[!0-9]*) NG_SUBHEAL_STALE_MIN=10 ;; esac
case "$NG_SUBHEAL_MIN_WAIT"  in ''|*[!0-9]*) NG_SUBHEAL_MIN_WAIT=900 ;; esac
case "$NG_SUBHEAL_MAX_WAIT"  in ''|*[!0-9]*) NG_SUBHEAL_MAX_WAIT=21600 ;; esac
[ "$NG_SUBHEAL_MIN_WAIT" -lt 300 ] && NG_SUBHEAL_MIN_WAIT=300
[ "$NG_SUBHEAL_MAX_WAIT" -lt "$NG_SUBHEAL_MIN_WAIT" ] && NG_SUBHEAL_MAX_WAIT=$NG_SUBHEAL_MIN_WAIT
# subheal_check: logs one line and, if needed, starts the detached refresh.
# Return value is informational only - the caller must never gate on it.
subheal_check(){
  [ "$NG_SUBHEAL" = "1" ] || return 0
  # profile must be subscription:<section>
  local sh_profile sh_type sh_id
  sh_profile=$(uci -q get nikki.config.profile 2>/dev/null) || return 0
  [ -n "$sh_profile" ] || return 0
  sh_type=$(echo "$sh_profile" | cut -d ':' -f 1)
  sh_id=$(echo "$sh_profile" | cut -d ':' -f 2)
  [ "$sh_type" = "subscription" ] || return 0
  [ -n "$sh_id" ] || return 0
  local sh_ok sh_upd sh_f
  sh_ok=$(uci -q get "nikki.$sh_id.success" 2>/dev/null)
  sh_upd=$(uci -q get "nikki.$sh_id.update" 2>/dev/null)
  sh_f="$NG_SUB_DIR/$sh_id.yaml"
  # F31c: a missing/empty subscription file is the one failure the uci marks
  # cannot see - update_subscription sets success=1 and update ONLY after the
  # mv, but a later rm/truncate leaves both marks green forever. A zero-byte
  # file is as fatal as a missing one: the core would fail to parse it.
  if [ "$sh_ok" = "1" ] && [ -n "$sh_upd" ] && [ -s "$sh_f" ]; then
    local sh_upd_ts sh_age
    sh_upd_ts=$(date -d "$sh_upd" +%s 2>/dev/null)
    case "$sh_upd_ts" in
      ''|*[!0-9]*) : ;;   # unparseable -> fall through to heal
      *) sh_age=$(( $(date +%s) - sh_upd_ts ))
         # A NEGATIVE age means the stamp is in the future (clock stepped back,
         # or a hand-edited value). Treating it as fresh would freeze the heal
         # path until the clock caught up, so a negative age heals.
         if [ "$sh_age" -ge 0 ] && [ "$sh_age" -lt "$NG_SUBHEAL_OK_WIN" ]; then
           return 0        # healthy and fresh: say nothing, do nothing
         fi ;;
    esac
  fi
  # F31c: the lock lives in a tmpfs dir the init.d creates on demand. If it is
  # NOT there, mkdir fails with ENOENT and find returns empty, so the old code
  # read that as "lock held" and skipped the heal on EVERY round - a permanent
  # silent stall. Create the parent first; if that fails, the box is in a far
  # worse state and we bail loudly rather than pretend to be locked out.
  if [ ! -d "$(dirname "$SUBHEAL_LOCK")" ]; then
    mkdir -p "$(dirname "$SUBHEAL_LOCK")" 2>/dev/null \
      || { log "ERR SUBHEAL cannot create $(dirname "$SUBHEAL_LOCK"), skip cause=NO_TMPDIR"; return 0; }
  fi
  # atomic claim; reclaim only by age
  if ! mkdir "$SUBHEAL_LOCK" 2>/dev/null; then
    if [ -n "$(find "$SUBHEAL_LOCK" -mmin +"$NG_SUBHEAL_STALE_MIN" 2>/dev/null)" ]; then
      rm -rf "$SUBHEAL_LOCK" 2>/dev/null
      mkdir "$SUBHEAL_LOCK" 2>/dev/null || { log "SUBHEAL skipped: lock reclaim failed"; return 0; }
    else
      log "SUBHEAL skipped: refresh in flight (lock held)"
      return 0
    fi
  fi
  # F31b backoff: a permanently dead CDN must not cost a 67s fetch every
  # cron tick. The backoff file holds "<next_epoch> <wait_seconds>"; the wait
  # DOUBLES per consecutive failure from 15min to a 6h cap, and success
  # removes the file. It lives in /var/run (tmpfs), so a reboot resets it by
  # design and no state line is added (the 4-line rule stays intact).
  # sh_cur is cleared first: a stale value from a previous in-process call
  # would be doubled as if it were the last recorded wait.
  sh_hold=0
  sh_cur=""
  sh_next=0
  if [ -f "$SUBHEAL_BACKOFF" ]; then
    read -r sh_next sh_cur < "$SUBHEAL_BACKOFF" 2>/dev/null
    case "${sh_next:-x}" in
      ''|*[!0-9]*) rm -f "$SUBHEAL_BACKOFF" 2>/dev/null; sh_next=0 ;;
    esac
    case "${sh_cur:-x}" in ''|*[!0-9]*) sh_cur=$NG_SUBHEAL_MIN_WAIT ;; esac
    if [ "$sh_next" -gt 0 ] && [ "$(date +%s)" -lt "$sh_next" ]; then
      sh_hold=1
    fi
  fi
  if [ "$sh_hold" = 1 ]; then
    rm -rf "$SUBHEAL_LOCK" 2>/dev/null
    log "SUBHEAL skipped: backoff ${sh_cur}s, next retry $(date -d "@$sh_next" '+%H:%M:%S' 2>/dev/null || echo "$sh_next")"
    return 0
  fi
  log "SUBHEAL subscription [$sh_id] success=[${sh_ok:-missing}] update=[${sh_upd:-none}] -> refresh in background"
  (
    trap 'rm -rf "$SUBHEAL_LOCK" 2>/dev/null' EXIT INT TERM HUP
    /etc/init.d/nikki update_subscription "$sh_id" > /dev/null 2>&1
    _s=$(uci -q get "nikki.$sh_id.success" 2>/dev/null)
    if [ "$_s" = "1" ]; then
      rm -f "$SUBHEAL_BACKOFF" 2>/dev/null
    else
      # consecutive failure: double the wait (capped)
      if [ "$sh_hold" = 0 ] && [ -n "${sh_cur:-}" ]; then
        _wait=$(( sh_cur * 2 ))
      else
        _wait=$NG_SUBHEAL_MIN_WAIT
      fi
      [ "$_wait" -lt "$NG_SUBHEAL_MIN_WAIT" ] && _wait=$NG_SUBHEAL_MIN_WAIT
      [ "$_wait" -gt "$NG_SUBHEAL_MAX_WAIT" ] && _wait=$NG_SUBHEAL_MAX_WAIT
      echo "$(( $(date +%s) + _wait )) $_wait" > "$SUBHEAL_BACKOFF" 2>/dev/null
    fi
  ) > /dev/null 2>&1 &
}
# log trim (v8.1 rule: 200KB cap). F15: keep last 400 lines instead of
# 100 - a round writes 5-15 lines, so 100 lines only covered ~10-30 rounds
# and the A1 PREV_BPS fallback (grep the previous "OK [cur]" line) could
# miss. 400 lines is ~40KB, still far under the 200KB cap.
# F16 (v9.6): the trim moved BELOW the lock (was above it) and the temp
# name carries $$. Above the lock two overlapping cron rounds could both
# run tail+mv; the mv is atomic but the loser then keeps writing into an
# already-unlinked inode, silently losing its own log lines. Inside the
# critical section there is only one writer, and $$ avoids a name clash.

# ---- helpers ----
enc(){ printf "%s" "$1" | awk 'BEGIN{for(i=0;i<256;i++)o[sprintf("%c",i)]=i}{n=length($0);for(i=1;i<=n;i++){c=substr($0,i,1);if(c~/[A-Za-z0-9._~-]/)printf"%s",c;else printf"%%%02X",o[c]}}'; }
get_now(){ curl -s -m 3 -H "$AH" "$API/proxies/$(enc "$SEL")" | tr ',' '\n' | grep -o '"now":"[^"]*"' | head -n1 | sed 's/^"now":"//; s/"$//'; }
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
# V1 (v9.9): GROUP_NOW = the group's actual landing point, assigned ONLY
# from a real get_now readback (never guessed, never persisted across runs).
# put_node uses it to skip a PUT that is provably a no-op. Empty means
# "unknown", which makes every PUT go out - the safe default.
GROUP_NOW=""
PUT_RET=""
PK_SKIP=0
put_node(){
  # Private variable names: k / N / A are live loop variables in the caller
  # (for N in $RACE_LIST, the 204 retry counters, speed_med). Because this
  # function now runs in the CALLER's shell, clobbering them would corrupt
  # the loops around every call site.
  _pn="$1"
  # V1 fast path: the group is already known to sit on the requested
  # target, so the PUT cannot change anything. The target itself is the
  # confirmed value (it IS what a readback would return).
  if [ -n "$GROUP_NOW" ] && [ "$GROUP_NOW" = "$_pn" ]; then
    PK_SKIP=$((PK_SKIP+1))
    log "PUT skip#${PK_SKIP} [$_pn] already selected, redundant PUT avoided (V1)"
    PUT_RET="$_pn"; return
  fi
  _pk=0; _pa=""
  while [ $_pk -lt 2 ]; do
    curl -s -m 5 -X PUT -H "$AH" -H "Content-Type: application/json" \
      -d "{\"name\":\"$_pn\"}" "$API/proxies/$(enc "$SEL")" >/dev/null 2>&1
    _pa=$(get_now)
    if [ "$_pa" = "$_pn" ]; then GROUP_NOW="$_pa"; PUT_RET="$_pa"; return; fi
    # A readable but different _pa is a genuine readback: record it, so a
    # later PUT back to that same node can also skip (V1). An UNREADABLE
    # _pa proves nothing about where the group is, so GROUP_NOW is CLEARED
    # (unknown): the next PUT always goes out. Skipping on a guess is
    # exactly the failure mode V1 must not introduce.
    if [ -n "$_pa" ] && now_ok "$_pa"; then GROUP_NOW="$_pa"; else GROUP_NOW=""; fi
    _pk=$((_pk+1)); sleep 1
  done
  PUT_RET="$_pa"
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
# V3 (v9.9): read-only self-check, BEFORE the lock and before any write
# ============================================================
# Trigger: NG_CHECK=1 in the environment, or a bare "--check" argv.
# Contract: touches NO lock, NO state file, NO log file, NO proxy group.
# Only GET requests are issued (plus one group-delay call with
# NG_CHECK_DEEP=1, which is still read-only on the group - the delay
# endpoint probes members without re-selecting anything, which is the
# same property SECTION 5 relies on).
# Output goes to stdout in "KEY=value" form so it can be grepped or
# pasted into a report. Exit status: 0 = all core checks passed,
# 1 = at least one core check failed (API / group type / selection).
NG_CHECK=${NG_CHECK:-0}
for a in "$@"; do [ "$a" = "--check" ] && NG_CHECK=1; done
if [ "$NG_CHECK" = "1" ]; then
  CHK_FAIL=0
  # -- core 1: version endpoint reachable (also V5) --
  CV=$(curl -s -m 5 -H "$AH" "$API/version" 2>/dev/null)
  CVN=$(printf '%s' "$CV" | tr ',' '\n' | grep -o '"version":"[^"]*"' | head -n1 | cut -d'"' -f4)
  case "$CVN" in ""|*[!-.A-Za-z0-9+]*) CVN="" ;; esac
  if [ -n "$CVN" ]; then echo "check_api=ok"; else echo "check_api=FAIL"; CHK_FAIL=1; fi
  echo "check_script=$NG_VERSION"
  echo "check_mihomo_version=${CVN:-unreadable}"
  # -- core 2: group type must be Selector (same invariant as the round) --
  CT=$(curl -s -m 5 -H "$AH" "$API/proxies/$(enc "$SEL")" 2>/dev/null | tr ',' '\n' | grep -o '"type":"[^"]*"' | head -n1 | sed 's/^"type":"//; s/"$//')
  case "$CT" in
    Selector) echo "check_group_type=Selector" ;;
    "")       echo "check_group_type=FAIL_UNREADABLE"; CHK_FAIL=1 ;;
    *)        echo "check_group_type=FAIL_${CT}_NOT_SELECTOR"; CHK_FAIL=1 ;;
  esac
  # -- core 3: readable current selection --
  CCUR=$(get_now)
  if now_ok "$CCUR"; then echo "check_selection=[$CCUR]"; else echo "check_selection=FAIL"; CHK_FAIL=1; fi
  # -- info: providers API answer, i.e. is the M5/F5 path alive? (V5) --
  CPV=$(curl -s -m 10 -H "$AH" "$API/providers/proxies" 2>/dev/null)
  if [ -n "$CPV" ]; then
    CPVN=$(printf '%s' "$CPV" | tr '{' '\n' | grep -c '"name":"')
    echo "check_providers_api=ok entries=$CPVN"
  else
    echo "check_providers_api=DOWN (round would use the M5 degraded keyword-only filter)"
  fi
  # -- info: cooldown + budget from the state file (READ ONLY, no save) --
  CFAIL=0; CTS=0; CRACE=0; CRTS=""
  if [ -f "$STATE" ]; then
    S1V=$(sed -n 1p "$STATE"); S3V=$(sed -n 3p "$STATE")
    case "$S1V" in
      v9:*) CB=${S1V#v9:}
            case "$CB" in
              *:*:*)
                CFAIL=${CB%%:*}; CT=${CB#*:}; CTS=${CT%%:*}; CRACE=${CT#*:} ;;
              *:*)  CFAIL=${CB%%:*}; CTS=${CB#*:} ;;
              *)    CFAIL=$CB ;;
            esac ;;
    esac
    case "$S3V" in RTS_LOG=*) CRTS=${S3V#RTS_LOG=} ;; esac
    case "$CFAIL" in ''|*[!0-9]*) CFAIL=0 ;; esac
    case "$CRACE" in ''|*[!0-9]*) CRACE=0 ;; esac
    case "$CTS"   in ''|*[!0-9]*) CTS=0 ;; esac
    echo "check_state_file=present"
  else
    echo "check_state_file=absent (first run would initialise it)"
  fi
  CNOW=$(date +%s)
  if [ "$CRACE" -gt 0 ] && [ $((CNOW-CRACE)) -lt "$RACE_CD" ]; then
    echo "check_cooldown_remaining=$((RACE_CD-(CNOW-CRACE)))s of ${RACE_CD}s"
  else
    echo "check_cooldown_remaining=0s (not cooling down)"
  fi
  CREC=$(printf '%s' "$CRTS" | tr ',' '\n' | awk -v now="$CNOW" -v w="$RACE_BUDGET_WIN" '$1+0>0 && now-$1<w' | grep -c .)
  echo "check_budget_used=${CREC:-0}/${RACE_BUDGET_H} in ${RACE_BUDGET_WIN}s"
  echo "check_fail_counter=$CFAIL/${FAIL_TRIGGER}"
  # -- static cost model, derived from this file's own -m constants --
  echo "check_ceiling_healthy_s=$((5+5+5+6+5+4+4))"
  echo "check_ceiling_racing_s=84 (v9.12: F30 dropped the serial /proxies refetch; parallel S5 already produced that data)"
  echo "check_lock_threshold=480s margin_vs_84s=$((480-84))s"
  # -- optional deep probe: ONE raw group-delay call --
  if [ "${NG_CHECK_DEEP:-0}" = "1" ]; then
    CDJ=$(curl -s -m 30 -H "$AH" "$API/group/$(enc "$SEL")/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000" 2>/dev/null)
    if [ -n "$CDJ" ]; then
      CDN=$(printf '%s' "$CDJ" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' | grep -c ':')
      echo "check_deep_raw_delay_entries=$CDN (RAW, unfiltered: groups/info nodes included)"
    else
      echo "check_deep_raw_delay_entries=FAIL_no_response"
    fi
  fi
  if [ "$CHK_FAIL" = "1" ]; then
    echo "check_result=FAIL"
    exit 1
  fi
  echo "check_result=ok"
  exit 0
fi

# ---- single instance lock (mkdir + stale guard > 8min) ----
# S1: the original justification put the worst-case round at ~265s
# (4.4min) > the old 4min threshold, so a slow-but-alive round could be
# stolen by the next cron tick. Neither 265s nor the 360s v9.8 figure is
# reproducible (mutually exclusive paths added); the v9.9-corrected
# racing ceiling was 281s (4.7min), still > 4min, so 8min remained
# correct with 199s of margin. v9.10 (scheme B) trims the all-timeout
# ceiling to 94s (cost_v910.py), v9.12 F30 to 84s; margin 480-84=396s,
# so 8min holds with far more headroom.
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
# F33: take the SAME flock the daily selfupdate deploy guard uses, for the
# whole round. selfupdate (/root/selfupdate.sh) runs `flock -n
# /tmp/nodeguard.single` and backs off when it is held - but until v9.14 this
# script never held it, so at 05:10 a deploy could cp a new file over the one
# the running shell was reading, producing a mixed old/new body. Opening the fd
# here makes both guards share one lock domain. If flock is not installed the
# redirect fails harmlessly (fd 9 on /dev/null) and the mkdir lock above is
# still the single-instance gate.
NG_FLOCK="${NG_FLOCK:-/tmp/nodeguard.single}"
if command -v flock >/dev/null 2>&1; then
  exec 9>>"$NG_FLOCK" 2>/dev/null
  # Not fatal on contention here: the mkdir lock above already proved we are
  # the single round, so a held flock can only mean a deploy is in flight;
  # wait for it (bounded) instead of skipping the round.
  # busybox flock has NO -w option (usage: [-sxun]), so the bounded wait is a
  # poll loop; the lock is held by this fd until the script exits.
  _fl_i=0
  while [ "$_fl_i" -lt 60 ]; do
    flock -n 9 2>/dev/null && break
    sleep 1
    _fl_i=$((_fl_i+1))
  done
  [ "$_fl_i" -ge 60 ] && log "WARN flock $NG_FLOCK still held after 60s, continuing (F33)"
else
  exec 9>/dev/null 2>/dev/null
fi
# F16: log trim runs inside the critical section (see note above).
[ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 204800 ] && tail -400 "$LOG" > "$LOG.$$.new" && mv "$LOG.$$.new" "$LOG"

# ============================================================
# SECTION 1: state (v9:FAIL:TS:RTS + LEDGER line)
# ============================================================
FAIL_N=0; LAST_TS=0; RACE_TS=0; LEDGER=""; RTS_LOG=""; PREV_BPS=0
NOW=$(date +%s)
[ "$NG_TIMING" = "1" ] && T0=$NOW
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
# V7 (v9.10): S2's version + group-type/now reads are independent local GETs,
# so they launch in parallel (ceiling 3+3=6s -> 3s). Both tightened
# -m5->-m3: 127.0.0.1 API answers in <100ms; a 3s cap only trims the all-down
# timeout. CUR (the group's landing) is parsed from the SAME response that
# yields the type, so no second read is needed.
VER_F=/tmp/ng9_ver.$$
TYP_F=/tmp/ng9_typ.$$
curl -s -m 3 -H "$AH" "$API/version" > "$VER_F" 2>/dev/null &
curl -s -m 3 -H "$AH" "$API/proxies/$(enc "$SEL")" > "$TYP_F" 2>/dev/null &
wait
VER_RESP=$(cat "$VER_F"); rm -f "$VER_F"
[ -z "$VER_RESP" ] && { log "WARN mihomo api unreachable, skip cause=API_DOWN"; exit 0; }
NG_VER=$(printf '%s' "$VER_RESP" | tr ',' '\n' | grep -o '"version":"[^"]*"' | head -n1 | cut -d'"' -f4)
case "$NG_VER" in ""|*[!-.A-Za-z0-9+]*) NG_VER=unreadable ;; esac
log "RUN $NG_VERSION mihomo=$NG_VER"
# F31 (v9.13): the core just answered on the API, so tproxy is up - this is
# the first moment a subscription fetch can leave the box proxied. Heal in
# the background (never blocks the round).
subheal_check
# F10: runtime assert - SEL must be a Selector group. If someone changes
# the group type to url-test/fallback, /group/{SEL}/delay would UNPIN it
# (route_groups.go L62-65: only non-Selector groups get ForceSet("")),
# which breaks the "no unpin side effect" invariant. Refuse + alert.
SEL_TYPE=$(tr ',' '\n' < "$TYP_F" | grep -o '"type":"[^"]*"' | head -n1 | sed 's/^"type":"//; s/"$//')
case "$SEL_TYPE" in
  Selector) : ;;
  "")      log "WARN cannot read group type, skip round cause=GROUP_TYPE"; exit 0 ;;
  *)       log "ERR group [$SEL] type is [$SEL_TYPE] not Selector; stage-1 delay would UNPIN it, REFUSE to run. Fix NG_GROUP_SEL or yaml. cause=GROUP_TYPE"; exit 0 ;;
esac
CUR=$(tr ',' '\n' < "$TYP_F" | grep -o '"now":"[^"]*"' | head -n1 | sed 's/^"now":"//; s/"$//'); rm -f "$TYP_F"
now_ok "$CUR" || { log "WARN read selector failed (bad response [$CUR]), skip cause=READ_FAIL"; exit 0; }
# V1: this get_now is a REAL readback of the group's landing point, so it
# seeds GROUP_NOW. Every later put_node to the same node can skip its PUT.
GROUP_NOW="$CUR"
[ -n "$LEDGER" ] || LEDGER="$CUR"
if [ "$LEDGER" != "$CUR" ]; then
  # S2: do NOT fall through to the PREV_BPS persist line - that
  # polluted the spike baseline with a measurement of a node nobody
  # evaluated. Sync ledger, zero the baseline, let next round re-seed.
  log "EXT external change [$LEDGER] -> [$CUR] (manual/panel/restart), ledger synced, baseline reset, no action cause=EXT_CHANGE"
  LEDGER="$CUR"; PREV_BPS=0
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
tlog S2

# ============================================================
# SECTION 3: health check (v8 logic) + spike confirm (A1)
# ============================================================
# V7 (v9.10): S3's three health probes are INDEPENDENT, so they launch in
# parallel (ceiling max(6,5,4)=6s instead of 6+5+4=15s). google + 204 are
# zero-download; speed_once is the only download and does not share the
# tunnel with them, so the parallel launch cannot skew its median. The
# F7 re-test stays serial (it depends on SUSPECT).
G_F=/tmp/ng9_g.$$
R_F=/tmp/ng9_r.$$
B_F=/tmp/ng9_b.$$
( google_check > "$G_F" ) &
( curl -s -o /dev/null -w "%{http_code}" -m 5 "https://www.gstatic.com/generate_204" > "$R_F" 2>/dev/null ) &
( speed_once > "$B_F" ) &
wait
G=$(cat "$G_F"); rm -f "$G_F"
R204=$(cat "$R_F"); rm -f "$R_F"
BEST_BPS=$(cat "$B_F"); rm -f "$B_F"
[ -z "$BEST_BPS" ] && BEST_BPS=0
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
# F8/F26 (v9.11): persist this round's observed bps as PREV_BPS for next
# round, via a capped EMA instead of v9.10's hard overwrite. A one-off burst
# can now lift the baseline by at most EMA_CAP% (default +25%) instead of
# 300%; samples beyond EMA_SPIKE% of the baseline (default 3x) are treated as
# spikes and do not touch it at all. Integer math only; case $EMA_* guards
# against garbage conf values. v9.10 behaviour (plain overwrite) is available
# by setting EMA_A=0 EMA_CAP=10000 EMA_SPIKE=1000000.
if [ "$BEST_BPS" -gt 0 ] 2>/dev/null; then
  if [ "$PREV_BPS" -gt 0 ] 2>/dev/null; then
    case "$EMA_A"    in ''|*[!0-9]*) EMA_A=80 ;; esac
    case "$EMA_CAP"  in ''|*[!0-9]*) EMA_CAP=125 ;; esac
    case "$EMA_SPIKE" in ''|*[!0-9]*) EMA_SPIKE=300 ;; esac
    SPK_LIM=$(( PREV_BPS * EMA_SPIKE / 100 ))
    if [ "$BEST_BPS" -gt "$SPK_LIM" ]; then
      log "  F26 spike ignored: sample ${BEST_BPS}B/s > ${EMA_SPIKE}% of baseline ${PREV_BPS}B/s, baseline kept"
    else
      CAP_LIM=$(( PREV_BPS * EMA_CAP / 100 ))
      SAMPLE=$BEST_BPS
      [ "$SAMPLE" -gt "$CAP_LIM" ] && { SAMPLE=$CAP_LIM; }
      PREV_BPS=$(( (PREV_BPS * EMA_A + SAMPLE * (100 - EMA_A)) / 100 ))
    fi
  else
    PREV_BPS=$BEST_BPS
  fi
fi
log "OK [$CUR] google=$GW 204=$R204 bps=$BEST_BPS fail=${FAIL_N}/${FAIL_TRIGGER} rcd=${REM}s spike=${SPIKE_FLAG}"
tlog S3

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
      log "WARN [$CUR] anomaly in cooldown but spike unconfirmed, wait cause=SPIKE_WAIT"
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW; save_state "$FAIL_N" "$NOW"; exit 0
    fi
    if [ $SEVERE -eq 1 ]; then
      log "WARN [$CUR] SEVERE breaks cooldown gate"
      REASON="severe-in-cooldown"; NEED_RACE=1
    else
      log "WARN [$CUR] mild anomaly suppressed by cooldown ${REM}s left cause=COOLDOWN_MILD"
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
        log "WARN [$CUR] mild anomaly(spike) window hit ${FAIL_N}/${FAIL_TRIGGER}, no race yet cause=MILD_WINDOW"
        save_state "$FAIL_N" "$NOW"; exit 0
      fi
    else
      FAIL_N=$((FAIL_N+1)); LAST_TS=$NOW
      if [ "$FAIL_N" -ge "$FAIL_TRIGGER" ]; then
        REASON="mild-window"; NEED_RACE=1
      else
        log "WARN [$CUR] mild anomaly window hit ${FAIL_N}/${FAIL_TRIGGER}, no race yet cause=MILD_WINDOW"
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
# V7 (v9.10): S5's three read-only GETs (group-delay / providers / proxies)
# are INDEPENDENT (no data dependency), so they launch in parallel and the
# ceiling drops from 15+15+10=40s to max(15,15,10)=15s. All three are
# zero-download API probes - none contests the tunnel bandwidth, so the
# parallel launch cannot skew a throughput median (unlike speed_once, which
# stays serial for exactly that reason). The $$ names keep concurrent cron
# rounds (if any) from colliding.
TYPE_F=/tmp/ng9_types.$$
GRP_F=/tmp/ng9_grps.$$
DLY_F=/tmp/ng9_delay.$$
TYPE_N=0
curl -s -m 15 -H "$AH" "$API/group/$SELU/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000" > "$DLY_F" 2>/dev/null &
curl -s -m 15 -H "$AH" "$API/providers/proxies" 2>/dev/null | tr '{' '\n' | awk -v t="$PROV_TYPES" '
  BEGIN { n = split(t, a, "|"); for (i=1;i<=n;i++) w[a[i]] = 1 }
  {
    n1 = index($0, "\"name\":\""); if (!n1) next
    r = substr($0, n1+8); n2 = index(r, "\""); if (!n2) next; name = substr(r, 1, n2-1)
    t1 = index($0, "\"type\":\""); if (!t1) next
    r2 = substr($0, t1+8); t2 = index(r2, "\""); if (!t2) next; typ = substr(r2, 1, t2-1)
    if (w[typ]) print name "\t" typ
  }' > "$TYPE_F" &
curl -s -m 10 -H "$AH" "$API/proxies" 2>/dev/null \
  | tr '{' '\n' | grep -o '"name":"[^"]*"' | sed 's/^"name":"//; s/"$//' \
  | sort -u > "$GRP_F" &
wait
DELAY_JSON=$(cat "$DLY_F"); rm -f "$DLY_F"
if [ -z "$DELAY_JSON" ]; then
  # F30: this early exit runs between the parallel launch and the cleanup, so
  # the other two S5 temp files (TYPE_F, GRP_F) would leak in /tmp for a day.
  rm -f "$TYPE_F" "$GRP_F"; TYPE_F=""; GRP_F=""
  log "ERR screen no response, keep [$CUR] cause=SCREEN_NORESP"; save_state "$FAIL_N" "$NOW"; exit 0
fi

# parse layer 0: last-colon split (v8 rules)
# layer 1: keyword junk filter (v8 rules, kept as defense in depth:
#          billing/info nodes share protocol types, keywords still needed)
# layer 2 (M5): keep only protocol-typed real nodes from providers API;
#          groups / DIRECT / REJECT are excluded by type, not by name guessing
TYPE_N=$(grep -c . "$TYPE_F" 2>/dev/null)
TPS_ALL=$(echo "$DELAY_JSON" | sed 's/^[{]*//; s/[}]*$//; s/"//g' | tr ',' '\n' \
  | awk -F: 'BEGIN{OFS=":"} NF>1 && $NF ~ /^[0-9]+$/ { d=$NF; NF--; print d "\t" $0 }' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '建议' -e '订阅' \
            -e '官网' -e '剩余' -e '重置' -e '到期' -e '套餐' -e '：' \
            -e '倍率' -e '勿跑' -e '过期' -e '失联' )

# F30 (v9.12): the authoritative GROUP set is the one the PARALLEL $API/proxies
# fetch above already wrote to GRP_F. v9.11 refetched it serially (-m10) right
# here, into the same variable, so the parallel result was never used: a pure
# waste of up to 10s per race round (on the router the two curls overlap, but
# the busybox-w32 sandbox serialises them, which is how the waste survived the
# v9.10 sandbox A/B unnoticed). Verified live: /proxies returns ONLY groups +
# builtins (32 entries), never provider nodes, because provider nodes do not
# register in tunnel.Proxies(). So this subtraction is exact and survives the
# providers-API-down degraded path, where the keyword blacklist alone would
# happily keep "HK Hong Kong node" and then put_node it (legal, but a nested
# delegation instead of a real node).
GRP_N=$(grep -c . "$GRP_F" 2>/dev/null)
if [ "${GRP_N:-0}" -gt 0 ] 2>/dev/null; then
  TPS_G=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' 'NR==FNR{g[$0]=1;next} NF>1 && !($2 in g)' "$GRP_F" -)
  TPS_ALL=$TPS_G
else
  log "WARN /proxies group set unreadable, group subtraction skipped (F5 degraded) cause=SCREEN_EMPTY"
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
  log "ERR screen produced nothing, keep [$CUR] cause=SCREEN_EMPTY"; save_state "$FAIL_N" "$NOW"; exit 0
fi
# S4: pool floor - a 1-2 node screen is too small to race meaningfully
# (TOP_PICK=3 can never fill, and a race over a tiny pool has a high
# chance of just re-validating the current node while burning budget).
# Keep current, log clearly, don't race. Only <1 (empty) was guarded
# before; now <3 bails too.
# NOTE (F19, v9.8: fixed by F23, not by the retracted F22 precheck): this
# floor checks POOL SIZE, not LIVE-CANDIDATE count. The pool is built from
# group-delay replies, and stage-2 still re-gates every candidate on 204 +
# google. A >=3 pool can still yield zero seats (all TOPS dead). v9.7 tried
# to catch that with a pre-race precheck; that precheck measured cur rather
# than TOPS (F22 retracted) and blocked the one case it was meant to help.
# v9.8 instead defers the budget/cooldown commit to the first real seat
# (F23), so the all-dead path simply spends nothing and retries next tick.
if [ "$screen_cnt" -lt 3 ]; then
  log "WARN screen pool too small to race ($screen_cnt nodes < 3), keep [$CUR] cause=SCREEN_SMALL"
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
tlog S5

# ---- shadow exit: measurement-without-switch would be fake ----
# NOTE (F13): DRY_RUN exits here, i.e. BEFORE the budget commit, so a
# shadow round never consumes a budget slot or arms the cooldown.
if [ "$DRY_RUN" = "1" ]; then
  log "DRY shadow: real run would switch-measure [$(printf '%s' "$TOPS" | tr '\n' ' ')] + cur, no action taken"
  save_state 0 "$NOW"; exit 0
fi

# ============================================================
# SECTION 5a: race budget + cooldown CHECK ONLY (F23)
# ============================================================
# Budget is a hard ceiling per rolling window; severe does NOT break it.
# F13 moved these writes here (out of SECTION 4) so a failed or too-small
# screen could not arm RACE_CD or burn a slot for a race that never ran.
# F23 (v9.8) moves them one step further: this section now only CHECKS,
# and the commit happens at the first real seat in SECTION 6b. A race
# that seats nobody (every TOPS member dead at the gates) costs neither
# a cooldown window nor a budget slot - the goal F19 wanted, and exactly
# what v9.7's F22 precheck failed to deliver (it probed cur, not TOPS).
# ---- F22 RETRACTED (v9.8): this section deliberately does NOT precheck ----
# The v9.7 precheck is gone, but NOT because a per-member probe is
# impossible: /providers/proxies/{provider}/{name}/healthcheck does exist
# (route/provider.go L30-38 -> getProxyDelay in proxies.go L106-148). That
# handler parses url, timeout and expected from the query string
# (proxies.go L108, L109, L116), so the provider-scoped form takes the
# same parameters as /proxies/{name}/delay. [source-verified, not probed
# on the router] What was
# broken was the call site: its curl never referenced $N, so it measured
# cur three times (see the header note). The plain /proxies/{name}/delay
# form is the only one that 404s for provider members (proxies.go L46-60).
# A correct precheck is therefore implementable but redundant after F23:
#     it would only trim the all-dead round (ceiling 281s, normally far
#     shorter; see trade-off 2, v9.9-corrected) at the price of
# a second probe path kept in sync with the stage-2 gates. Not done here.
RTS_LOG=$(printf '%s' "$RTS_LOG" | tr ',' '\n' | awk -v now="$NOW" -v w="$RACE_BUDGET_WIN" '$1+0>0 && now-$1<w' | tr '\n' ',' | sed 's/,$//')
N_RECENT=$(printf '%s' "$RTS_LOG" | awk -F, 'NF>0{n=NF} END{print n+0}')
if [ "$N_RECENT" -ge "$RACE_BUDGET_H" ]; then
  log "WARN [$CUR] race budget exhausted (${N_RECENT}/${RACE_BUDGET_H} in ${RACE_BUDGET_WIN}s), keep cur cause=BUDGET"
  save_state "$FAIL_N" "$NOW"
  exit 0
fi
# F23: nothing is written here on purpose. RTS_LOG/RACE_TS are committed
# in SECTION 6b as soon as a candidate (or cur) earns its first seat.
log "RACE start reason=$REASON cur=[$CUR] budget=$((N_RECENT+1))/${RACE_BUDGET_H} (commit deferred to first seat, F23)"

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
  # V1: CN is a real readback, so it is the truth about GROUP_NOW. Resync
  # BEFORE the restore, otherwise a stale GROUP_NOW could make put_node
  # skip the very restore this trap exists to perform.
  GROUP_NOW="$CN"
  # F2: capture the result; only claim "restored" if it really happened.
  # Old v9.1 threw the return value away and always logged "restored",
  # so a failed recovery read as success (worst case: TERM landed on a
  # candidate while it was being measured).
  put_node "$CUR"; RB="$PUT_RET"
  if [ "$RB" = "$CUR" ]; then
    log "TRAP exit mid-race: group was [$CN], restored [$CUR]"
  else
    log "ERR TRAP restore FAILED (wanted [$CUR], actual [$RB]) - group left on [$CN]!!! MANUAL CHECK REQUIRED cause=RESTORE_FAIL"
  fi
  exit 0
}
trap 'on_exit' EXIT INT TERM HUP

# ---- F23 (v9.8): commit budget slot + cooldown at the FIRST real seat ----
# SECTION 5a only checked. Nothing is spent until some node actually
# passed the 204 + google gates and produced a score row in RACE_RES:
# that is real measurement traffic, so the slot is earned there and
# nowhere earlier. An all-dead race therefore leaves RACE_TS and RTS_LOG
# untouched and the next cron tick may race again immediately.
# Idempotent by BUDGET_COMMITTED; called from both seat sites (cur in 6a,
# candidates in 6b).
BUDGET_COMMITTED=0
commit_seat(){
  [ "$BUDGET_COMMITTED" = "1" ] && return 0
  BUDGET_COMMITTED=1
  RTS_LOG="$RTS_LOG,$NOW"
  [ -z "${RTS_LOG%,*}" ] && RTS_LOG="$NOW"
  RACE_TS=$NOW
  save_state "$FAIL_N" "$NOW"
  log "  race budget committed at first seat (F23): slots=$((N_RECENT+1))/${RACE_BUDGET_H} cd=${RACE_CD}s"
}
# V4 (v9.9): egress trace, OFF by default (NG_EGRESS=1 turns it on).
# Runs once, after a SETTLED round only (keep-confirm or confirmed switch),
# so the trace reflects the node the group is actually going to stay on.
# cloudflare cdn-cgi/trace returns KEY=value lines; we keep ip= and loc=.
# -m 6 and no retry: a slow trace must never extend a settled round.
# Diagnostic aid only - nothing gates on it.
egress_trace(){
  [ "$NG_EGRESS" = "1" ] || return 0
  ET=$(curl -s -m 6 "$NG_TRACE_URL" 2>/dev/null)
  EIP=$(printf '%s\n' "$ET" | grep -m1 '^ip=' | cut -d= -f2)
  ELC=$(printf '%s\n' "$ET" | grep -m1 '^loc=' | cut -d= -f2)
  if [ -n "$EIP" ]; then
    log "  egress ip=${EIP} loc=${ELC:-unknown} (V4)"
  else
    log "  egress trace unreadable (V4 enabled, no ip= line)"
  fi
}

SAVED_IFS=$IFS
IFS='
'
: > "$RACE_RES"

# 6a) measure current node - V7 (v9.10): REUSES the S3 samples instead of
# re-probing. cur already ran 204 (R204), google (G) and one speed sample
# (BEST_BPS) in SECTION 3, so re-firing all three here would be pure waste.
# The cost: cur's 204 gate is now a single sample (R204=="204") instead of
# the TRY204-of-TRY204 triple, and its median/throughput is the S3 value
# (which F7 may have taken as the lower of two), not a fresh 2-try median.
# Stability is unknown for cur (S3 measured once) so it is recorded as 100
# (neutral: neither rewarded nor punished in the min/max ratio). This is a
# deliberate accepted precision trade-off (see doc section 17).
C_OK204=0
[ "$R204" = "204" ] && C_OK204=$TRY204
CG="$G"
[ "$TERM_SIG" = "1" ] && exit 0       # F11: TERM checkpoint before the measure
CMED=$BEST_BPS
CSTAB=100
# F24/F25 (v9.11): cur gets a single S3 204 sample, so its jitter span is NOT
# observable and is written as the NO-DATA marker -1; the score awk then drops
# the jitter term (from numerator AND denominator) for that row. That is true
# neutrality: a small fixed "neutral" value could not deliver it, because any
# number near 0 scores ~100 against a real span and would silently REWARD cur.
# The SAME -1 marker is used for a candidate whose probes return no time_total
# (see the probe loop).
# LOSS is different: it is an UNWEIGHTED column (weighting it would be
# weighting a constant - the gate already zeroes it for every seated row), and
# cur did clear its 204 sample, so 0 is its true recorded value. Only the
# jitter column carries -1 here (r1 fix: this comment used to claim both).
CLOSS=0
CJIT=-1
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
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$CUR" "$CUR_LAT" "$CMED" "$CSTAB" "$CLOSS" "$CJIT" >> "$RACE_RES"
  commit_seat
  log "  cur [$CUR] ok204=${C_OK204}/${TRY204} google=$(google_word $CG) thr=${CMED}B/s stab=${CSTAB} loss=${CLOSS} jit=${CJIT}ms lat=${CUR_LAT}ms"
else
  # V2: name the gate that actually failed, so the log distinguishes a dead
  # node (204) from a polluted exit (google) without reading the counters.
  if [ "$C_OK204" -ne "$TRY204" ]; then CUR_CAUSE=G204_FAIL; else CUR_CAUSE=GOOGLE_POLLUTED; fi
  log "  cur [$CUR] failed gates (204=${C_OK204}/${TRY204} google=$(google_word $CG)), no seat cause=$CUR_CAUSE"
fi
tlog 6a

# 6b) finalists: jump, confirm, gate, measure
RACE_LIST="$TOPS"
for N in $RACE_LIST; do
  [ "$TERM_SIG" = "1" ] && break
  [ -z "$N" ] && continue
  [ "$N" = "$CUR" ] && continue
  put_node "$N"; ACTUAL="$PUT_RET"
  if [ "$ACTUAL" != "$N" ]; then
    if [ -z "$ACTUAL" ] || ! now_ok "$ACTUAL"; then
      log "  cand [$N] switch rejected (unreadable actual [$ACTUAL]) skip cause=PUT_UNKNOWN"
    else
      log "  cand [$N] switch rejected (actual [$ACTUAL]) skip cause=PUT_REJECTED"
    fi
    continue
  fi
  # F24/F25 (v9.11): the 204 gate loop now also captures %{time_total} per
  # probe. OK204 keeps its gate role (unchanged); NEWL is the loss share the
  # seat records, and TT_MIN/TT_MAX track the time span for the jitter
  # column. The curl is the SAME request as v9.10 (one -w field added), so
  # ceiling and traffic cost are unchanged.
  OK204=0; k=1; TT_MIN=""; TT_MAX=""
  while [ $k -le "$TRY204" ]; do
    C1=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" -m "$CAND_204_TMO" "https://www.gstatic.com/generate_204" 2>/dev/null)
    C1_CODE=$(printf '%s' "$C1" | cut -d' ' -f1)
    C1_TT=$(printf '%s' "$C1" | cut -d' ' -f2)
    [ "$C1_CODE" = "204" ] && OK204=$((OK204+1))
    # v9.11 r1: the old test only checked the CHARACTER SET, so a malformed
    # value such as "1.2.3", "12.34.56", "." or ".." passed and awk then took
    # its numeric PREFIX ("1.2.3" -> 1200ms, ".." -> 0ms). A corrupt sample was
    # therefore used silently instead of dropped, and could widen or collapse
    # the span the jitter vote is built on. Reject more than one dot, and a
    # leading or trailing dot, on top of the character-set filter.
    case "$C1_TT" in
      ''|*[!0-9.]*|.*|*.|*.*.*) : ;;
      *)
        # integer ms; leading 0s preserved by printf %.0f-free math
        C1_MS=$(printf '%s' "$C1_TT" | awk '{printf "%d", $1*1000}')
        [ -z "$TT_MIN" ] && TT_MIN=$C1_MS
        [ -z "$TT_MAX" ] && TT_MAX=$C1_MS
        [ "$C1_MS" -lt "$TT_MIN" ] && TT_MIN=$C1_MS
        [ "$C1_MS" -gt "$TT_MAX" ] && TT_MAX=$C1_MS
        ;;
    esac
    k=$((k+1))
  done
  # F24: loss share of the seat, integer 0-100.
  # The gate is OK204 >= TRY204-LOSS_MAX. LOSS_MAX defaults to 0, which makes
  # that gate identical to v9.10's all-204 requirement, so LOSS is a constant 0
  # unless the operator raises LOSS_MAX in conf. That is deliberate: the column
  # is the hook mihomo's confidence idea needs, but the DEFAULT behaviour must
  # stay bit-identical to v9.10 (no silent loosening of the 204 gate).
  # e.g. TRY204=5 LOSS_MAX=1 lets 4/5 seat and records LOSS=20.
  LOSS=$(( (TRY204 - OK204) * 100 / TRY204 ))
  # F25: jitter = ms span of the probe times.
  # NO-DATA must be the SAME marker cur uses (-1), not a small "neutral"
  # number. A fixed 5ms would score (bestjit+1)*100/6 = ~350 -> capped 100
  # against any real 20ms span, i.e. a node that produced NO timing data at
  # all would win the jitter vote outright. Reachable whenever the loss gate
  # is opened (LOSS_MAX>0) and every probe still failed to report time_total.
  # -1 makes the score awk drop the jitter term from numerator AND denominator,
  # which is the only honest treatment: no data, no vote.
  if [ -n "$TT_MIN" ] && [ -n "$TT_MAX" ]; then
    JITTER=$(( TT_MAX - TT_MIN ))
  else
    JITTER=-1
  fi
  if [ $(( TRY204 - OK204 )) -gt "$LOSS_MAX" ]; then
    log "  cand [$N] 204 only ${OK204}/${TRY204} (loss ${LOSS}% > LOSS_MAX ${LOSS_MAX}%), skip cause=G204_FAIL"
    continue
  fi
  # V7 (v9.10): google (zero-download) and speed_med (the only download)
  # launch in parallel - google never contests the tunnel bandwidth, so the
  # median is unaffected. Ceiling max(6, 2*SPEED_MAX) instead of 6+2*SPEED_MAX.
  CG_F=/tmp/ng9_cg.$$
  MS_F=/tmp/ng9_ms.$$
  ( google_check > "$CG_F" ) &
  ( speed_med > "$MS_F" ) &
  wait
  CG=$(cat "$CG_F"); rm -f "$CG_F"
  if [ "$CG" = "2" ]; then
    rm -f "$MS_F"
    log "  cand [$N] google $(google_word $CG), skip cause=GOOGLE_POLLUTED"
    continue
  fi
  [ "$TERM_SIG" = "1" ] && break        # F11: TERM checkpoint before the measure
  MED_STAB=$(cat "$MS_F"); rm -f "$MS_F"
  MED=$(printf '%s\n' "$MED_STAB" | cut -f1)
  STB=$(printf '%s\n' "$MED_STAB" | cut -f2)
  LAT=$(printf '%s\n' "$TPS_ALL" | awk -F'\t' -v n="$N" '$2==n{print $1; exit}')
  [ -z "$LAT" ] && LAT=999
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$N" "$LAT" "$MED" "$STB" "$LOSS" "$JITTER" >> "$RACE_RES"
  commit_seat
  log "  cand [$N] ok204=${OK204}/${TRY204} google=$(google_word $CG) thr=${MED}B/s stab=${STB} loss=${LOSS} jit=${JITTER}ms lat=${LAT}ms"
done
IFS=$SAVED_IFS
tlog 6b

# ============================================================
# SECTION 7: stage-3 scoring (vs-best, rank-free) + gates + settle
# ============================================================
SEATS=$(grep -c . "$RACE_RES" 2>/dev/null)
if [ -z "$SEATS" ] || [ "$SEATS" -lt 1 ]; then
  # F23 (v9.8): nobody seated -> commit_seat never ran, so RACE_TS and
  # RTS_LOG are still untouched by this round. No cooldown armed, no slot
  # burned. FAIL_N is set to 1 to keep the mild counter honest (cur is
  # still in the same state), and the next round races again at once.
  put_node "$CUR"; RBF="$PUT_RET"
  LEDGER=$RBF
  log "ERR race seated nobody (all 204/google/throughput gates failed), restored [$RBF]; no slot, no cooldown (F23) - next round may retry cause=ALL_DEAD"
  save_state 1 "$NOW"
  SW_DONE=1
  exit 0
fi

# columns: name TAB lat TAB med TAB stab TAB loss TAB jitter. N2: stability
# is real now (min/max ratio of the throughput samples, 0-100). F24/F25
# (v9.11): loss is recorded per seat (always 0 while TRY204=3: the gate
# passes all-204); jitter is the ms span of the 204 probes. The WEIGHTED
# SUM uses lat/thr/stab/jit; loss stays a column only (in-pool value is
# 0 by the gate, weighting it would be weighting a constant).
# W_STAB=0 / W_JIT=0 in conf disables either vote (columns still logged).
awk -F'\t' -v wl="$W_LAT" -v wt="$W_THR" -v ws="$W_STAB" -v wj="$W_JIT" '
  BEGIN { nobest = 1; bestjit = 0 }
  NR==FNR {
    if (FNR==1 || $2+0 < bestlat+0) bestlat=$2+0
    if (FNR==1 || $3+0 > bestthr+0) bestthr=$3+0
    if (FNR==1 || $4+0 > beststab+0) beststab=$4+0
    # jit < 0 is the NO-DATA marker (cur: one S3 sample; or a candidate whose
    # probes reported no time_total). It must not become "the best span" - a -1
    # baseline would drive (bestjit+1) to 0 and zero every candidate row too.
    # Seed from the first REAL span only.
    if ($6+0 >= 0 && (nobest == 1 || $6+0 < bestjit+0)) { bestjit=$6+0; nobest=0 }
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
    # F25: jitter = ms span of the 204 probes. Lower is better.
    # Score is (bestjit+1)*100/(jit+1), NOT bestjit*100/(jit+1): with the
    # latter a legitimate 0ms span would make bestjit=0 and every score 0,
    # silently disabling the whole jitter vote.
    # jit < 0 is the NO-DATA marker (cur: one S3 sample; or a candidate whose
    # probes reported no time_total). Such a row drops the jitter term from
    # BOTH numerator and denominator, which is the only way to be truly
    # neutral - a small fixed "neutral" number would score ~100 against a real
    # span and quietly REWARD that row.
    jit = $6+0
    if (jit < 0) {
      sc_jit = 0
      wj_e   = 0
    } else {
      sc_jit = (bestjit + 1) * 100 / (jit + 1)
      if (sc_jit > 100) sc_jit = 100
      wj_e   = wj
    }
    # F27 (v9.11 r1): a row can end up with NO live vote. With wl=wt=ws=0
    # (jitter is the only enabled vote) a row carrying the -1 NO-DATA marker
    # drops wj_e to 0, so the denominator reaches 0 and awk ABORTS the whole
    # scoring pass with "Division by zero" - SCORED stays empty, BEST_NODE is
    # empty and the round is left with no verdict at all. Verified in the
    # sandbox (jitter-only weights + a jit=-1 row). -1 is a safe UNRANKABLE
    # sentinel here because a real score is always >= 0 (every sc_* term and
    # every weight is >= 0), so such a row simply sorts last.
#     den = wl + wt + ws + wj_e
#     if (den > 0) score = (wl*sc_lat + wt*sc_thr + ws*sc_stab + wj_e*sc_jit) / den
#     else         score = -1
# F28 (v9.12): also emit score3 = the same weighted sum over the votes that
# are live for EVERY row regardless of data availability (lat/thr/stab all
# are: every seated row really measured them). den3 = wl+wt+ws; if that is 0
# (jitter-only conf) score3 is the -1 sentinel and the common-vote margin
# degrades to the F27 NO_METRIC rule. Column order: score TAB name TAB lat
# TAB med TAB stab TAB loss TAB jit TAB score3.
    den = wl + wt + ws + wj_e
    if (den > 0) score = (wl*sc_lat + wt*sc_thr + ws*sc_stab + wj_e*sc_jit) / den
    else         score = -1
    den3 = wl + wt + ws
    if (den3 > 0) score3 = (wl*sc_lat + wt*sc_thr + ws*sc_stab) / den3
    else         score3 = -1
    printf "%.1f\t%s\t%s\t%s\t%s\t%s\t%s\t%.1f\n", score, $1, $2, $3, stab, $5, jit, score3
  }
' "$RACE_RES" "$RACE_RES" | sort -rn > "$SCORED"

# F28 (v9.12): the SCORE log loop now reads the 8th column too (score3).
# busybox read folds the unterminated tail into the LAST variable, so
# without the extra `s3` the score3 field would glue itself onto the jit
# field and corrupt the "jit=Nms" prefix every text assertion greps for.
log "SCORE (score/name/lat/thr/stab/loss/jit/score3):"
TABC=$(printf '\t')
while IFS="$TABC" read -r sc nm lt tb st ls jt s3; do
  log "  $nm score=$sc lat=${lt}ms thr=${tb}B/s stab=${st} loss=${ls} jit=${jt}ms s3=$s3"
done < "$SCORED"

BEST_LINE=$(head -1 "$SCORED")
BEST_SCORE=$(echo "$BEST_LINE" | cut -f1)
BEST_NODE=$(echo "$BEST_LINE" | cut -f2)
BEST_S3=$(echo "$BEST_LINE" | cut -f8)
CUR_LINE=$(awk -F'\t' -v n="$CUR" '$2==n{print; exit}' "$SCORED")
CUR_SCORE=$(echo "$CUR_LINE" | cut -f1)
CUR_S3=$(echo "$CUR_LINE" | cut -f8)
[ -z "$CUR_SCORE" ] && CUR_SCORE=0
# F27 (v9.11 r1): if even the BEST row still carries the -1 unrankable sentinel,
# every seat had no live vote (only the jitter vote is enabled and no row
# produced jitter data). There is then nothing to compare, so keep cur instead
# of letting the sort pick an arbitrary name and "switch" on a meaningless tie.
# A normal round never reaches this branch: a real score is always >= 0.
# F28 (v9.12): with W_JIT=0 the full score is never -1 (den = wl+wt+ws > 0
# after the L400 default guard), so this branch still fires exactly when the
# F27 world fires; score3's own -1 gets its own guard at the margin below.
if [ "$BEST_SCORE" = "-1.0" ]; then
  put_node "$CUR"; RBF="$PUT_RET"; LEDGER=$RBF
  log "WARN no comparable metric: every seat unrankable (only jitter weight enabled, no jitter data), keep [$CUR] restored [$RBF] cause=NO_METRIC"
  save_state "$FAIL_N" "$NOW"; SW_DONE=1; exit 0
fi
# F28 (v9.12): compare BEST vs CUR on the votes BOTH rows actually have.
# cur structurally carries jit=-1 (single S3 sample -> no observable span), so
# in the common round the full-score margin lets a full-data candidate collect
# the jitter "participation bonus" against a node that simply cannot vote.
# Rules in order:
#   0. cur did NOT seat (CUR_LINE empty: it failed the 204/google gates this
#      round, e.g. c2). v9.10/v9.11 semantics preserved: an unseated cur is
#      compared against 0 and any seated best outranks it -> rescue switch.
#      The common-lens guard below must NOT swallow this path.
#   1. cur seated WITH jitter data (a loss-gate-open round probed cur, or a
#      candidate-to-candidate handoff left a jittered cur) and BEST has it:
#      full four-vote margin (v9.11 behaviour, unchanged).
#   2. either side lacks jitter data (the common round: cur always jit=-1):
#      score3-vs-score3 margin. score3 covers lat/thr/stab only - votes every
#      seated row really measured - so the comparison is apples-to-apples.
# DECIDE prints both lenses so an operator can audit every marginal call.
CUR_JIT=$(echo "$CUR_LINE" | cut -f7)
BEST_JIT=$(echo "$BEST_LINE" | cut -f7)
CUR_JIT_HAVE=1;  case "$CUR_JIT"  in ""|*-*) CUR_JIT_HAVE=0  ;; esac
BEST_JIT_HAVE=1; case "$BEST_JIT" in ""|*-*) BEST_JIT_HAVE=0 ;; esac
if [ -z "$CUR_LINE" ]; then
  M_B="$BEST_SCORE"; M_C="0"; M_LENS=unseated
elif [ "$CUR_JIT_HAVE" = "1" ] && [ "$BEST_JIT_HAVE" = "1" ]; then
  M_B="$BEST_SCORE"; M_C="$CUR_SCORE"; M_LENS=full
else
  M_B="$BEST_S3";   M_C="$CUR_S3";   M_LENS=common
fi
log "DECIDE best=[$BEST_NODE]($BEST_SCORE/s3=$BEST_S3) cur=[$CUR]($CUR_SCORE/s3=$CUR_S3) margin-lens=$M_LENS"

# F28: guard the degenerate common-lens values BEFORE the margin math. If the
# chosen lens holds the -1 sentinel (score3 = -1 happens when W_LAT=W_THR=
# W_STAB=0 is set on purpose - a jitter-only conf - and the jitter vote is
# the only thing that could decide, exactly dmg1), keep cur: arithmetic on
# sentinels is how dmg1 shipped. Reached only with a SEATED cur, so the
# unseated rescue path above is untouched by design.
KEEP_LENS=0
case "$M_LENS" in
  common) case "$M_B$M_C" in *-*) KEEP_LENS=1 ;; esac ;;
esac
if [ "$KEEP_LENS" = "1" ]; then
  put_node "$CUR"; RBF="$PUT_RET"; LEDGER=$RBF
  log "WARN margin lens [$M_LENS] carries only sentinels (no common vote exists), keep [$CUR] restored [$RBF] cause=NO_COMMON_METRIC"
  save_state "$FAIL_N" "$NOW"; SW_DONE=1; exit 0
fi
MARGIN=$(awk -v b="$M_B" -v c="$M_C" -v p="$TIE_PCT" 'BEGIN{if(b*100>=c*(100+p))print 1;else print 0}')

KEEP=0
[ "$BEST_NODE" = "$CUR" ] && KEEP=1
[ "$MARGIN" != "1" ] && KEEP=1
if [ "$KEEP" = "1" ]; then
  put_node "$CUR"; CONFIRMED="$PUT_RET"
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
    MARGIN_PCT=$(awk -v b="$M_B" -v c="$M_C" 'BEGIN{ if(c+0<=0) c=0.1; printf "%.0f", b*100/c-100 }')
    log "OK margin ${MARGIN_PCT}% under TIE_PCT=${TIE_PCT} (lens=$M_LENS), keep [$CUR]"
  fi
  if [ "$CONFIRMED" = "$CUR" ]; then
    egress_trace
    save_state 0 "$NOW"; SW_DONE=1
    exit 0
  fi
  if [ "$BEST_NODE" = "$CUR" ]; then
    log "ERR cannot restore [$CUR] (actual [$CONFIRMED]), manual check next round cause=KEEP_REJECTED"
    save_state 1 "$NOW"; SW_DONE=1
    exit 0
  fi
  log "WARN keep-restore rejected (actual [$CONFIRMED]), fall through to switch [$BEST_NODE] cause=KEEP_REJECTED"
fi

put_node "$BEST_NODE"; CON="$PUT_RET"
LEDGER=$CON
SW_DONE=1
if [ "$CON" != "$BEST_NODE" ]; then
  put_node "$CUR"; RBF="$PUT_RET"
  LEDGER=$RBF
  log "ERR switch to [$BEST_NODE] ineffective (actual [$CON]), rolled back [$RBF] cause=SWITCH_ROLLBACK"
  save_state 1 "$NOW"
  exit 0
fi
log "ACT switch [$CUR] -> [$BEST_NODE] score ${CUR_SCORE}->${BEST_SCORE} [confirmed]"
# F26: the confirmed-switch landing node is a DIFFERENT node than the one the
# PREV_BPS baseline was built from. v9.10's overwrite made that moot, but the
# EMA now carries old-node history forward: if the new node is much faster
# (>EMA_SPIKE% of the old baseline) every sample would be classed a spike and
# the baseline could never rise. Zero it (same policy as EXT_CHANGE) so next
# round re-seeds from a real measurement of the node actually in seat.
PREV_BPS=0
egress_trace

rm -f "$RACE_RES" "$SCORED"
save_state 0 "$NOW"
exit 0
