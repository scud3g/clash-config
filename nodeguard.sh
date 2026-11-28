#!/bin/sh
# ============================================================
# nodeguard.sh v9.24 - a node name containing a TAB silently corrupted the score
#                      table and switched the group to a node it never measured
# Base: v9.23. All v9.23 (F55/F56/F56b) and earlier fixes retained.
# v9.24 changes (one defect from the F51 probe series):
#  F57 A NAME CONTAINING A RAW TAB CROSSED A TAB-DELIMITED BOUNDARY.
#      Every intermediate structure in the race is TAB separated:
#        delay pool    "<delay> TAB <name>"        (TPS_ALL)
#        TYPE_F        "<name>  TAB <type>"        (providers API)
#        RACE_RES      name TAB lat TAB bps TAB stab TAB loss TAB jit
#        SCORED        score TAB name TAB lat ...
#      so a name carrying 0x09 adds fields and every column after the name shifts
#      by one. The parser does NOT unescape JSON (it scans for "name":"..."), so
#      it accepts a raw TAB that a real mihomo body can never send (Go's
#      json.Marshal escapes 0x09 as backslash-t) - but nothing else in the chain
#      rejects one either, and the harm is not cosmetic:
#      MEASURED on the router with probe f51dbg (real race, fake curl, the TAB
#      name present in BOTH prov.json and delay.json so it is a real candidate):
#        control  name=N3      -> screen[N3 N3] score N3=99.7 DECIDE best=[N3] -> ACT [N1]->[N3]
#        tabbed   name=N3<TAB>X-> screen[N3<TAB>X N3] SCORE reads
#            "N3 score=21.9 lat=Xms thr=999B/s stab=450000 loss=100 jit=0ms s3=10.1"
#        i.e. the TAB name's row was mis-split, its FIELDS BECAME THE COLUMNS
#        (lat="X", thr=999 default, stab=450000), it scored 21.9 and the round
#        still reported "DECIDE best=[N3]" - a name assembled from the wreckage.
#        With a real deployment that is a switch decided on a corrupted score,
#        or a PUT to a name that does not exist (the F39 failure class again).
#      Fix, in four places so the boundary can never be crossed again:
#        1. now_ok(): a byte-count compare after tr -d '\001-\037\177' rejects
#           any control byte (TAB/CR/ESC/DEL) in a name. Byte count, not ${#1}:
#           ${#1} counts characters and a trailing LF would be eaten by $().
#           Verified on the router: TAB/CR/ESC rejected, CJK/emoji/space/punct,
#           "auto" and "DIRECT" all still accepted.
#        2. the delay-pool scanner drops any candidate whose NAME has a control
#           byte (awk hasctrl(), built from sprintf("%c") - [:cntrl:] in tr is
#           broken on this build, in grep it works, in awk it is not portable).
#        3. the providers/TYPE_F scanner drops such a name too, so the type
#           filter cannot re-import it.
#        4. the group set (GRP_F) is filtered with grep -v '[[:cntrl:]]', the one
#           place where the POSIX class IS supported on BusyBox v1.37.
#      A rejected name is simply not a candidate: the pool shrinks by that one
#      entry, the screen-floor and every other gate behave as before, and a
#      normal pool is bit-for-bit unchanged (measured: 4 normal nodes, 0 drops).
# ------------------------------------------------------------------------
# nodeguard.sh v9.23 - a sanitiser that sanitised nothing, and an exit code that
#                      said "all good" after the round was shot
# Base: v9.22. All v9.22 (F52/F53/F53b/F54) and earlier fixes retained.
# v9.23 changes (two defects from the robustness rounds):
#  F55 A CONTROL-BYTE SANITISER THAT WAS A COMPLETE NO-OP IN PRODUCTION.
#      F48 strips control bytes before writing state, using tr -d '[:cntrl:]'.
#      BusyBox v1.37 tr has NO character-class support: '[:cntrl:]' is parsed as
#      the literal seven-byte set [ : c n t r l ], so it deleted only those
#      characters and every real control byte survived. Proof on the router:
#        printf '[:cnrl]abc\tDEF' | tr -d '[:cntrl:]'  ->  'ab<TAB>DEF'
#      ('c' gone, TAB untouched). F48 passed on the dev box's GNU tr and did
#      nothing at all in production - the one failure mode a sanitiser must
#      never have. Fix: explicit octal span tr -d '\001-\037\177', verified on
#      the router to delete 0x01-0x1f and 0x7f while keeping 0x20-0x7f, all high
#      bytes and every UTF-8 multibyte sequence intact. DO NOT "improve" this
#      back to a character class: tr -cd '[:print:]' on this build emits an EMPTY
#      string, and tr -cd '\040-\176' would delete every CJK and emoji byte.
#  F56 A MID-RACE SIGNAL EXITED 0, INDISTINGUISHABLE FROM A NORMAL SUCCESS.
#      on_exit() was the SINGLE handler for `EXIT INT TERM HUP` and ended with a
#      literal `exit 0`. Measured on the router with probe r7j, real race, TERM
#      3s after "RACE start", 5/5 runs:
#          rc=0  midrace_line=1  restored_line=1  act=0
#      while the SAME round killed BEFORE the race (the F41 arm at the lock)
#      returns 130. So the exit-code channel reported success for a round that
#      had been shot mid-restore, and only a log grep could tell the two apart.
#      Nothing on this box consumed rc (crontab discards it, selfupdate gates on
#      `flock -n 8` not on nodeguard's status, no init.d wrapper), so nothing was
#      broken yet - but the code was a booby trap for the next consumer and made
#      any wrapper's health math wrong. Fix: the signal arms record 128+N in
#      OE_RC (the POSIX convention the pre-race arm already used) and exit
#      through the EXIT arm; on_exit() carries OE_RC out instead of a hardcoded
#      0, so a normal end still returns whatever the body returned. on_exit is
#      now RE-ENTRY GUARDED (OE_RUN), because exiting inside a signal arm re-runs
#      the EXIT trap in ash: without the guard the restore would run twice, which
#      is ~13s of extra traffic on a round already told to stop. Verified on the
#      router: INT/TERM/HUP -> 130/143/129, three-TERM storm -> 143 with the
#      restore performed exactly once, normal round -> 0 and the lock/scratch
#      cleanup unchanged.
# ------------------------------------------------------------------------
# nodeguard.sh v9.21 - a numeric value with a leading zero is read as octal
# Base: v9.20 (2341 lines). All v9.20 (F41/F42) and earlier fixes retained.
# v9.21 changes (two defects found by the tenth and thirteenth robustness rounds):
#  F43 A LEADING ZERO TURNED A NUMBER INTO OCTAL AND KILLED THE ROUND.
#      Every numeric knob and state field is validated with
#        case "$V" in ''|*[!0-9]*) V=<default> ;; esac
#      which tests only the CHARACTER SET, so "08", "09", "010" all pass.
#      POSIX arithmetic then reads a leading 0 as octal, and 8/9 are not octal
#      digits: $((08+1)) is a FATAL "arithmetic syntax error" and busybox ash
#      ABORTS THE WHOLE SCRIPT at that line. Under cron stderr is discarded, so
#      the round dies silently with no log line saying why. A leading-zero value
#      that IS valid octal ("010", "0125") is the quieter half of the same bug:
#      it is silently read as 8 / 85, so the guard keeps running on a wrong
#      number - e.g. PREV_BPS=0100000 becomes 32768 and the F26 spike rule then
#      rejects every honest sample, re-creating the F34 ratchet permanently.
#      Every input is reachable without malice: a state file restored from a
#      backup, hand-edited while debugging, produced by an older tool, a conf
#      knob typed as "08" by someone copying a padded value (dates, sizes,
#      zero-padded counters), or a forged "bps=080000" in the log fallback.
#      Measured in sandbox probes p46/p47 against v9.20 (real rounds, fake curl):
#        FAIL_N=08 + one mild hit   -> rc=2, log stops right after the OK line
#        FAIL_N=8  (control)        -> rc=0, full 14-line round
#        RACE_TS=08 (healthy round) -> rc=2, not even a second log line
#        RACE_TS=08 (severe round)  -> rc=2
#        PREV_BPS=0100000           -> rc=0 but baseline read as octal 32768:
#                                      "F26 spike ignored ... 300% of baseline
#                                      0100000B/s", baseline stuck forever
#        --check with RACE_TS=08    -> rc=2, "arithmetic syntax error" on stderr
#        TRY204=08 (conf)           -> rc=0 but "TRAP exit mid-race: group was
#                                      [N3], restored [N1]" - i.e. the round
#                                      crashed mid-race and was only cleaned up
#                                      by the EXIT trap
#        RACE_CD=08 / THRESH_BPS=030000 / TOP_PICK=02 / SPEED_TRIES=08
#                                   -> rc=0, silently misread as octal
#      Fix: nn() / nnall() strip leading zeros from an ALREADY-NUMERIC value, in
#      place, with no fork (eval on a literal variable name at each call site).
#      Non-numeric values are left untouched for the case guards, so every call
#      site sits AFTER its guard and BEFORE the first $(( )) or [ -lt ] that
#      touches the value. "0" is preserved (the loop needs two characters).
#      Call sites: conf knob guards (knobs + weights + SUBHEAL), SECTION 1 state
#      fields, spk_read()'s "N:TS", the --check state parser, and the log
#      fallback for PREV_BPS. The RTS_LOG budget counter needs no change: its
#      awk test is `$1+0>0`, and +0 forces a decimal read.
#      Note: [ -gt ] / [ -lt ] compare DECIMALLY, so a clamp such as
#      "EMA_CAP -lt 100" does NOT see the octal problem - the damage shows up
#      only where the value reaches $(( )). That is why nnall sits after each
#      guard block rather than relying on the clamps.
#  F47 THE COST MODEL AND THE LOCK THRESHOLD WERE FROZEN LITERALS, SO BOTH
#      INSTRUMENTS LIE AS SOON AS A PROBE KNOB IS RAISED - AND THE GUARD CAN
#      RUN TWO ROUNDS AT ONCE.
#      Two symptoms, one cause. Everything below is measured in the sandbox
#      (pbigcost.sh real wall clock, psteal.sh real lock theft):
#      (a) --check printed the round ceiling as the literal
#            check_ceiling_healthy_s=$((5+5+5+6+5+4+4))   = 34
#            check_ceiling_racing_s=84
#            check_lock_threshold=480s margin_vs_84s=396s
#          but SPEED_MAX / SPEED_TRIES / TRY204 / CAND_204_TMO / TOP_PICK are
#          all conf-tunable and each of them lengthens the round. Measured wall
#          clock on a conf of 30/20/20/20/10 with fake-curl latency injected:
#            slp=1  -> 66s   (reported 84)    ok
#            slp=2  -> 106s  (reported 84)    already past the report
#            slp=3  -> 189s  (reported 84)    2.3x the report
#          So the number an operator reads to decide "is my lock threshold big
#          enough" is unrelated to the round that will actually run. --check
#          exists to answer exactly that question.
#      (b) The stale-lock reclaim is `find "$LOCK_DIR" -mmin +8`, a hard 480s.
#          With the defaults the true ceiling is 84s, so 480s is generous. With
#          a tuned conf the ceiling reaches 189s (measured) and beyond; the
#          margin collapses and then inverts. psteal.sh shows the consequence
#          with the REAL script: start a long round A (max knobs, slp=6), then
#          move the lock directory's mtime back 9 minutes and start round B.
#          B reclaims the lock as "stale" while A is still working, and both
#          rounds run: two "RUN v9.21" banners, two "RACE start", two
#          "ACT switch [N1] -> [N3]" against ONE state file. That is double
#          traffic, a doubled budget/cooldown write, and a state race - the
#          single-instance lock is exactly what must never fail.
#      Fix: one function, ng_ceiling(), derives the healthy/racing ceilings from
#      the knobs actually in force, using the formulas verified in
#      cost_v910.py, and is NORMALISED AGAINST THE SHIPPED DEFAULTS:
#          racing = 84 + max(0, model(knobs) - model(defaults))
#      A smaller-than-default knob therefore cannot report a ceiling below the
#      documented 84s baseline, and the shipped defaults give delta=0, so the
#      default output is IDENTICAL to every earlier version ("84", "34").
#      --check prints the derived numbers, the derived lock threshold and the
#      real margin; the reclaim uses -mmin +ceil(lock_s/60) with
#      lock_s = max(480, ceiling*3), floored at 8 minutes (so the default path
#      is unchanged: 84*3=252 < 480 -> 480s -> 8 min) and capped at 1440 min so a
#      maximal knob set cannot push the threshold into absurdity.
# ------------------------------------------------------------------------
# nodeguard.sh v9.20 - a signal handler that did not exit, and a globbing word list
# Base: v9.19 (2312 lines). All v9.19 (F39/F40) and earlier fixes retained.
# v9.20 changes (two defects found by the ninth robustness round):
#  F41 A TERM BEFORE THE RACE LEFT THE ROUND RUNNING WITH NO LOCK. The
#      single-instance trap installed right after the mkdir lock was
#        trap 'rmdir "$LOCK_DIR"' EXIT INT TERM HUP
#      For INT/TERM/HUP it removed the lock and then RETURNED to the interrupted
#      command instead of exiting, so the round carried on through S3/S4/S5 (and
#      could issue a PUT) while the single-instance gate was already gone - the
#      next cron tick then starts a second round beside the first, which is the
#      exact double-round the mkdir lock exists to prevent.
#      Sandbox proof (dyn/p41.sh, real trap form): after `kill -TERM`,
#      "still executing after TERM" + "LOCK GONE (round continues unlocked)".
#      Fix: the INT/TERM/HUP arm exits (130) after the rmdir; EXIT stays a bare
#      rmdir for every normal path, and SECTION 6's later on_exit trap replaces
#      both arms once the race section begins (on_exit restores then exits).
#  F42 THE FINALIST LOOP GLOBBED NODE NAMES. `for N in $RACE_LIST` is an
#      UNQUOTED word list, so the shell applies PATHNAME EXPANSION to each word.
#      IFS=newline stops field splitting on spaces but NOT globbing. A name
#      containing '*' or a bracket expression gets replaced by the files that
#      match it in the current directory (a crontab round runs with cwd=/).
#      Sandbox proof (dyn/p41.sh, busybox ash): with files HK1V1 and N3 in cwd,
#      the list "HK*V1\nN3" produced the word HK1V1 instead of HK*V1, and a bare
#      "*" expanded into one word per file - extra phantom candidates plus the
#      real node silently dropped from the race. Same name-assumption class as
#      F38/F39.
#      Fix: `set -f` around the race section (globbing off, newline splitting
#      unchanged), restored with IFS after the loop.
# ------------------------------------------------------------------------
# nodeguard.sh v9.19 - two name/clock assumptions that silently disabled the guard
# Base: v9.18 (2184 lines). All v9.18 (F38) and earlier fixes retained.
# v9.19 changes (two defects found by the eighth robustness round):
#  F39 THE API BODY WAS SPLIT ON EVERY COMMA, SO A NODE NAME CONTAINING A COMMA
#      MADE EVERY ROUND DIE AT READ_FAIL. Three parse sites used
#      `tr ',' '\n'` (or `sed 's/"//g' | tr ',' '\n'`) to turn the JSON body
#      into lines before grepping a field. A comma inside a name -
#      "JP-01,HK-02", "HK,JP relay", "1,2x rate" - tore that name in half:
#        * get_now() and the SECTION 2 CUR read returned the truncated head, so
#          now_ok()/the ledger disagreed with the group's real landing and the
#          round exited cause=READ_FAIL with nothing measured. Same self-heal
#          failure mode as F38: the name never changes on its own, so the
#          monitor stays dead and the operator sees only a quiet log.
#        * the SECTION 5 delay pool additionally produced a PHANTOM node from
#          the tail half, i.e. a name that does not exist, and racing it would
#          PUT a nonexistent name.
#      Sandbox proof (dyn.sh D37, real body + fake curl, v9.18): node name
#      "JP-01,HK-02" -> "WARN read selector failed (bad response [JP-01])" ->
#      cause=READ_FAIL, 0 pass / 2 fail. The same D37 on v9.19 is green.
#      Fix: never split on commas. Fields are extracted with a single
#      `grep -o '"now":"[^"]*"'` / `'"type":"[^"]*"'` scan over the WHOLE body
#      (grep -o does not care about line length, so the tr was never needed),
#      and the delay pool is parsed by matching `[",]"[^"\\]*":[0-9]+` pairs,
#      which crosses commas inside a name and still rejects null/nested junk
#      because the value must be all digits. Verified on the router: whole-body
#      grep returns "now":"JP-01,HK-02" intact while the tr-split form returns
#      nothing; comma / colon / space+bracket+rate-tag names all parse.
#      Unchanged: a name carrying a raw double quote or backslash is still
#      rejected by now_ok's blacklist (it cannot be encoded safely), and
#      D38/D39 confirm tag-style names and colon-bearing state self-heal as
#      before.
#  F40 A SPIKE STREAK STAMPED IN THE FUTURE WAS TRUSTED FOREVER. spk_read()
#      expired a streak only when `NOW - ts > SPK_TTL`. A stamp in the future
#      gives a NEGATIVE age, which is never greater than the TTL, so the streak
#      survived indefinitely - a clock step, an NTP jump or a hand-written file
#      could hand an unrelated round a half-earned streak, and EMA_UNSTICK=3
#      would then re-seed the baseline from one burst (the mirror image of the
#      F26/F34 ratchet).
#      Sandbox proof (dyn.sh D40, v9.18): spk="2:9999999999" was consumed and
#      rewritten ("got 0:... want empty"), i.e. retained rather than dropped.
#      Fix: an age below zero is unverifiable, so the streak is dropped - the
#      same rule SUBHEAL already applies to a future-dated subscription stamp
#      (L877-882: a negative age heals). Verified: D40 is green, and the F35
#      suite (stale / legacy / carry cases) is unchanged.
# ------------------------------------------------------------------------
# nodeguard.sh v9.18 - a name-length assumption that silently stopped the monitor
# Base: v9.17 (2114 lines). All v9.17 (F36/F37) and earlier fixes retained.
# v9.18 changes (one defect found by the seventh robustness round):
#  F38 now_ok() REJECTED ANY NAME OVER 96 BYTES - THE WHOLE ROUND THEN DIED.
#     now_ok() is the readback sanity gate: SECTION 2 refuses to run when the
#     group's current selection fails it (READ_FAIL), put_node distrusts the
#     readback when it fails it, and on_exit gives up on the restore when it
#     fails it. The 96 limit was written when node names were assumed ASCII,
#     and the P1 reasoning behind it is about rejecting a multi-KB HTML error
#     page - 96 was never a safety requirement, just a number that felt
#     generous.
#     It is not generous on a real subscription: CJK and emoji are 3-4 bytes
#     each, so 30 CJK chars = 90 bytes and 31 = 97. Measured live (namelen.sh,
#     real config): /proxies 32 entries max 24 bytes, /providers/proxies 174
#     entries max 48 bytes (longest was a Chinese "update the app" hint node).
#     So today's cap has only a 2x margin, and nothing stops a rename (airport
#     rate tags, campaign suffixes, emoji badge stacks) from crossing it.
#     Sandbox proof (dyn/t_name96.sh, real script body, fake curl):
#       bytes=94  -> ran normally, "OK [LONG...]"
#       bytes=97  -> "WARN read selector failed ... cause=READ_FAIL" + exit 0
#       bytes=100 -> same
#       bytes=106 -> same
#     i.e. from the first 97-byte name onward EVERY round exits at SECTION 2
#     before measuring anything. Nothing self-heals: the name does not change
#     on its own, and the fail counter is not even bumped, so the operator sees
#     a perfectly quiet log and a node that is never switched away from. One
#     sibling failure shares the root cause and was proven in the same run:
#     on_exit could not restore (the `now_ok "$CN" || exit 0` guard), so a TERM
#     mid-race left the group on a half-tested candidate - the exact situation
#     on_exit exists to prevent.
#     RETRACTION: an earlier draft of this note also claimed that a >96-byte
#     CANDIDATE would be misjudged as "switch rejected (unreadable actual ...
#     cause=PUT_UNKNOWN)" and could never be raced. That claim is NOT true and
#     is withdrawn here. put_node() returns before now_ok() whenever the
#     readback already equals the requested name (the `_pa = _pn` early
#     return), so a long candidate seats normally. Direct evidence: the same
#     N06 scenario also PASSES on unpatched v9.17. Only the two sites listed
#     above (SECTION 2 READ_FAIL and the on_exit guard) were ever broken.
#     Fix: raise the cap to 256 bytes (5x the measured live max) and demote it
#     in the comment to what it really is - a sanity bound. The real garbage
#     filter is the character blacklist below it, which every HTML page fails
#     on its own because HTML contains '<'. A very long error page is rejected
#     by the length test, a short one by the blacklist.
#     Verified (dyn/t_names.sh, N01-N08): v9.18 scores 20 pass / 0 fail. The
#     identical suite against v9.17 scores 13 pass / 8 fail, and every failure
#     lands in N02/N03/N04 (READ_FAIL, no bps) or N07 (trap never fired, core
#     not restored) - so the suite separates the fix from the baseline instead
#     of merely proving itself.
#     Failure direction: a loose cap lets a long-but-real name through, which
#     is correct; the blacklist still rejects anything that could poison enc().
# ------------------------------------------------------------------------
# nodeguard.sh v9.17 - a detached refresh that is actually detached
# Base: v9.16 (2057 lines). All v9.16 (F35) and earlier fixes retained.
# v9.17 changes (two defects found by the sixth robustness round, both in the
# F31 subscription self-heal that v9.13 added):
#  F36 THE "BACKGROUND" REFRESH WAS NOT BACKGROUND - IT BLOCKED THE ROUND.
#     subheal_check ends with `( ... ) > /dev/null 2>&1 &`. That is a JOB OF THE
#     ROUND'S SHELL, so every later bare `wait` in the same round catches it:
#     S3 line 1264, S5 line 1480, S6 line 1825. The F31 design note promises
#     "never blocks the round: the refresh is backgrounded, the round goes on to
#     screen/race immediately" - the code did the opposite.
#     Measured (busybox ash 1.37.0, child replaced by `sleep 8`, real
#     subheal_check body): round wall time 8.000s for an 8s child, i.e. the
#     round waited exactly as long as the fetch. In production the fetch is
#     capped at 120s + retry 3, so a dead CDN - the exact scenario F31b exists
#     for - could add up to ~67s to a round whose whole budget is 84s.
#     Fix: double fork. `( ( ... ) & )` puts the refresh in a grandchild that is
#     not a job of the round's shell, so `wait` returns at once.
#     Verified: same harness -> round wall 0s with an 8s child; grandchild still
#     runs to completion (marker file written).
#  F37 THE DETACHED CHILD INHERITED FD 9, THE F33 DEPLOY LOCK.
#     F33 makes the round hold flock on /tmp/nodeguard.single for its whole
#     life. The refresh subshell forked AFTER that, so it inherited the locked
#     descriptor. On the paths that leave early (GROUP_TYPE at 1214/1215,
#     READ_FAIL at 1218) the round returns before any `wait`, the trap drops the
#     mkdir lock, and the still-running orphan keeps the flock: the deploy lock
#     then belongs to a process nobody is tracking, and the 05:10 selfupdate
#     backs off against a round that has already finished.
#     Measured (real subheal_check body, early-exit path, 8s child): after the
#     round exits, `flock -n` reports HELD, holders = the wrapper shell and its
#     sleep. It goes FREE only when the child finishes. Thus F36 alone would
#     have left this live: before the fix the blocking `wait` masked it on the
#     normal path and made it impossible to observe.
#     Fix: `exec 9>&-` as the first command of the refresh subshell, and the
#     same guard on every other background child in the round (S2, S3, S5, S6).
#     Verified: same harness -> FREE immediately after the early exit, while the
#     child is still alive.
#     Note: those other children are reaped by their own `wait` and so cannot
#     outlive a normal round; the guard is added because a round killed by TERM
#     between launch and wait would orphan them for up to their curl -m cap, and
#     the cost is one dup2 in a forked child.
# ------------------------------------------------------------------------
# nodeguard.sh v9.16 - make the unstick streak genuinely consecutive
# Base: v9.15 (1976 lines). All v9.15 (F34) and earlier fixes retained.
# v9.16 changes (one defect found by the sixth robustness round):
#  F35 THE F34 STREAK SURVIVED ROUNDS THAT PRODUCED NO SAMPLE. F34 counts
#     "consecutive rejections" in /var/run/nodeguard.spk so that a one-off
#     burst cannot move the baseline. But the counter was only written inside
#     the EMA block, which is guarded by `[ "$BEST_BPS" -gt 0 ]`, and several
#     round paths return before the EMA block runs at all (API_DOWN,
#     GROUP_TYPE, READ_FAIL, EXT_CHANGE, precheck/screen early exits). On
#     those rounds the file kept its old value, so the streak was not
#     consecutive - it was "however many rejections ever happened".
#     Measured (sandbox, 2026-11-27, baseline pinned at 16000):
#       streak=2 -> one round with a dead SPEED_URL (BEST_BPS=0, no write)
#       -> ONE high sample -> F34 fired and re-seeded the baseline to
#       467696699B/s. With 3 real bursts (CASE B) the result was identical,
#       i.e. the extra 2 rejections were never actually observed.
#     Consequence: a single burst after any skip could plant an absurd
#     baseline, and every later honest sample would then sit far below it
#     (the mirror image of F26's ratchet).
#     Fix: consume-at-start. The streak is read ONCE and immediately zeroed,
#     right after the single-instance lock is held. A round leaves a nonzero
#     streak behind only if it actually reached the EMA block (the only writer
#     of a nonzero value), so every early exit breaks the chain by
#     construction. A TTL alone was rejected: cron fires every 300s, so a
#     skipped round inside any TTL wide enough to be useful stays invisible.
#     The file still carries a TS as a second guard, and legacy bare-number
#     files (v9.15) are dropped as unverifiable.
#     Verified: same sandbox - CASE A now stays at 16000 after the single
#     burst; CASE B (3 consecutive bursts) still re-seeds on the 3rd; CASE C
#     (single burst, clean streak) still only counts 1/3.
# ------------------------------------------------------------------------
# nodeguard.sh v9.15 - unstick the spike baseline (F34)
# Base: v9.14 (1873 lines). All v9.14 (F32/F33) and earlier fixes retained.
# v9.15 changes (one defect found by the fifth robustness round):
#  F34 THE SPIKE BASELINE COULD RATCHET AND NEVER RECOVER. F26 (v9.11) treats
#     any sample above EMA_SPIKE% (default 300%) of PREV_BPS as a one-off burst
#     and refuses to move the baseline. That is correct while the baseline is
#     roughly right, and fatal once it is too low: every honest sample is then
#     "a burst", so the baseline can never climb. Two ways in were measured on
#     the live router (2026-11-27):
#       (a) DOWN DRIFT. EMA_CAP capped an UP step at +25% but nothing capped a
#           DOWN step, so a run of low samples walked PREV_BPS down without
#           limit. Measured: PREV_BPS=16393 while the node's 5MB throughput was
#           180-360KB/s and the 108KB probe read 46-122KB/s (3x the baseline was
#           49KB, so EVERY sample was rejected). 196 F26 rejections in the log,
#           baseline never moved once.
#       (b) the effect. SPIKE_FLAG compares the live sample against that tiny
#           bar, so a real deceleration of a healthy node is classified "spike
#           not confirmed" and the switch is suppressed (COOLDOWN_MILD /
#           SPIKE_WAIT). The guard stays parked on a node it should leave.
#     Fix (two parts, both additive to F26 - no gate or scoring change):
#       F34  streak escape: consecutive rejections are counted in
#            /var/run/nodeguard.spk (tmpfs, NOT a 5th state line - state stays
#            4 lines). After EMA_UNSTICK (default 3) in a row the sample is
#            accepted as the new baseline, which proves the old value was a
#            floor, not a level. A single burst still cannot move it.
#       F34b clean handover: the streak is zeroed on EXT_CHANGE and on a
#            confirmed switch, i.e. the two places that already zero PREV_BPS.
#     Rejected during development: a symmetric DOWN cap on the EMA step. It
#     looked like the obvious companion fix, but measurement showed it delays a
#     genuine deceleration ~5x (200000->16000 takes 11 rounds unclamped, 63
#     clamped) and the streak escape already covers the real failure, so it was
#     removed rather than shipped as dead weight.
#     Verified: sandbox replay of the measured state (baseline pinned at 16000,
#     high samples) - v9.14 keeps the baseline at 16000 for every round; v9.15
#     re-seeds it on the 3rd consecutive rejection and thereafter tracks samples
#     normally. Live regression: see section 21.F.
# ------------------------------------------------------------------------
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

# F43 (v9.21): A NUMERIC VALUE WITH A LEADING ZERO IS READ AS OCTAL.
# Every numeric knob and state field is validated with
#   case "$V" in ''|*[!0-9]*) V=<default> ;; esac
# which only tests the CHARACTER SET, so "08", "09" and "010" all pass. POSIX
# arithmetic $(( )) then reads a leading 0 as octal, and 8/9 are not octal
# digits: $((08+1)) is a FATAL "arithmetic syntax error" and busybox ash aborts
# the whole script at that line. Under cron stderr is discarded, so the round
# dies silently with no log line explaining why. A leading-zero value that IS
# valid octal ("010") is worse in the other direction - it is silently read as
# 8 instead of 10, so the guard keeps running on a wrong number.
# Every one of these inputs is reachable without malice: a state file restored
# from a backup, hand-edited while debugging, produced by an earlier tool, or a
# conf knob typed as "08" by someone copying a padded value.
# Measured in sandbox probes p46/p47 against v9.20 (all real rounds, fake curl):
#   FAIL_N=08 + one mild hit   -> rc=2, log stops after the OK line
#   RACE_TS=08 (healthy round) -> rc=2, no log line after RUN at all
#   PREV_BPS=0100000           -> rc=0 but baseline read as octal 32768: the
#                                 EMA never moves and F26 rejects every sample
#   --check with RACE_TS=08    -> rc=2, "arithmetic syntax error" on stderr
# nn() strips leading zeros from an ALREADY-NUMERIC value, in place, with no
# fork (eval on a literal variable name at every call site). Non-numeric values
# are left untouched for the case guards, so it must be called AFTER them.
# "0" is preserved (the loop needs at least two characters to strip).
nn(){
  eval "_nv=\${$1}" 2>/dev/null
  case "$_nv" in ''|*[!0-9]*) return 0 ;; esac
  _nz=$_nv
  while :; do case "$_nz" in 0?*) _nz=${_nz#0} ;; *) break ;; esac; done
  [ "$_nz" = "$_nv" ] || eval "$1=\$_nz" 2>/dev/null
  return 0
}
nnall(){
  for _k in "$@"; do nn "$_k"; done
}

# F45 (v9.21): A NUMBER ABOVE THE SHELL'S INTEGER RANGE SILENTLY DISARMS EVERY
# CLAMP, FLOOR AND GATE - AND CAN MAKE THE GUARD UNSWITCHABLE.
# The character-set guards above accept any digit string of any length, and a
# leading-zero strip only shortens it. busybox ash stores integers in 64 bits,
# so a value >= 2^63 is OUT OF RANGE, and every comparison against it fails in
# the most dangerous possible direction: it prints "sh: N: out of range" on
# stderr (which cron throws away) and returns FALSE. So
#   [ 99999999999999999999 -gt 30720 ] -> false
#   [ 99999999999999999999 -gt 0 ]     -> false
# i.e. every "is this value too big / non-zero" test says NO, all floors and
# clamps do nothing, and the value then reaches $(( )) where it wraps to a
# NEGATIVE number or garbage. Reachable without malice: a corrupted state file,
# a restored backup from another tool, a copy-paste of a 20-digit number, a
# 19-digit epoch from a clock glitch, or a hand-edited conf.
# Measured in sandbox probe p45d (busybox 1.36 sh):
#   [ 9223372036854775807 -gt 0 ] -> true   (2^63-1 is the last valid value)
#   [ 9223372036854775808 -gt 0 ] -> false  + "out of range" on stderr
#   [ 99999999999999999999 -gt 0 ] -> false + "out of range" on stderr
#   $(( 9999999999999999999 * 1 )) -> -8446744073709551617   (wrapped negative)
# Three REAL harms measured on v9.21 with probe pover.sh:
#   TOP_PICK=99999999999999999999 -> "screen TOP99999999999999999999:" (empty)
#     and then NO seat and NO ACT switch for the whole round: the guard can never
#     switch again. Cause: `head -N` rejects the number ("head: invalid number")
#     and TOPS comes out empty. Control run with TOP_PICK=2 switches normally.
#   EMA_A=99999999999999999999    -> PREV_BPS persisted as -40075284104017732:
#     the baseline goes NEGATIVE, which silently disables the F26/F34 spike rule
#     (every test against a negative baseline fails) and corrupts the next round.
#   TRY204=99999999999999999999   -> "cur [N1] failed gates (204=999.../999...)"
#     and FAIL_N accounting goes wrong: cur is judged failed forever.
# Also measured: `head -4294967295` is the last accepted -N (4294967296 fails),
# so TOP_PICK additionally needs a much tighter ceiling than the 64-bit one.
# Fix: nr() = strip leading zeros, then reject anything whose digit LENGTH
# exceeds the maximum this knob can legitimately have, or whose value exceeds an
# optional hard ceiling, and put the shipped default back. A rejected value is
# reset to the DEFAULT (not clamped to the ceiling) on purpose: an absurd value
# is evidence of corruption, so the safe answer is the known-good behaviour, not
# a guess at what the operator "meant" by 1e20.
# Length is tested with ${#var}, which is pure string length - it never goes
# through integer conversion, so it cannot itself trip the out-of-range trap.
# nr() is a NO-OP for a value already inside the window, so it can be applied
# unconditionally and costs no fork (eval on a literal name).
nr(){
  nn "$1"
  eval "_nv=\"\${$1}\"" 2>/dev/null
  case "$_nv" in
    ''|*[!0-9]*) eval "$1=\"\$3\"" 2>/dev/null; return 0 ;;
  esac
  if [ ${#_nv} -gt "${2:-9}" ]; then eval "$1=\"\$3\"" 2>/dev/null; return 0; fi
  if [ -n "${4:-}" ] && [ "$_nv" -gt "$4" ]; then eval "$1=\"\$3\"" 2>/dev/null; return 0; fi
  return 0
}
# nrall cannot carry a per-knob window in one flat list, so call sites use nr
# directly with an explicit (maxlen, default [, ceiling]) triple.

# V6 (v9.9): single version constant - the per-round log prints this.
# (v9.6 F14 shipped logging "v9.3": a literal at the log site is how
# that happens. The mihomo version keeps its own name NG_VER.)
NG_VERSION=v9.24

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
# F43: strip leading zeros BEFORE the first $(( )) that touches TRY204 - the
# clamp two lines down already divides/uses it arithmetically, so "08" would
# abort the round here rather than later.
nn TRY204
# F45: TRY204 is a DIVISOR *and* a gate. An out-of-range value makes every
# comparison against it false, so the LOSS gate fails OPEN (loss is never
# "> LOSS_MAX") and the score maths runs on garbage. Cap at 3 digits (999
# probes is already absurd); a longer value is corruption -> default 3.
nr TRY204 3 3
[ "$TRY204" -lt 1 ] && TRY204=1
# F24 (v9.11): how many 204 misses a seat may absorb. 0 = v9.10's all-204 rule
# (bit-identical default); raise to 1..TRY204-1 to let a near-clean node seat
# with a non-zero LOSS share recorded (mihomo confidence spirit).
LOSS_MAX=${LOSS_MAX:-0}
case "$LOSS_MAX" in ''|*[!0-9]*) LOSS_MAX=0 ;; esac
nn LOSS_MAX
# F45: LOSS_MAX is compared against TRY204 and then subtracted inside $(( )).
# Out of range -> both tests say false, so "[ LOSS_MAX -ge TRY204 ]" never clamps
# and LOSS_MAX keeps a 20-digit value that later wrappers produce garbage.
# 3 digits, same scale as TRY204; anything longer is corruption -> default 0.
nr LOSS_MAX 3 0
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
# F43 (v9.21): the sum on the next line is a $(( )), so W_*=08 would abort the
# round right here, before any traffic. Strip after the guards, before the sum.
nnall W_LAT W_THR W_STAB W_JIT
if [ $(( W_LAT + W_THR + W_STAB + W_JIT )) -eq 0 ]; then
  W_LAT=30; W_THR=60; W_STAB=10; W_JIT=15
fi
# F26 (v9.11): capped-EMA constants for the PREV_BPS baseline
EMA_A=${EMA_A:-80}               # old-sample weight in percent (0.8 -> 80)
EMA_CAP=${EMA_CAP:-125}          # up-step cap in percent (1.25 -> 125)
EMA_SPIKE=${EMA_SPIKE:-300}      # sample above old*this%% is a spike, ignored
EMA_UNSTICK=${EMA_UNSTICK:-3}    # F34: consecutive rejections before re-seed
# F35 (v9.16): a streak is only meaningful while it is CONSECUTIVE, so the
# counter file carries its own timestamp. A streak older than SPK_TTL seconds
# (default 450 = 1.5 cron intervals of 300s) is discarded instead of being
# carried across skipped / crashed rounds. See the header block for the
# measurement that motivated this.
SPK_TTL=${SPK_TTL:-450}
# v9.11: EMA_A doubles as a WEIGHT, so a value above 100 makes the blend
# extrapolate backwards - the new sample gets a NEGATIVE weight and a fast node
# would push the baseline DOWN, manufacturing a fake spike next round. Clamp to
# the meaningful range 0..100 (non-numeric values are re-guarded at the use site
# too, so an old conf with garbage still degrades to the default).
case "$EMA_A" in ''|*[!0-9]*) EMA_A=80 ;; esac
# F43 (v9.21): EMA_A/EMA_CAP/EMA_SPIKE are multiplied inside $(( )) later, and
# "$(( PREV_BPS * EMA_SPIKE / 100 ))" with EMA_SPIKE=0300 would abort the round.
# Strip here, before any of the three clamps: nn() is a no-op on a non-numeric
# value, so EMA_CAP/EMA_SPIKE still get their own character-set guard a few
# lines down and a garbage value is replaced by the default there as before.
nnall EMA_A EMA_CAP EMA_SPIKE
# F45: EMA_A is a WEIGHT in the blend (see the clamp directly below), so an
# out-of-range value made the clamp "EMA_A -gt 100" false and the multiplication
# wrapped the baseline NEGATIVE (measured: PREV_BPS=-40075284104017732). 3 digits
# is enough for the meaningful 0..100 window; the clamp right below trims >100.
nr EMA_A 3 80
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
# F45: both are multiplied into $(( )) against the baseline. Out of range -> the
# "EMA_CAP -lt 100" floor is false, the cap never lifts, and the product wraps.
nr EMA_CAP 3 125
[ "$EMA_CAP" -lt 100 ] && EMA_CAP=100
case "$EMA_SPIKE" in ''|*[!0-9]*) EMA_SPIKE=300 ;; esac
nr EMA_SPIKE 3 300
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
# F43 (v9.21): every knob above has now passed its CHARACTER-SET guard, so a
# leading zero can be stripped safely (a non-numeric value would be left alone
# by nn() and would have been replaced by the default one line earlier anyway).
# This is the single point that matters for the conf side: the floors below and
# every $(( )) later in the file then see plain decimal. Measured on v9.20
# (p46/p47): TRY204=08 aborted a racing round with "arithmetic syntax error",
# RACE_CD=08 / THRESH_BPS=030000 were silently misread as octal.
nnall WIN_SEC FAIL_TRIGGER RACE_CD RACE_BUDGET_H RACE_BUDGET_WIN TOP_PICK \
      TIE_PCT THRESH_BPS SEVERE_BPS SPEED_MAX SPEED_TRIES CAND_204_TMO \
      SPIKE_PCT TRY204 LOSS_MAX W_LAT W_THR W_STAB W_JIT \
      EMA_UNSTICK SPK_TTL
# F45 (v9.21): leading zeros fixed one class of bad number; a value ABOVE 2^63 is
# the other. nr() applies the same window to every remaining knob with a length
# ceiling chosen from what the knob can physically mean (all times are seconds,
# all rates are B/s, all percentages are 0..100-ish). A value that fails the
# window is replaced by the shipped default - see the F45 block at nr() for the
# three measured harms this prevents.
#   seconds  (<= 8 digits  = 3.1 years) : WIN_SEC RACE_CD RACE_BUDGET_WIN
#   counters (<= 5 digits)              : FAIL_TRIGGER RACE_BUDGET_H SPK_TTL
#   pool     (<= 3 digits)              : TOP_PICK
#   percent  (<= 3 digits)              : TIE_PCT SPIKE_PCT EMA_A EMA_CAP
#                                         EMA_SPIKE EMA_UNSTICK
#   rate     (<= 8 digits)              : THRESH_BPS SEVERE_BPS
#   probes   (<= 3 digits)              : SPEED_MAX SPEED_TRIES CAND_204_TMO
#   weights  (<= 5 digits)              : W_LAT W_THR W_STAB W_JIT
nr WIN_SEC            8 900
nr FAIL_TRIGGER       5 2
nr RACE_CD            8 900
nr RACE_BUDGET_H      5 2
nr RACE_BUDGET_WIN    8 3600
# TOP_PICK also reaches `head -N`, and busybox head rejects anything past
# 4294967295 (measured: 4294967295 ok, 4294967296 "invalid number"). 3 digits is
# far below that and far above any real selector pool.
nr TOP_PICK           3 2
nr TIE_PCT            3 20
nr THRESH_BPS         8 30720
nr SEVERE_BPS         8 15360
nr SPEED_MAX          3 4
nr SPEED_TRIES        3 2
nr CAND_204_TMO       3 2
nr SPIKE_PCT          3 20
nr W_LAT              5 30
nr W_THR              5 60
nr W_STAB             5 10
nr W_JIT              5 15
nr EMA_UNSTICK        3 3
nr SPK_TTL            5 450
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
# F52/F53b (v9.22): ONE place that removes every per-round scratch file, shared
# by the early traps and on_exit. The variables are assigned later in the file,
# so the ones not yet reached expand to empty and are skipped - that is what
# lets the traps installed at the lock (long before VER_F exists) use it too.
# Two leaks measured on the router motivated this: probe r4leak showed an
# API_DOWN exit leaving /tmp/ng9_typ.* behind on EVERY round (98 files had piled
# up on the live box), and probe r4d7 case C showed a TERM during S2 leaving 2
# files. Both are tmpfs, i.e. the same filesystem the API and the flock use.
ng_rm_tmp(){
  for _ngtmp in "$VER_F" "$TYP_F" "$TYPE_F" "$G_F" "$R_F" "$B_F" \
                "$GRP_F" "$DLY_F" "$CG_F" "$MS_F" "$RACE_RES" "$SCORED"; do
    [ -n "$_ngtmp" ] && rm -f "$_ngtmp" 2>/dev/null
  done
  return 0
}
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
# F43 (v9.21): NG_SUBHEAL_MIN_WAIT is the seed for the backoff doubling, whose
# next step is _wait=$(( sh_cur * 2 )) inside the detached child. "0900" here
# would abort that CHILD (a silent dead heal) rather than the round, so it is
# the same defect with a quieter symptom.
nnall NG_SUBHEAL_OK_WIN NG_SUBHEAL_STALE_MIN NG_SUBHEAL_MIN_WAIT NG_SUBHEAL_MAX_WAIT
# F45 (v9.21): the backoff step is _wait=$(( sh_cur * 2 )) and the seed is
# NG_SUBHEAL_MIN_WAIT. An out-of-range seed makes "wait < MIN" false (so the
# floor never applies) and the doubling then wraps NEGATIVE - the heal would
# either storm or stall silently, in a detached child whose stderr is discarded.
# All four are seconds/minutes: 8 digits is already ~3 years.
nr NG_SUBHEAL_OK_WIN    8 21600
nr NG_SUBHEAL_STALE_MIN 5 10
nr NG_SUBHEAL_MIN_WAIT  8 900
nr NG_SUBHEAL_MAX_WAIT  8 21600
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
    # F43 (v9.21): the backoff file is plain text in tmpfs and survives a crash,
    # so "0900" is reachable. sh_cur is later doubled inside $(( )), which would
    # abort the detached heal child on an 8/9 digit.
    nnall sh_next sh_cur
    # F45: sh_cur is doubled in $(( )) inside the detached child. Out of range
    # makes the MIN/MAX clamps below false, and the doubled value wraps, so the
    # backoff file gets a negative next-retry and the heal either storms or
    # never retries. 8 digits is ~3 years of seconds: anything longer is a
    # hand-planted or corrupted file, so re-seed from the conf default.
    nr sh_next 10 0
    nr sh_cur  8 "$NG_SUBHEAL_MIN_WAIT"
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
  # F36b/F37: DOUBLE fork. A plain `( ... ) &` is a JOB OF THIS SHELL, so every
  # later bare `wait` in the round (S3 line 1253, S5 line 1465, S6 line 1809)
  # waits for it - measured 8s/8s, i.e. the "never blocks the round" promise was
  # false and a dead CDN could add ~67s to a round it was supposed to be
  # independent of. Wrapping it in a second subshell detaches it from this
  # shell's job table; the inner block replaces the old body unchanged.
  ( (
    # F36a: the child would inherit fd 9, the flock this round holds for its
    # whole life (F33). On an early-exit path the round returns before any
    # `wait`, so the orphan held /tmp/nodeguard.single past the round's death
    # and the 05:10 selfupdate saw a lock nobody owned. Release it here.
    exec 9>&- 2>/dev/null
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
  ) > /dev/null 2>&1 & ) > /dev/null 2>&1
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
# F39 (v9.19): NO tr ',' '\n' here. The old form tore the JSON body on every
# comma to make grep line-oriented, but a node name may itself contain a comma
# ("JP-01,HK-02", "HK,JP relay", "1,2x rate"). Then "now":"JP-01,HK-02" is split
# into '"now":"JP-01' + 'HK-02"' and grep -o can only return the truncated head,
# so the readback disagrees with the name we asked for and every round ends in
# READ_FAIL - the same class as F38 (a name assumption, not a safety limit),
# measured in sandbox D37 (0 pass / 2 fail on v9.18). grep -o works on one long
# line as well as on many short ones, so the tr was never needed. Verified on
# the router: whole-body grep returns "now":"JP-01,HK-02" intact, tr-split
# returns nothing.
get_now(){ curl -s -m 3 -H "$AH" "$API/proxies/$(enc "$SEL")" | grep -o '"now":"[^"]*"' | head -n1 | sed 's/^"now":"//; s/"$//'; }
# F1: exact JSON field parse replaces greedy sed. Verified live: an HTML
# 502 page, {"error":...}, {"now":""} all yield an empty string now.
# Keep a defensive blacklist on top (defense in depth): a truncated JSON with
# an escaped quote leaves a trailing backslash ("a\" -> a\), so backslash,
# quote, backtick and bracket chars are all rejected. Verified in ash:
# quoted-quote, single-quote, backslash, brace, angle and backtick patterns all
# match; normal names with spaces / CJK / pipes / hyphens still pass.
# NOTE: spaces must stay legal - real node names contain them.
# F38 (v9.18): the byte cap was 96, which was sized as if a name were ASCII.
# Real airport names carry emoji, CJK and rate tags, and 30 CJK chars are
# already 90 bytes, so a 31-char CJK name is 97 bytes. Measured live max on
# this subscription was 48 bytes (174 provider entries + 32 /proxies entries),
# so the cap had only a 2x margin and nothing guarantees a rename stays under
# it. Sandbox proof (t_name96.sh): a 97-byte name made SECTION 2 log
# READ_FAIL and exit 0 - the monitor stopped EVERY round with no self-
# recovery, and on_exit's restore read the same name as unreadable and
# returned without restoring, so a TERM mid-race could leave the group on a
# half-tested candidate. Both are the same root cause: 96 was a name-length
# assumption, not a safety limit.
# (A third claim - that a >96-byte candidate was misfiled as PUT_UNKNOWN and
# could never be raced - is WRONG and withdrawn: put_node returns before this
# gate when the readback already equals the requested name, so a long
# candidate seats normally. The same scenario passes on unpatched v9.17.)
# 256 keeps a 5x margin over the measured live max and still rejects a
# multi-KB HTML error page, which the blacklist below also rejects on its own
# (every HTML page contains '<'). The length test is a saneness bound, not the
# primary garbage filter - the character blacklist is.
now_ok(){
  [ -z "$1" ] && return 1
  [ "${#1}" -gt 256 ] && return 1
  case "$1" in *'"'*|*"'"*|*'\'*|*'{'*|*'}'*|*'<'*|*'>'*|*'`'*) return 1 ;; esac
  # F57 (v9.24): a control byte in a name crosses every TAB-delimited boundary
  # downstream (RACE_RES columns shift, the SCORED row mis-splits and the round
  # can switch the group on a corrupted score). Verified on the router: TAB, CR,
  # ESC, DEL and a mid-string LF all rejected; CJK, emoji, space, comma, parens,
  # brackets, '*' and high bytes still accepted. The octal span is mandatory -
  # tr -d '[:cntrl:]' is a NO-OP on this busybox (see F55). A plain compare is
  # used (not a byte count): measured on the router to give the identical
  # verdict for all 15 probe cases, and it saves a fork on a per-node hot path.
  _ns=$(printf '%s' "$1" | tr -d '\001-\037\177')
  [ "$_ns" = "$1" ] || return 1
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
# F47 (v9.21): the round ceiling is DERIVED from the knobs in force.
# ------------------------------------------------------------
# The old --check numbers were literals (34 / 84 / 480s margin 396s) that only
# held for the shipped defaults. SPEED_MAX, SPEED_TRIES, TRY204, CAND_204_TMO and
# TOP_PICK are all conf-tunable and all lengthen the round, so with a tuned conf
# the report described a round that is not the one that runs (measured 106s and
# 189s of real wall clock against a reported 84s, see the F47 header block).
# The same constants also drive the stale-lock reclaim, which is the dangerous
# half: once the true ceiling passes the 480s threshold the next cron tick can
# reclaim a live lock and two rounds run at once.
#
# Formula, taken from 35_yanzheng/cost_v910.py (the authority for 84/34) and
# generalised over the knobs. NORMALISED AGAINST THE DEFAULTS:
#   per_cand = TRY204*CAND_204_TMO + max(6, SPEED_TRIES*SPEED_MAX) + 8
#   s3       = max(6, CAND_204_TMO, SPEED_MAX) + SPEED_MAX
#   racing   = 84 + max(0, s3-10) + TOP_PICK*max(0, per_cand-22)
#              + max(0, TOP_PICK-2)*22
#   healthy  = 34 + max(0, s3-10) + max(0, SPEED_TRIES*SPEED_MAX-8)
# With the shipped defaults every delta is 0, so the reported numbers are
# EXACTLY the historical 34 / 84 - existing documents and tests stay valid.
# Each max(0, .) term keeps a BELOW-default knob from reporting a ceiling under
# the documented baseline: the baseline is a real measurement, not a guess, and
# shrinking the report below it would be a new lie in the other direction.
# An upper clamp of 86400s (a day) keeps a maximal knob set (all 3-digit) from
# printing an absurd number; the lock minutes then clamp separately at 1440.
# Wall clock per section is the worst case where every request times out, so the
# result is an upper bound by construction.
# Output: NG_HEALTHY, NG_RACING, NG_LOCK_S, NG_LOCK_MIN.
ng_ceiling(){
  _g=6
  _sp=$(( SPEED_TRIES * SPEED_MAX ))
  _cm=$(( TRY204 * CAND_204_TMO ))
  _hi="$_sp"; [ "$_g" -gt "$_hi" ] && _hi=$_g
  _pc=$(( _cm + _hi + 8 ))            # per-candidate worst case, ship defaults 22
  _mx="$CAND_204_TMO"
  [ "$SPEED_MAX" -gt "$_mx" ] && _mx=$SPEED_MAX
  [ "$_g" -gt "$_mx" ]        && _mx=$_g
  _s3=$(( _mx + SPEED_MAX ))          # ship defaults 10
  _d_s3=$(( _s3 - 10 ));      [ "$_d_s3" -lt 0 ] && _d_s3=0
  _d_cand=$(( _pc - 22 ));    [ "$_d_cand" -lt 0 ] && _d_cand=0
  _d_pool=$(( TOP_PICK - 2 )); [ "$_d_pool" -lt 0 ] && _d_pool=0
  _d_sp=$(( _sp - 8 ));       [ "$_d_sp" -lt 0 ] && _d_sp=0
  NG_RACING=$(( 84 + _d_s3 + _d_cand * TOP_PICK + _d_pool * 22 ))
  NG_HEALTHY=$(( 34 + _d_s3 + _d_sp ))
  [ "$NG_RACING" -gt 86400 ] && NG_RACING=86400
  NG_LOCK_S=$(( NG_RACING * 3 ))
  [ "$NG_LOCK_S" -lt 480 ] && NG_LOCK_S=480
  NG_LOCK_MIN=$(( (NG_LOCK_S + 59) / 60 ))
  [ "$NG_LOCK_MIN" -lt 8 ]    && NG_LOCK_MIN=8
  [ "$NG_LOCK_MIN" -gt 1440 ] && NG_LOCK_MIN=1440
  return 0
}
ng_ceiling

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
    # F43 (v9.21): $((CNOW-CRACE)) below aborts with "arithmetic syntax error"
    # on a leading zero - measured on v9.20 with RACE_TS=08: rc=2 and --check
    # printed no verdict at all (p46), which reads as "--check is broken".
    nnall CFAIL CTS CRACE
    # F45 (v9.21): an out-of-range stamp makes "CRACE -gt 0" FALSE, so the report
    # claims "not cooling down" while the round would still see a cooldown (or
    # vice versa) - the diagnostic lies in the exact situation it is consulted
    # for. Both stamps are epochs (10 digits); CFAIL is a small counter.
    nr CFAIL 5 0
    nr CTS   10 0
    nr CRACE 10 0
    echo "check_state_file=present"
  else
    echo "check_state_file=absent (first run would initialise it)"
  fi
  CNOW=$(date +%s)
  # F46 (v9.21): same future-stamp policy as the round path - a stamp ahead of
  # now is not evidence about the past, so it is ignored here too. Otherwise the
  # report would claim a cooldown the round no longer respects (or, for
  # RTS_LOG, a budget that never expires), i.e. the diagnostic would disagree
  # with the behaviour precisely when an operator consults it.
  [ "$CRACE" -gt 0 ] && [ "$CRACE" -gt "$CNOW" ] && CRACE=0
  [ "$CTS"   -gt 0 ] && [ "$CTS"   -gt "$CNOW" ] && { CFAIL=0; CTS=0; }
  if [ "$CRACE" -gt 0 ] && [ $((CNOW-CRACE)) -lt "$RACE_CD" ]; then
    echo "check_cooldown_remaining=$((RACE_CD-(CNOW-CRACE)))s of ${RACE_CD}s"
  else
    echo "check_cooldown_remaining=0s (not cooling down)"
  fi
  CREC=$(printf '%s' "$CRTS" | tr ',' '\n' | awk -v now="$CNOW" -v w="$RACE_BUDGET_WIN" '$1+0>0 && $1+0<=now && now-$1<w' | grep -c .)
  echo "check_budget_used=${CREC:-0}/${RACE_BUDGET_H} in ${RACE_BUDGET_WIN}s"
  echo "check_fail_counter=$CFAIL/${FAIL_TRIGGER}"
  # -- static cost model, derived from the knobs in force (F47) --
  # These were the literals 34 / 84 / 480s before v9.21: correct only for the
  # shipped defaults, wrong for every tuned conf that lengthens the round (real
  # wall clock measured 66s / 106s / 189s against the printed 84s). ng_ceiling()
  # derives them from SPEED_MAX, SPEED_TRIES, TRY204, CAND_204_TMO, TOP_PICK and
  # is normalised against the defaults, so the default output is unchanged.
  echo "check_ceiling_healthy_s=$NG_HEALTHY"
  echo "check_ceiling_racing_s=$NG_RACING (derived from SPEED_MAX=$SPEED_MAX SPEED_TRIES=$SPEED_TRIES TRY204=$TRY204 CAND_204_TMO=$CAND_204_TMO TOP_PICK=$TOP_PICK; default conf -> 84)"
  echo "check_lock_threshold=${NG_LOCK_S}s (${NG_LOCK_MIN}min) margin_vs_ceiling=$((NG_LOCK_S-NG_RACING))s"
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

# ---- single instance lock (mkdir + stale guard) ----
# F47 (v9.21): the stale threshold used to be the literal "-mmin +8" (480s).
# That is only safe while the true ceiling is 84s. The threshold is now DERIVED
# (ng_ceiling): lock_s = max(480, ceiling*3), minutes rounded up, floored at 8
# and capped at 1440. Shipped defaults: 84*3=252 < 480 -> 480s -> 8 min, i.e.
# the old behaviour, bit for bit. A tuned conf that lengthens the round raises
# the threshold with it, which is what keeps a live round from being reclaimed.
# Measured harm it prevents (psteal.sh, real script): a long round with maximal
# knobs had its lock directory back-dated by 9 minutes, the next round reclaimed
# it as "stale" and BOTH rounds ran - two RUN banners, two RACE start lines, two
# ACT switch lines against one state file.
if ! mkdir "$LOCK_DIR" 2> /dev/null; then
  if [ -n "$(find "$LOCK_DIR" -mmin +"$NG_LOCK_MIN" 2>/dev/null)" ]; then
    rm -rf "$LOCK_DIR" 2>/dev/null
    mkdir "$LOCK_DIR" 2>/dev/null || { log "SKIP lock contention after stale reclaim"; exit 0; }
  else
    log "SKIP another instance running"
    exit 0
  fi
fi
# F54 (v9.22): F44 made the lock open PROBE-guarded, but the window between the
# probe and the real `exec 9>>` was still fatal and still SILENT. Re-measured on
# the router with probe r4trap T1/T2: when the main `exec 9>>dir/that/died`
# fails, ash terminates the shell with rc=1, but the EXIT trap DOES run. So the
# round can be made loud instead of invisible: FLOCK_OPENING marks the exact
# span where a death means "the deploy lock open failed", and the EXIT arm below
# writes a FATAL line before releasing the lock. Probe r4r3 case 9R reproduced
# the old behaviour exactly - no TAIL, no OR-BRANCH, no log line, FLOCK_FD
# already set - i.e. a round that silently vanished while holding the mkdir lock.
# A full elimination is impossible (busybox ash makes a failed `exec` redirect
# unconditionally fatal, so the main shell cannot fall back by itself); the
# honest fix is to make the failure diagnosable and to leave no lock behind.
FLOCK_OPENING=0
trap '[ "$FLOCK_OPENING" = "1" ] && log "ERR deploy lock open failed mid-round (F54): shell terminated by exec redirect, round aborted cause=FLOCK_OPEN_DIED"; rmdir "$LOCK_DIR" 2>/dev/null' EXIT
# F41 (v9.19): a TERM/INT/HUP that arrives BEFORE SECTION 6 installs its
# on_exit trap must END the round. The old single trap
#   trap 'rmdir "$LOCK_DIR"' EXIT INT TERM HUP
# ran the rmdir and then RETURNED, so the shell simply carried on with the rest
# of the script: measured in sandbox probe (p41b) - "B: still executing after
# TERM" / "B: LOCK GONE (round continues unlocked)". Two consequences, both
# real: (a) the round kept doing S3/S4/S5 traffic and could even reach a PUT
# after being told to stop; (b) the single-instance gate was already gone, so
# the next cron tick could start a SECOND round while the first was alive -
# exactly the double-round the mkdir lock exists to prevent, and the reason
# `trap` must exit. exit 130 keeps it distinguishable from a normal 0.
# The EXIT arm above still covers every normal path, and SECTION 6's later
# per-signal `trap ... on_exit` set replaces both arms once the race starts
# (on_exit does its own restore and then exits with OE_RC).
# F53b (v9.22): the INT/TERM/HUP arm below must clean the SAME scratch files as
# EXIT. Before this it only did `rmdir "$LOCK_DIR"`, so a signal during S2/S3/S5
# left /tmp/ng9_* behind: probe r4d7 case C on the router measured 2 leftovers
# after one TERM, probe r4r2 case 3/4 measured 0 only because those runs happened
# to be killed before the files were created. ng_rm_tmp covers every variable
# that exists at the moment the signal lands and silently skips the rest.
# F56b (v9.23): the same defect as F56, one phase earlier. This arm hardcoded
# `exit 130` for INT *and* TERM *and* HUP, so a TERM before the race reported the
# exit status of a Ctrl-C: measured on the router with probe r7d L3 - `kill
# -TERM` returned RC=130. An operator (or a wrapper, or a supervisor restarting
# on 143) cannot distinguish "the operator pressed Ctrl-C" from "the system asked
# us to shut down". 128+N is the only value that carries the identity of the
# signal, and it costs nothing: one arm per signal, as in SECTION 6 below.
trap 'ng_rm_tmp; rmdir "$LOCK_DIR" 2>/dev/null; exit 130' INT
trap 'ng_rm_tmp; rmdir "$LOCK_DIR" 2>/dev/null; exit 143' TERM
trap 'ng_rm_tmp; rmdir "$LOCK_DIR" 2>/dev/null; exit 129' HUP
# F33: take the SAME flock the daily selfupdate deploy guard uses, for the
# whole round. selfupdate (/root/selfupdate.sh) runs `flock -n
# /tmp/nodeguard.single` and backs off when it is held - but until v9.14 this
# script never held it, so at 05:10 a deploy could cp a new file over the one
# the running shell was reading, producing a mixed old/new body. Opening the fd
# here makes both guards share one lock domain. If flock is not installed the
# redirect fails harmlessly (fd 9 on /dev/null) and the mkdir lock above is
# still the single-instance gate.
# F44 (v9.21): THE LOCK OPEN ITSELF MUST NOT BE ABLE TO KILL THE ROUND.
# `exec 9>>FILE` is a SPECIAL BUILTIN: when the redirect cannot be performed
# busybox ash terminates the shell right there, before any later line runs.
# Measured in sandbox probe pfd: `exec 9>>/nonexistent_dir/f` -> the script ends
# with rc=1 and nothing after it executes; a plain `echo x >>file` in the same
# position merely fails. Under cron stderr is discarded, so the round VANISHES
# with no banner, no SKIP line and no log entry - it looks exactly like cron
# never fired, which is the worst possible failure shape for a silent guard.
# Reachable whenever NG_FLOCK points into a directory that does not exist (a
# conf typo, an init.d that was supposed to mkdir it), or when the tmpfs holding
# it is full or read-only. The mkdir lock above is already held, so the safe
# behaviour is: probe the open in a SUBSHELL (a dying subshell cannot kill us),
# and only exec on the main shell when the probe proved the file is openable.
NG_FLOCK="${NG_FLOCK:-/tmp/nodeguard.single}"
FLOCK_FD=0
if command -v flock >/dev/null 2>&1; then
  # The probe opens the real file (>> creates it) and closes it on subshell
  # exit, so a successful probe leaves no lock held and no state behind.
  if ( exec 9>>"$NG_FLOCK" ) 2>/dev/null; then
    # F54: arm the FATAL-reporting EXIT trap for exactly this redirect. If the
    # shell dies here (the probe passed but the real open still fails - tmpfs
    # went read-only or full in between), the trap above logs why.
    FLOCK_OPENING=1
    exec 9>>"$NG_FLOCK" 2>/dev/null
    FLOCK_OPENING=0
    FLOCK_FD=1
  else
    FLOCK_FD=0
  fi
fi
if [ "$FLOCK_FD" = "1" ]; then
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
  # F44: say it out loud. The round proceeds on the mkdir lock alone; the only
  # thing lost is the F33 mutual exclusion with a 05:10 selfupdate, which is a
  # narrow window compared with losing every round forever.
  exec 9>/dev/null 2>/dev/null
  log "WARN deploy lock $NG_FLOCK unavailable (open failed or flock missing), continuing on the mkdir lock only cause=FLOCK_UNAVAILABLE"
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
# F43 (v9.21): the state file is the most likely carrier of a leading zero
# (restored backup, hand edit, an older tool). The four fields below are all
# used inside $(( )) - FAIL_N+=1, NOW-LAST_TS, NOW-RACE_TS, and PREV_BPS in the
# EMA/spike maths - so "v9:08:..." or "PREV_BPS=0100000" aborts or corrupts the
# round. Measured on v9.20 (p46): FAIL_N=08 + one mild hit -> rc=2 and the log
# stops mid-round; PREV_BPS=0100000 -> baseline read as octal 32768 and the F26
# spike rule then rejects every honest sample forever.
nnall FAIL_N LAST_TS RACE_TS PREV_BPS
# F45 (v9.21): the character-set guard above accepts a 20-digit field, and an
# out-of-range value then fails EVERY comparison against it. Measured on v9.21:
#   PREV_BPS=99999999999999999999 -> the EMA product wraps and the state line is
#   persisted as PREV_BPS=-40075284104017732 (a NEGATIVE baseline, which silently
#   disables the whole F26/F34 spike rule from then on).
#   RACE_TS=99999999999999999999  -> "RACE_TS -gt 0" is false, so the cooldown
#   gate is skipped entirely; the epoch maths inside $(( )) runs on garbage.
# Windows: FAIL_N is a 2-hit counter, the two stamps are epochs (10 digits),
# PREV_BPS is B/s (12 digits = 1 TB/s, far past any tunnel seen).
nr FAIL_N  5 0
nr LAST_TS 10 0
nr RACE_TS 10 0
nr PREV_BPS 12 0
# F46 (v9.21): F40 removed the FUTURE-STAMP hazard from the streak file
# (spk_read) but left it in the state file, which carries TWO stamps with the
# same class of consequence. Every test on an epoch here is an AGE
# (NOW-TS), and a negative age fails in the dangerous direction:
#   RACE_TS > NOW   -> (NOW-RACE_TS) < RACE_CD stays TRUE, so the cooldown
#                      gate reads "inside cooldown" for however far ahead the
#                      stamp is (measured: 86400 ahead -> rcd=87299s). A mildly
#                      degraded cur is then suppressed round after round with
#                      cause=COOLDOWN_MILD and the guard never races at all
#                      (D55).
#   RTS_LOG entries -> the budget purge keeps an entry when
#                      (now-ts) < RACE_BUDGET_WIN; a negative age is always
#                      less, so the entry NEVER expires and each one holds a
#                      budget slot permanently. Two such entries mean
#                      RACE_BUDGET_H=2 is exhausted forever ("race budget
#                      exhausted (2/2 in 3600s)" every round, D56).
#   LAST_TS > NOW   -> (NOW-LAST_TS) > WIN_SEC never fires, so FAIL_N is never
#                      reset. Rounds days apart then still count as hits inside
#                      one window and a single blip races immediately, burning
#                      a slot on noise (D57).
# Reachable without malice: a clock jump / bad NTP step while a round runs, a
# state file restored from another machine, or a hand edit. Same policy as F40:
# a stamp that cannot be about the past is not evidence, so it is DISCARDED -
# the counter it dates goes with it (a count with no trustworthy timestamp has
# no window). NOW is the upper bound, not a tolerance: cron rounds are seconds
# apart and every comparison here is a multi-minute window, so a small skew is
# harmless while a future stamp is never legitimate.
[ "$LAST_TS" -gt "$NOW" ] && { FAIL_N=0; LAST_TS=0; }
[ "$RACE_TS" -gt "$NOW" ] && { RACE_TS=0; }
# RTS_LOG: keep only entries that are both positive and not in the future
# (same filter as the budget purge in SECTION 5a, so the two agree).
RTS_LOG=$(printf '%s' "$RTS_LOG" | tr ',' '\n' | awk -v now="$NOW" '$1+0>0 && $1+0<=now' | tr '\n' ',' | sed 's/,$//')
# stale mild count outside window is void
[ "$LAST_TS" -gt 0 ] && [ $((NOW-LAST_TS)) -gt "$WIN_SEC" ] && FAIL_N=0
# F8: 4th line = PREV_BPS (old 3-line state -> missing -> fallback 0)
# N1: atomic write - a killed round must not leave a truncated state
# (half-written line 1 zeroes FAIL_N and resets cooldown/budget).
# F48 (v9.22): THE 4-LINE INVARIANT MUST BE SELF-ENFORCED AT THE WRITE SIDE.
# LEDGER/RTS_LOG/PREV_BPS are interpolated straight into the file, so any byte
# that the reader treats as a line break splits one field into two and shifts
# every later line: measured on v9.21 by planting a state whose LEDGER carried a
# literal newline - the file became 5 lines, the next round read "LEDGER=N" and
# lost PREV_BPS entirely (RTS_LOG= got parsed as line 4, PREV_BPS fell back to 0),
# which silently resets the F26/F34 baseline and the race cooldown accounting.
# Today a raw newline cannot arrive from the normal API path (JSON escapes it to
# the two characters \n, measured), but "cannot arrive" is exactly the kind of
# assumption that breaks when the source changes (a hand-edited state, a restored
# backup from another tool, a future provider name field, a CRLF-mangled copy).
# A 4-line file is a hard contract of this script, so enforce it where it is
# written instead of trusting every upstream encoder forever: strip every control
# byte from the three free-form fields, i.e. 0x01-0x1f (which covers TAB, LF, CR)
# plus 0x7f. Node names stay readable because every byte >= 0x20 survives.
#
# F55 (v9.23): the original F48 sanitiser used tr -d '[:cntrl:]'. That expression
# was measured to be a COMPLETE NO-OP on the router. BusyBox v1.37 tr has no
# character-class support at all: it parses '[:cntrl:]' as the LITERAL byte set
# [ : c n t r l ] and deletes only those seven characters. Proof on the router:
#   printf '[:cnrl]abc\tDEF' | tr -d '[:cntrl:]'   ->  'ab\tDEF'
# ('c' vanished because it is a literal set member, while the real control bytes
# survived untouched). Same for [:digit:] -> 'a1b2c3' stays 'a1b2c3'. So F48
# passed on the dev box's GNU tr and silently did nothing in production, which is
# exactly the failure mode a sanitiser must never have.
# The fix uses an explicit octal span, verified on the router to delete 0x01-0x1f
# and 0x7f while leaving 0x20-0x7f, ALL high bytes 0x80-0xff and every UTF-8
# multibyte sequence intact (a backslash 0x5c survives too, so a name containing
# one is not mangled).
# DO NOT "improve" this back to a character class. tr -cd '[:print:]' on this
# busybox keeps the literal set and therefore emits an EMPTY string (measured: 0
# bytes), and tr -cd '\040-\176' would delete every CJK and emoji byte. The octal
# span is the only portable form on this build.
# F49 (v9.22): the sanitiser temporaries are named _f48* ON PURPOSE. POSIX sh has
# no local, so any helper that assigns a plain _x leaks it into the caller's
# namespace; an audit of every single-underscore name in this file found save_state
# sharing _sp with ng_ceiling (which uses _sp for SPEED_TRIES*SPEED_MAX and reads it
# three more times in the same function). Today nothing observes the value across
# the two, so it is not reachable - but relying on call ORDER for correctness is
# exactly what a later edit breaks silently, so the write side gets its own names.
save_state(){
  _f48l=$(printf '%s' "$LEDGER" | tr -d '\001-\037\177')
  _f48r=$(printf '%s' "$RTS_LOG" | tr -d '\001-\037\177')
  _f48p=$(printf '%s' "$PREV_BPS" | tr -d '\001-\037\177')
  printf '%s\n%s\n%s\n%s\n' "v9:$1:$2:$RACE_TS" "LEDGER=$_f48l" "RTS_LOG=$_f48r" "PREV_BPS=$_f48p" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

# F35 (v9.16): the F34 unstick streak is stored as "N:TS" in tmpfs, so a round
# that produced no sample cannot donate its count to a later one. The file is
# deliberately NOT state line 5 (state stays 4 lines) and not a log grep (the
# log trims to tail-400).
#
# The mechanism is CONSUME-AT-START, not just a TTL: the streak is read once and
# immediately zeroed, here, right after the single-instance lock is held. A round
# only leaves a nonzero streak behind if it actually reached the EMA block (the
# only place that writes one). Every early exit - API_DOWN, GROUP_TYPE,
# READ_FAIL, EXT_CHANGE, manual hold, precheck/screen, a TERM kill - therefore
# breaks the chain by construction, which is exactly what "consecutive" means.
# A TTL alone would NOT be enough: cron fires every 300s, so a skipped round
# inside a 450s window would stay invisible. The TS is kept as a second guard
# for the one case consume cannot cover (a file planted by hand or by an older
# script version), and legacy bare-number files are dropped as unverifiable.
SPK_DEF=/var/run/nodeguard.spk
SPK_CARRY=0
spk_write(){ printf '%s:%s' "$1" "$NOW" > "${NG_SPK:-$SPK_DEF}" 2>/dev/null; }
spk_read(){
  _sf="${NG_SPK:-$SPK_DEF}"; _n=0
  case "$SPK_TTL" in ''|*[!0-9]*) SPK_TTL=450 ;; esac
  [ -f "$_sf" ] && _n=$(cat "$_sf" 2>/dev/null)
  case "$_n" in
    *:*)
      _ts=${_n#*:}; _n=${_n%%:*}
      case "$_n"  in ''|*[!0-9]*) _n=0 ;; esac
      case "$_ts" in ''|*[!0-9]*) _ts=0 ;; esac
      # F43 (v9.21): NOW-_ts is a $(( )), so "3:08" in the streak file would
      # abort the round before any traffic. This file is tmpfs and written by
      # spk_write with plain numbers, but it is hand-editable and survives a
      # crash, so it gets the same treatment as state.
      nnall _n _ts
      # F45: the streak file is tmpfs and survives a crash, and "$NOW-_ts" is a
      # $(( )). An out-of-range _ts makes the TTL test false (age > TTL never
      # fires), so the streak would be trusted indefinitely - the exact failure
      # F40 was written to stop, re-opened by a long number instead of a future
      # one. _n beyond 3 digits is not a streak any more either.
      nr _n  3 0
      nr _ts 10 0
      [ "$_ts" -gt 0 ] || _n=0
      [ "$_n" -gt 0 ] && [ "$_ts" -gt 0 ] && [ $((NOW-_ts)) -gt "$SPK_TTL" ] && _n=0
      # F40 (v9.19): a stamp in the FUTURE has a NEGATIVE age, so the TTL test
      # above (age > TTL) never fires and the streak would be trusted forever -
      # a clock jump, a bad NTP step or a hand-planted file could then hand an
      # unrelated round a half-earned streak and let it re-seed the baseline.
      # Same rule SUBHEAL already applies (L877: a negative age means the stamp
      # is not trustworthy, so it is discarded). Measured in sandbox D40 on
      # v9.18: spk "2:9999999999" was consumed and rewritten instead of dropped.
      [ "$_n" -gt 0 ] && [ "$_ts" -gt "$NOW" ] && _n=0
      ;;
    *) _n=0 ;;   # legacy bare number (v9.15) or garbage: unverifiable -> drop
  esac
  echo "$_n"
}
SPK_CARRY=$(spk_read)
spk_write 0

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
# F36a: every background child closes fd 9 (the F33 flock) first. These are
# reaped by the `wait` below, so they cannot outlive a normal round - but a
# round killed by TERM in between would orphan them for up to their -m cap
# while they still held the deploy lock. Closing is free and removes the case.
( exec 9>&- 2>/dev/null; curl -s -m 3 -H "$AH" "$API/version" > "$VER_F" 2>/dev/null ) &
( exec 9>&- 2>/dev/null; curl -s -m 3 -H "$AH" "$API/proxies/$(enc "$SEL")" > "$TYP_F" 2>/dev/null ) &
wait
VER_RESP=$(cat "$VER_F"); rm -f "$VER_F"
# F52 (v9.22): the API_DOWN early exit used to leave TYP_F behind. S2 launches
# BOTH reads in parallel (ver + type) so TYP_F is already created by the time
# the version read comes back empty; the old `exit 0` released the lock, wrote
# the WARN and walked away without removing it. Measured on the router with
# probe r4leak: 20 consecutive API_DOWN rounds leaked exactly 20
# /tmp/ng9_typ.* files, and `ls /tmp/ng9_typ.* | wc -l` was 98 on the live box -
# an unbounded growth on tmpfs, the very filesystem the API and the flock live
# on. Every early exit below this line is audited for the same shape.
[ -z "$VER_RESP" ] && { rm -f "$TYP_F"; log "WARN mihomo api unreachable, skip cause=API_DOWN"; exit 0; }
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
  # F52: both arms below exit while TYP_F is still on disk (it is only removed
  # on the success path, at the CUR read). Same leak shape, same tmpfs.
  "")      rm -f "$TYP_F"; log "WARN cannot read group type, skip round cause=GROUP_TYPE"; exit 0 ;;
  *)       rm -f "$TYP_F"; log "ERR group [$SEL] type is [$SEL_TYPE] not Selector; stage-1 delay would UNPIN it, REFUSE to run. Fix NG_GROUP_SEL or yaml. cause=GROUP_TYPE"; exit 0 ;;
esac
# F39 (v9.19): same class as get_now - the body must not be split on ','.
# grep -o scans chars, not comma-delimited tokens, so a name carrying a comma
# survives whole. The trailing rm stays where it was.
CUR=$(grep -o '"now":"[^"]*"' < "$TYP_F" | head -n1 | sed 's/^"now":"//; s/"$//'); rm -f "$TYP_F"
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
  # F34: the streak is relative to the baseline that is being discarded here;
  # leaving it behind would let a switch hand the next node a half-earned
  # re-seed. Cleared explicitly rather than relying on the file being absent.
  # F35: written through spk_write so the timestamp matches this round.
  spk_write 0
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
( exec 9>&- 2>/dev/null; google_check > "$G_F" ) &
( exec 9>&- 2>/dev/null; curl -s -o /dev/null -w "%{http_code}" -m 5 "https://www.gstatic.com/generate_204" > "$R_F" 2>/dev/null ) &
( exec 9>&- 2>/dev/null; speed_once > "$B_F" ) &
wait
G=$(cat "$G_F"); rm -f "$G_F"
R204=$(cat "$R_F"); rm -f "$R_F"
BEST_BPS=$(cat "$B_F"); rm -f "$B_F"
[ -z "$BEST_BPS" ] && BEST_BPS=0
# F45 (v9.21): BEST_BPS is curl's %{speed_download} cut at the decimal point, so
# it is normally a plain integer - but it is the OTHER operand of every EMA
# product and of the DROP percentage. A 20-digit reading (a wrapped counter, a
# proxy injecting a huge sample) makes those products wrap; the public fallback
# is the only sane answer. 12 digits = 1 TB/s.
nr BEST_BPS 12 0
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
  # F43 (v9.21): the log is user-visible and hand-restorable, and the line this
  # greps (a v9.x "OK [...] bps=NNN") is trivially forgeable. The very next
  # $(( )) divides by PREV_BPS after multiplying it, so "bps=080000" would
  # either abort the round (8 is not octal) or silently run on 32768.
  nn PREV_BPS
  # F45 (v9.21): the log fallback is the same hostile input as the state field -
  # a forged or truncated "bps=<20 digits>" line. Without the window the EMA
  # product wraps and the baseline goes negative (measured harm, see nr()).
  nr PREV_BPS 12 0
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
#
# F34 (v9.15) RATCHET ESCAPE. The F26 spike rule assumed a high sample is a
# one-off burst and the baseline is "about right". That assumption breaks the
# moment the baseline itself is physically too low: if PREV_BPS is stuck below
# the real capability, EVERY honest sample is >EMA_SPIKE% of it and is thrown
# away, so the baseline can never climb back. Measured on the live router
# (2026-11-27): a single bad reading pinned PREV_BPS=16393; the node's actual
# 5MB throughput was 180-360KB/s; the 108KB probe read 46-122KB/s; 196 F26
# rejections accumulated in the log and not one of them moved the baseline.
# Consequence: SPIKE_FLAG compares the current sample to a permanently tiny
# bar, so a genuine deceleration of a healthy node is misread as "spike not
# confirmed", which suppresses the switch decision (COOLDOWN_MILD /
# SPIKE_WAIT paths). The guard gets stuck on a node it would otherwise leave.
# Fix: allow the baseline to escape, but keep F26's anti-burst protection. A
# sample above SPK_LIM is only accepted as a new baseline when the baseline has
# proven to be a floor rather than a level, i.e. when the previous F26 streaks
# (consecutive rejections in a row) reached EMA_UNSTICK (default 3). On escape
# the baseline is re-seeded with the capped value (CAP_LIM applied against the
# OLD baseline, so escape is still gradual), and the streak resets. A genuine
# one-off burst therefore still cannot move the baseline, because the streak
# counter has to be earned by repeated high samples first.
if [ "$BEST_BPS" -gt 0 ] 2>/dev/null; then
  if [ "$PREV_BPS" -gt 0 ] 2>/dev/null; then
    case "$EMA_A"    in ''|*[!0-9]*) EMA_A=80 ;; esac
    case "$EMA_CAP"  in ''|*[!0-9]*) EMA_CAP=125 ;; esac
    case "$EMA_SPIKE" in ''|*[!0-9]*) EMA_SPIKE=300 ;; esac
    case "$EMA_UNSTICK" in ''|*[!0-9]*) EMA_UNSTICK=3 ;; esac
    [ "$EMA_UNSTICK" -lt 1 ] && EMA_UNSTICK=1
    case "$SPK_TTL" in ''|*[!0-9]*) SPK_TTL=450 ;; esac
    SPK_N=$SPK_CARRY
    SPK_LIM=$(( PREV_BPS * EMA_SPIKE / 100 ))
    CAP_LIM=$(( PREV_BPS * EMA_CAP / 100 ))
    if [ "$BEST_BPS" -gt "$SPK_LIM" ]; then
      SPK_N=$((SPK_N+1))
      if [ "$SPK_N" -ge "$EMA_UNSTICK" ]; then
        # F34: baseline proven to be a floor -> take the sample as-is. No
        # EMA_CAP clipping here on purpose: clipping against the (wrongly low)
        # old baseline would need many rounds to converge, which is the bug
        # being fixed. Three consecutive high samples are the evidence.
        PREV_BPS=$BEST_BPS
        log "  F34 baseline re-seeded ${PREV_BPS}B/s after ${SPK_N} consecutive rejections (was stuck below real capability)"
        SPK_N=0
      else
        log "  F26 spike ignored: sample ${BEST_BPS}B/s > ${EMA_SPIKE}% of baseline ${PREV_BPS}B/s, baseline kept (streak ${SPK_N}/${EMA_UNSTICK})"
      fi
    else
      # Normal path: unchanged v9.11 EMA. The DOWN direction is deliberately
      # NOT capped - EMA_A already limits a single step to (100-EMA_A)% and a
      # real deceleration must be tracked at that speed. An earlier draft of
      # F34 added a symmetric floor here; measurement showed it slowed genuine
      # deceleration ~5x (200000->16000 needs 11 rounds unclamped, 63 clamped)
      # and solved nothing the streak escape does not, so it was removed.
      SPK_N=0
      SAMPLE=$BEST_BPS
      [ "$SAMPLE" -gt "$CAP_LIM" ] && { SAMPLE=$CAP_LIM; }
      PREV_BPS=$(( (PREV_BPS * EMA_A + SAMPLE * (100 - EMA_A)) / 100 ))
    fi
    spk_write "$SPK_N"
  else
    # No baseline yet: seed from this round's sample (unchanged v9.11 policy).
    # SPK_N is reset here on purpose - the streak only means anything relative
    # to an existing baseline, and PREV_BPS is zeroed on EXT_CHANGE and on a
    # confirmed switch, so a stale streak must not survive that.
    PREV_BPS=$BEST_BPS
    spk_write 0
  fi
else
  # F35: a round with no usable sample proves nothing about the streak, so it
  # must not carry it forward. Explicit zero (not just TTL) keeps the common
  # path honest: two isolated bursts separated by a dead probe are NOT two
  # consecutive rejections. Without this the counter was "however many
  # rejections ever happened", and one burst could re-seed the baseline.
  spk_write 0
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
# F36a: drop the inherited flock fd in each S5 probe (see the S2 note).
( exec 9>&- 2>/dev/null; curl -s -m 15 -H "$AH" "$API/group/$SELU/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000" > "$DLY_F" 2>/dev/null ) &
( exec 9>&- 2>/dev/null; curl -s -m 15 -H "$AH" "$API/providers/proxies" 2>/dev/null | tr '{' '\n' | awk -v t="$PROV_TYPES" '
  BEGIN {
    n = split(t, a, "|"); for (i=1;i<=n;i++) w[a[i]] = 1
    # F57 (v9.24): build the control-byte set once. sprintf("%c",9) is a raw TAB,
    # which is the only portable way to name it inside an awk program (a literal
    # "\t" inside a regex is a GNU extension; [:cntrl:] is not portable in awk).
    for (i=1;i<32;i++) CTL = CTL sprintf("%c", i)
    CTL = CTL sprintf("%c", 127)
  }
  function hasctrl(s,   i, L, c) {
    L = length(s)
    for (i = 1; i <= L; i++) { c = substr(s, i, 1); if (index(CTL, c)) return 1 }
    return 0
  }
  {
    n1 = index($0, "\"name\":\""); if (!n1) next
    r = substr($0, n1+8); n2 = index(r, "\""); if (!n2) next; name = substr(r, 1, n2-1)
    t1 = index($0, "\"type\":\""); if (!t1) next
    r2 = substr($0, t1+8); t2 = index(r2, "\""); if (!t2) next; typ = substr(r2, 1, t2-1)
    # F57: a control byte in the NAME would be written into TYPE_F as a TAB and
    # break the "name TAB type" contract that the type filter reads back.
    if (w[typ] && !hasctrl(name)) print name "\t" typ
  }' > "$TYPE_F" ) &
( exec 9>&- 2>/dev/null; curl -s -m 10 -H "$AH" "$API/proxies" 2>/dev/null \
  | tr '{' '\n' | grep -o '"name":"[^"]*"' | sed 's/^"name":"//; s/"$//' \
  | grep -v '[[:cntrl:]]' | sort -u > "$GRP_F" ) &
wait
DELAY_JSON=$(cat "$DLY_F"); rm -f "$DLY_F"
if [ -z "$DELAY_JSON" ]; then
  # F30: this early exit runs between the parallel launch and the cleanup, so
  # the other two S5 temp files (TYPE_F, GRP_F) would leak in /tmp for a day.
  rm -f "$TYPE_F" "$GRP_F"; TYPE_F=""; GRP_F=""
  log "ERR screen no response, keep [$CUR] cause=SCREEN_NORESP"; save_state "$FAIL_N" "$NOW"; exit 0
fi

# parse layer 0: quote-aware top-level split, then last-colon split (v8 rules)
# layer 1: keyword junk filter (v8 rules, kept as defense in depth:
#          billing/info nodes share protocol types, keywords still needed)
# layer 2 (M5): keep only protocol-typed real nodes from providers API;
#          groups / DIRECT / REJECT are excluded by type, not by name guessing
# F39 (v9.19): the old form was
#   sed 's/"//g' | tr ',' '\n' | awk -F: '...'
# which split the body on EVERY comma, including commas inside a node name.
# "JP-01,HK-02":110 tore into `"JP-01` + `HK-02":110`, so the pool held a
# phantom node `HK-02` (and lost the real one); racing it PUTs a name that does
# not exist. Measured in sandbox D37 on v9.18 (READ_FAIL every round).
# Fix: scan the body for `"name":digits` pairs instead of splitting on commas.
# [^"]* crosses commas, so a whole quoted name is matched regardless of its
# contents; the value must be all digits, which is the same junk filter v8 had
# (null / nested objects / info text never match). The separator is the FIRST
# `":` after the opening quote, which is exactly where the name ends (a name
# carrying a raw quote is escaped as \" and then cannot match this pattern at
# all - such a name is also rejected by now_ok, so it could never be CUR).
# Verified on the router: comma name, colon name, space/bracket/rate-tag name
# all parse, and {"bad":null} / {"x":{"a":5}} emit nothing.
TYPE_N=$(grep -c . "$TYPE_F" 2>/dev/null)
TPS_ALL=$(echo "$DELAY_JSON" | awk '
  BEGIN {
    # F57 (v9.24): the control-byte set, built from sprintf("%c") because a
    # literal "\t" regex is a GNU extension and awk has no portable [:cntrl:].
    for (i=1;i<32;i++) CTL = CTL sprintf("%c", i)
    CTL = CTL sprintf("%c", 127)
  }
  function hasctrl(s,   i, L, c) {
    L = length(s)
    for (i = 1; i <= L; i++) { c = substr(s, i, 1); if (index(CTL, c)) return 1 }
    return 0
  }
  {
    s = $0
    while (match(s, /[{,][ \t]*"[^"\\]*":[0-9]+/)) {
      m = substr(s, RSTART, RLENGTH)
      s = substr(s, RSTART + RLENGTH)
      sub(/^[{,][ \t]*"/, "", m)
      p = index(m, "\":")
      if (p > 1) {
        nm = substr(m, 1, p - 1)
        dv = substr(m, p + 2)
        # F57: the output line is "delay TAB name", so a name carrying a TAB/CR
        # would inject extra fields into every downstream TAB consumer (screen,
        # RACE_RES, the score table). Such a name is dropped here, before it can
        # ever be a candidate. Measured harm without this gate: f51dbg case B.
        # The rejection is also ANNOUNCED (a marker line starting with 0x01,
        # which no valid pool line can - every real line starts with a digit -
        # so the shell can count and strip it below). A pool that silently
        # shrinks would be the same half-accounting F18 removed elsewhere.
        if (nm != "" && dv ~ /^[0-9]+$/) {
          if (hasctrl(nm)) printf "\001%s\n", nm
          else printf "%s\t%s\n", dv, nm
        }
      }
    }
  }' \
  | grep -v -e 'DIRECT' -e '自动选择' -e '其他地区' -e '建议' -e '订阅' \
            -e '官网' -e '剩余' -e '重置' -e '到期' -e '套餐' -e '：' \
            -e '倍率' -e '勿跑' -e '过期' -e '失联' )

# F57 (v9.24): count and strip the 0x01-prefixed rejection markers emitted by the
# scanner above. Done BEFORE the group/type filters so the reported number is the
# true count of bad names, and because those filters key on column 2 (a marker
# line has no TAB at all). A valid pool line always starts with a digit, so a
# 0x01 lead byte cannot collide with one.
BADNM_N=$(printf '%s\n' "$TPS_ALL" | grep -c "$(printf '\001')" )
[ -z "$BADNM_N" ] && BADNM_N=0
if [ "$BADNM_N" -gt 0 ] 2>/dev/null; then
  log "WARN dropped $BADNM_N candidate(s) whose name carries a control byte - a TAB inside a name would break every TAB-delimited column downstream (F57)"
  TPS_ALL=$(printf '%s\n' "$TPS_ALL" | grep -v "$(printf '\001')")
fi

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
RTS_LOG=$(printf '%s' "$RTS_LOG" | tr ',' '\n' | awk -v now="$NOW" -v w="$RACE_BUDGET_WIN" '$1+0>0 && $1+0<=now && now-$1<w' | tr '\n' ',' | sed 's/,$//')
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
# F56 (v9.23): a signal that lands mid-race used to exit 0. on_exit() was the
# SINGLE handler for `EXIT INT TERM HUP` and it ended with a literal `exit 0`,
# so "killed by TERM after a successful restore" was indistinguishable from
# "finished normally" on the exit-code channel. Measured with probe r7j on the
# router (5/5 runs, real race, TERM 3s after RACE start):
#     rc=0  midrace_line=1  restored_line=1  act=0
# and the same round killed BEFORE the race (the F41 arm at the lock) returns
# 130. Two different signals, two different phases, and an operator or a
# wrapper could only tell them apart by grepping the log.
# Nothing on THIS box consumed rc (crontab discards it, selfupdate gates on
# flock -n 8 not on nodeguard's status, no init.d wrapper), so this was not
# breaking anything today - but an exit code that says "all good" after the
# round was shot is a booby trap for the next consumer, and "TRAP exit
# mid-race" + rc=0 also makes a wrapper's own health math wrong.
# Fix: OE_RC carries the signal's exit status (128+N, the POSIX convention
# already used by the pre-race arm) and the EXIT arm preserves whatever the
# body returned. on_exit() is re-entry guarded because a signal arm now exits
# THROUGH the EXIT arm, so the function is entered twice per signal and the
# restore must run exactly once.
OE_RUN=0
OE_RC=0

# exit guard: never leave group on a half-tested node
on_exit(){
  # F56: second entry is the natural consequence of `exit` inside a signal arm
  # (ash re-runs the EXIT trap). The restore below must NOT run twice: a second
  # get_now/put_node pair is ~13s of traffic on a round that was told to stop,
  # and the lock is already gone by then. Just carry the code out.
  if [ "$OE_RUN" = "1" ]; then exit "$OE_RC"; fi
  OE_RUN=1
  TERM_SIG=1
  # F53 (v9.22): THE LOCK MUST OUTLIVE THE RESTORE. This function used to rmdir
  # the lock FIRST and then spend up to ~13s restoring the group (get_now -m3,
  # put_node = 2 tries x (5s+1s)). Measured on the router with probe r4r3 case
  # 5R: a TERM landed mid-race, and at t=7s - while the round was still alive
  # and still restoring - a second `mkdir $LOCK_DIR` SUCCEEDED. That is exactly
  # the double-round the lock exists to prevent: cron `*/5` can fire inside the
  # restore window, start a second round, and two rounds then drive the same
  # group. Releasing the lock is now the LAST thing this trap does, after the
  # restore attempt has finished (success or failure).
  # F52/F53b: same single scratch-file sweep the early traps use.
  ng_rm_tmp
  [ -n "$GRP_F" ] && rm -f "$GRP_F"
  if [ "$SW_DONE" != "1" ]; then
    CN=$(get_now); 
    if now_ok "$CN" && [ "$CN" != "$CUR" ]; then
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
    fi
  fi
  # F53: lock released only now, once the group state is settled.
  rmdir "$LOCK_DIR" 2>/dev/null
  # F56: block further signals for the remainder of the trap. A second TERM
  # arriving while the restore is still running used to re-enter via the signal
  # arm and (in the old code) simply exit 0 mid-restore. Now the restore body is
  # protected: the round has already decided to die, and no later signal may
  # perturb the group state it is writing.
  trap '' INT TERM HUP
  exit "$OE_RC"
}
# F56: ONE body (on_exit) but two arming paths - a normal end keeps whatever the
# body returned, a signal first records 128+N. `exit` inside the signal arm then
# enters on_exit through the EXIT arm; OE_RUN makes that second pass a no-op.
trap 'on_exit' EXIT
trap 'OE_RC=130; on_exit' INT
trap 'OE_RC=143; on_exit' TERM
trap 'OE_RC=129; on_exit' HUP

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
# F42 (v9.19): the finalist loop below is `for N in $RACE_LIST`, an UNQUOTED
# word list, so the shell applies PATHNAME EXPANSION to every word. IFS=newline
# only stops field splitting on spaces; it does NOT stop globbing. A node name
# containing '*' or a bracket expression is therefore replaced by whatever files
# happen to match it in the current directory ($RACE_RES is created in /tmp, and
# a crontab round runs with cwd=/, so the matches come from the real filesystem).
# Measured in sandbox probe p41b2 on busybox ash: with files HK1V1 and N3
# present, the list "HK*V1\nN3" yielded the word HK1V1 instead of HK*V1, and a
# bare "*" exploded into one word per file in the directory (extra words = extra
# candidates, and the real node silently vanished from the race). Real airport
# names do carry rate tags such as "1.5x" and, less often, "*" / "[" - the same
# name-assumption class as F38/F39.
# set -f turns globbing off for the whole race section; field splitting on
# newline is unchanged, so the loop still walks one name per line exactly as
# intended. Restored together with IFS below.
set -f
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
  ( exec 9>&- 2>/dev/null; google_check > "$CG_F" ) &
  ( exec 9>&- 2>/dev/null; speed_med > "$MS_F" ) &
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
# F42: restore globbing only together with IFS, i.e. after the last unquoted
# word list has been walked.
set +f
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
# F34: also clear the unstick streak - it belongs to the baseline just dropped.
# F35: written through spk_write so the timestamp matches this round.
spk_write 0
egress_trace

rm -f "$RACE_RES" "$SCORED"
save_state 0 "$NOW"
exit 0
