#!/usr/bin/env bash
# Compare canary-cellular-nas's counts against tshark's, on the same captures.
#
#   scripts/oracle_compare.sh [CAPTURE ...]
#
# With no arguments the synthetic captures from scripts/gen_gsmtap_pcap.py are
# written to a temporary directory and each one is compared.
#
# Why tshark is the oracle and not the spec: the spec says what a network may
# send, and only Wireshark's dissector says what a tool that has read real
# captures concludes from those bytes. Comparing against it turns "I read the
# offsets correctly" into a measurement. Where the two disagree, this script
# prints which byte one of them looked at and the other refused, and does not
# decide who won.
#
# Tables per capture, then the disagreements frame by frame:
#
#   coverage     does tshark find NAS in the frames this front-end says it found?
#   message type EMM counts, keyed by the message-type octet
#   discriminator ESM counts, keyed by the protocol discriminator: what tshark
#                named a session-management message against what CANARY called
#                a non-EMM one
#   security     the header-type nibble, counted on both sides over the frames
#                this front-end opens, because the two do not agree on when that
#                nibble means a security header at all
#   identity     identity-type counts, requests and responses apart because
#                tshark reads them from two different places in the message
#   disagreements  same instant on both sides, counts not equal
#
# Everything is compared as a multiset of per-frame values joined on the frame's
# own timestamp, so an aggregate on either side that happens to look right can
# still be caught: two errors of opposite sign do not cancel here.
#
# The join needs tshark to print the instant the way the record states it, and
# `-t ad` prints local time, so TZ=UTC is set for the calls that produce the
# join key: PCAP times are UTC seconds since the epoch and canary-cellular-nas
# prints them with a trailing `Z`. Frame timestamps from the file are read in
# file order; sorting them here only orders the output.
#
# Two passes over the capture, whatever its size: one field extraction over
# every frame, and one verbose print restricted to the frames whose EMM field
# came back empty. A 60k-frame capture costs the same as a 39-frame one. There
# used to be a tshark call per interesting frame, for the same two questions,
# and on a real capture the 1822 frames with an empty EMM field made that about
# forty minutes of re-reading the file — tshark re-dissects the whole capture to
# answer `-Y frame.number==N`, so each call is a full pass, not a seek.
#
# The divergences this found, and the ones it exists to explain:
#
#   1. A protected container's inner header. GSMTAP's subtype says protected and
#      tshark dissects the payload anyway, reporting the message type its
#      dissector reads out of bytes this stage refuses to interpret. tshark's
#      count is higher; CANARY's `sht=` event is the honest one, because without
#      the keys those bytes are ciphertext.
#   2. A message type Wireshark's table has no name for: it prints the octet in
#      the tree ("Unknown Message Type 0x40") and leaves the field empty, so a
#      bare field extraction silently drops the frame. Reading the octet back out
#      of the tree is what makes the message table complete.
#   3. A NAS PDU that is empty, or one octet long: tshark has nothing to dissect
#      and still calls the frame NAS-EPS, while this front-end counts it as
#      malformed. Both are statements about the same bytes.
#   4. A header tshark accepts and this front-end does not: a GSMTAP `hdr_len`
#      below the 16 octets the header has always had, and a fragment offset that
#      means the NAS PDU is not whole. tshark's dissector reads the message where
#      these are refused, so the disagreement table shows both verdicts.
#   5. ESM. A NAS PDU whose protocol discriminator is not EMM has no EMM message
#      type, and tshark's EMM field for it is whatever its dissector tried next.
#      tshark names the ESM message in its own field, so the discriminator table
#      can compare the two statements instead of letting them cancel out in the
#      per-frame counts.
#   6. NAS inside RRC. A GSMTAP frame whose payload type is LTE_RRC can carry a
#      NAS PDU inside the RRC message, and tshark dissects through the RRC layer
#      to name it. This front-end stops at the payload type: it counts the frame
#      as RRC and never reads the NAS inside it, because decoding the RRC layer
#      is ASN.1 with UPER encoding and a different piece of work. So tshark
#      calls more frames NAS-EPS than CANARY reports events, by the number of
#      frames whose GSMTAP payload type is 0x0d; the disagreement table names
#      those rows `gsmtap type 13` rather than counting them as a mismatch.
#
# The disagreement table is the one that grows with the capture, so past a few
# dozen frames it prints each distinct shape once with how many frames had it
# instead of a row per frame. ORACLE_DETAIL=1 prints every frame anyway.

set -euo pipefail

BIN="target/debug/canary-cellular-nas"
TSHARK="${TSHARK:-tshark}"
# How many disagreement rows to print before collapsing them into shapes.
ROW_CAP="${ORACLE_ROW_CAP:-25}"

if ! command -v "$TSHARK" >/dev/null 2>&1; then
  echo "error: tshark not found. Install Wireshark, or set TSHARK=/path/to/tshark." >&2
  exit 1
fi

cargo build --quiet --bin canary-cellular-nas

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ "$#" -gt 0 ]; then
  captures=("$@")
else
  python3 scripts/gen_gsmtap_pcap.py --outdir "$WORK/captures" >/dev/null
  # A pattern that matches nothing has to disappear, not be counted as a file:
  # the generator writes `.pcap` today, and an unexpanded `*.pcapng` here is a
  # capture name that tshark cannot open.
  shopt -s nullglob
  captures=("$WORK"/captures/*.pcap "$WORK"/captures/*.pcapng)
  shopt -u nullglob
fi

# Columns, in this order, of the per-frame table tshark writes. The GSMTAP
# header fields (`gsmtap.version`, `gsmtap.hdr_len`, `gsmtap.type`) and the
# fragment flag are read here rather than re-asked per frame, because the only
# thing that needs them is the disagreement table, and that table needs them for
# every frame it names: per-frame it was one pass over the capture per row.
TS=1 FRAME=2 EMM=3 ID_REQ=4 ID_RESP=5 PROTO=6 GTYPE=7 GVER=8 GHDR=9 FRAG=10 ESM=11 SHT=12

# The frames whose EMM field is empty are the ones the field extraction cannot
# answer for, and they are selected here rather than one at a time. `nas-eps`
# and `nas_eps` are both the name of the protocol; the hyphenated spelling of
# the field resolves but carries no value in this build, so every field below is
# the underscored one that the packet list actually shows.
NAS_WITHOUT_EMM_FIELD='nas-eps && !nas_eps.nas_msg_emm_type'

# The identity-type codes and the labels CANARY gives them, spelled out here so
# that a rename in the model shows up as a row reading "differs" rather than as a
# silent gap. Codes 0 and 5-7 are unassigned in TS 24.301 and are named for their
# number, not guessed at.
label_for_code() {
  case "$1" in
    1) echo "IMSI" ;;
    2) echo "IMEI" ;;
    3) echo "IMEISV" ;;
    4) echo "TMSI" ;;
    *) echo "Unknown($1)" ;;
  esac
}

# How many events CANARY reported with this label, read out of its own "by
# message kind" table: the sum of the rows whose label ends in `(LABEL)` and
# whose kind is `Identity Request` or `Identity Response` as asked. Matching the
# tail rather than a word keeps `IMEI` from counting `IMEISV`.
count_label() {
  awk -v want="($2)" -v kind="$1" '
    $1 ~ /^[0-9]+$/ && $2 == "Identity" && $3 == kind {
      if (substr($0, length($0) - length(want) + 1) == want) total += $1
    }
    END { print total + 0 }
  ' "$WORK/report"
}

# CANARY's own per-event lines are what gets compared, not the library's internal
# counters: the report a person reads is the thing that has to be right. Both of
# these read that report. An event line is
#   <timestamp> <field> <label words...> len=<n>
# and the field is `emm=0xNN` exactly when the message is a plain EMM one, which
# is the set tshark's EMM field is comparable against. `pd=0xNN` is the same
# statement about a message whose discriminator is not EMM, and is comparable
# against the octet tshark named in its ESM field.
canary_codes() {
  awk -v prefix="$1" '$1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ {
    for (i = 1; i <= NF; i++)
      if ($i ~ "^" prefix "=0x[0-9a-f][0-9a-f]$") { sub(/^.*=/, "", $i); print tolower($i) }
  }' "$WORK/report"
}

# Events per timestamp, which is the canary side of the frame-by-frame join.
canary_events_per_ts() {
  awk '$1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ { ev[$1]++ }
     END { for (t in ev) print t "\t" ev[t] }' "$WORK/report" | sort
}

# The security header types CANARY reported, one line per event. Decimal, as the
# event line spells it, which is how tshark prints the field too.
canary_shts() {
  awk '$1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ {
    for (i = 1; i <= NF; i++) if ($i ~ /^sht=[0-9]+$/) { sub(/^sht=/, "", $i); print $i }
  }' "$WORK/report"
}

printf '%s\n' "comparing ${#captures[@]} capture(s) against $("$TSHARK" --version 2>/dev/null | head -1)"

for capture in "${captures[@]}"; do
  name=$(basename "$capture")
  rows="$WORK/rows.tsv"

  TZ=UTC "$TSHARK" -r "$capture" -T fields -t ad \
    -e frame.time \
    -e frame.number \
    -e nas_eps.nas_msg_emm_type \
    -e nas_eps.emm.id_type2 \
    -e gsm_a.ie.mobileid.type \
    -e _ws.col.Protocol \
    -e gsmtap.type \
    -e gsmtap.version \
    -e gsmtap.hdr_len \
    -e ip.fragment \
    -e nas_eps.nas_msg_esm_type \
    -e nas_eps.security_header_type >"$rows" 2>/dev/null

  "$BIN" "$capture" >"$WORK/report" || true

  # tshark prints nanosecond precision and a numeric zone; CANARY prints
  # microseconds and `Z`. Six digits and `Z` is enough to be the same instant.
  keys="$WORK/keys.tsv"
  awk -F'\t' -v OFS='\t' -v ts="$TS" '{ $ts = substr($ts, 1, 26) "Z"; print }' "$rows" >"$keys"

  # --- message types -------------------------------------------------------
  # Only frames tshark itself called NAS-EPS are asked for a message type: a
  # frame it never dissected has an empty field for a reason that is not a
  # disagreement about NAS, and counting it would blame the front-end for
  # traffic it correctly skipped.
  field_codes="$WORK/field_codes"
  tree_codes="$WORK/tree_codes"
  awk -F'\t' -v e="$EMM" -v p="$PROTO" '$p ~ /NAS-EPS/ && $e != "" {
    code = $e; sub(/^0x/, "", code); print "0x" tolower(code)
  }' "$keys" >"$field_codes"

  # tshark names an untabled message type only in the tree, as an expert
  # warning, so the octet has to be read back out of the verbose print. One
  # filtered pass for all of them: the print starts a frame with `Frame N: ...`,
  # so the octet can be attributed without re-reading the capture per frame, and
  # only the first line of a frame counts because the same text appears again in
  # the expert-info item below it.
  TZ=UTC "$TSHARK" -r "$capture" -Y "$NAS_WITHOUT_EMM_FIELD" -O nas-eps 2>/dev/null |
    awk '
      /^Frame [0-9]+:/ {
        frame = substr($2, 1, length($2) - 1)
        next
      }
      {
        if (match($0, /Unknown Message Type 0x[0-9a-fA-F][0-9a-fA-F]/) && !(frame in said)) {
          said[frame] = 1
          print tolower(substr($0, RSTART + 21, 4))
        }
      }
    ' >"$tree_codes"

  # --- the report's own tallies -------------------------------------------
  frames=$(awk 'END { print NR }' "$keys")
  tshark_nas=$(awk -F'\t' -v p="$PROTO" '$p ~ /NAS-EPS/ { n++ } END { print n + 0 }' "$keys")
  # How many of tshark's NAS-EPS frames are NAS inside an RRC message: the frames
  # this front-end names by payload type as RRC and never opens. Stating it here
  # is what makes the coverage gap a count rather than a mystery.
  tshark_nas_rrc=$(awk -F'\t' -v p="$PROTO" -v g="$GTYPE" '$p ~ /NAS-EPS/ && $g != 18 { n++ } END { print n + 0 }' "$keys")
  canary_records=$(awk '/ records read$/ { print $1 }' "$WORK/report")
  canary_events=$(awk '/ NAS events$/ { print $1 }' "$WORK/report")
  canary_malformed=$(awk '/ skipped, malformed$/ { print $1 }' "$WORK/report")
  canary_frames=$(awk '/ LTE NAS frames/ { print $1 }' "$WORK/report")

  echo
  echo "### $name"
  printf '  coverage      tshark: %s frames, %s dissected as NAS-EPS\n' "$frames" "$tshark_nas"
  printf '                canary: %s records read, %s LTE NAS frames, %s events, %s malformed\n' \
    "$canary_records" "$canary_frames" "$canary_events" "$canary_malformed"
  if [ "$tshark_nas_rrc" -gt 0 ]; then
    printf '                %s frame(s) of those NAS-EPS are NAS inside an RRC message (GSMTAP type 0x0d), which this front-end stops at\n' \
      "$tshark_nas_rrc"
  fi

  echo "  message type  tshark  canary"
  join -t' ' -a1 -a2 -e 0 -o '0,1.2,2.2' \
    <(cat "$field_codes" "$tree_codes" | sort | uniq -c | awk '{ print $2, $1 }' | sort -k1,1) \
    <(canary_codes emm | sort | uniq -c | awk '{ print $2, $1 }' | sort -k1,1) |
    while read -r code t c; do
      marker=""
      [ "$t" != "$c" ] && marker="   <- differs"
      printf '        %-6s %6s %6s%s\n' "$code" "$t" "$c" "$marker"
    done

  named=$(awk 'END { print NR }' "$field_codes")
  empty=$(awk -F'\t' -v e="$EMM" -v p="$PROTO" '$p ~ /NAS-EPS/ && $e == "" { n++ } END { print n + 0 }' "$keys")
  recovered=$(awk 'END { print NR }' "$tree_codes")
  printf '  of %s NAS-EPS frame(s) tshark named %s in the message-type field and left %s empty; %s of those printed the octet in the tree as unknown, %s named nothing\n' \
    "$tshark_nas" "$named" "$empty" "$recovered" "$((empty - recovered))"

  # --- protocol discriminators ---------------------------------------------
  # The non-EMM half of the same comparison. tshark has no field for the
  # discriminator itself, only for the session-management message it named out of
  # one, so its side of the `pd=0x02` row is the number of frames where that field
  # came back, against CANARY's events that say the discriminator nibble is 0x02.
  # Without this row the two statements cancel each other in the per-frame table:
  # a frame CANARY calls non-EMM and a frame tshark calls ESM are both one NAS
  # frame at one instant, and only the vocabulary differs — or one of them is
  # wrong about the nibble.
  echo "  discriminator  tshark  canary"
  awk -F'\t' -v p="$PROTO" -v x="$ESM" -v g="$GTYPE" '
    $p ~ /NAS-EPS/ && $x != "" {
      n++
      codes[tolower($x)]++
      # A frame whose GSMTAP payload type is not LTE NAS is NAS inside something
      # else, and CANARY never reads past the payload type to find it.
      if ($g != "" && $g != 18) rrc++
    }
    END {
      kinds = 0
      for (k in codes) kinds++
      print n + 0, rrc + 0, kinds
    }
  ' "$keys" >"$WORK/esm_totals"
  read -r esm_total esm_rrc esm_kinds <"$WORK/esm_totals"
  canary_codes pd | sort | uniq -c | awk -v t="$esm_total" '
    { canary[$2] += $1 }
    END {
      two = canary["0x02"] + 0
      if (t != 0 || two != 0)
        printf "        %-9s %6s %6s%s\n", "pd=0x02", t, two, (two == t ? "" : "   <- differs")
      for (k in canary)
        if (k != "0x02")
          printf "        %-9s %6s %6s   no field names this discriminator\n", "pd=" k, "-", canary[k]
    }
  '
  printf '  tshark named an ESM message in %s frame(s) across %s message code(s); %s frame(s) of those carry it inside RRC (GSMTAP type 0x0d), which this front-end does not read past\n' \
    "$esm_total" "$esm_kinds" "$esm_rrc"

  # --- security header types -------------------------------------------------
  # The container-level claim, counted on both sides, over the frames this
  # front-end actually opens: GSMTAP payload type 18. A row where one side has
  # events and the other has none is a nibble the two read as different things,
  # which the per-frame counts cannot show because both sides still found one NAS
  # frame at that instant. Type 0 is left out: a plain message is named by its
  # message type or its discriminator, never as `sht=0`.
  echo "  security header type  tshark  canary"
  # One tagged file rather than two inputs to one awk: `NR == FNR` decides which
  # file a line came from by position, and says the second file is the first when
  # the first one turned out to be empty, which is exactly when a mix-up would go
  # unnoticed.
  awk -F'\t' -v p="$PROTO" -v g="$GTYPE" -v s="$SHT" '
    $p ~ /NAS-EPS/ && $g == 18 && $s != "" && $s+0 != 0 { print $s }
  ' "$keys" | sort -n | uniq -c | awk '{ print "t", $2, $1 }' >"$WORK/sht_counts"
  canary_shts | sort -n | uniq -c | awk '{ print "c", $2, $1 }' >>"$WORK/sht_counts"
  awk '
    $1 == "t" { tshark[$2] = $3; seen[$2] = 1; t_total += $3; next }
    $1 == "c" { canary[$2] += $3; seen[$2] = 1; c_total += $3; next }
    END {
      for (k = 1; k <= 15; k++)
        if (k in seen)
          printf "        %-6s %6s %6s%s\n", k, tshark[k] + 0, canary[k] + 0,
            (tshark[k] + 0 == canary[k] + 0 ? "" : "   <- differs")
      printf "  of the LTE NAS frames tshark dissected, %d carried a security header type in the message and canary reported %d events with one\n",
        t_total + 0, c_total + 0
    }
  ' "$WORK/sht_counts"

  # --- identity types ------------------------------------------------------
  # A request carries the type in a fixed nibble and a response inside the Mobile
  # Identity IE, so tshark has a field for each. One table per direction: a
  # merged table would hide a rule applied to the wrong message.
  for direction in Request Response; do
    case $direction in
      Request) column="$ID_REQ" ;;
      Response) column="$ID_RESP" ;;
    esac
    echo "  identity type ($direction)  tshark  canary"
    while read -r code count; do
      label=$(label_for_code "$code")
      got=$(count_label "$direction" "$label")
      marker=""
      [ "$got" != "$count" ] && marker="   <- differs"
      printf '        %8s %6s %6s  %s%s\n' "$code" "$count" "$got" "$label" "$marker"
    done < <(
      awk -F'\t' -v c="$column" '$c != "" { print $c }' "$keys" |
        sort -n | uniq -c | awk '{ print $2, $1 }'
    )
  done

  # --- frame by frame ------------------------------------------------------
  # Every instant where one tool found a NAS message and the other did not. This
  # is the table that catches a front-end skipping a frame it should not, which
  # no aggregate can: two matching totals made of different frames agree.
  #
  # What the frame said about itself comes out of the same pass that produced the
  # counts, so naming it costs nothing: the GSMTAP version and header length as
  # tshark understood them, whether the frame was an IP fragment, and whether the
  # payload type was NAS at all. Only the deviating ones are named, since a
  # normal frame adds nothing to the row.
  tshark_per_ts="$WORK/tshark_per_ts"
  awk -F'\t' -v OFS='\t' -v p="$PROTO" -v e="$EMM" -v f="$FRAME" -v g="$GTYPE" \
    -v v="$GVER" -v h="$GHDR" -v r="$FRAG" -v x="$ESM" '
    function append(cur, piece) { return cur (cur == "" ? "" : " ") piece }
    {
      ts = $1
      # The first frame at an instant is what the row names when tshark found no
      # NAS in it; once one is found, the row names that frame instead, since a
      # frame tshark never dissected is not the disagreement about NAS.
      if (!(ts in seen)) { seen[ts] = 1; order[++n] = ts; frame[ts] = $f; proto[ts] = $p }
      count[ts] += ($p ~ /NAS-EPS/)
      if ($p ~ /NAS-EPS/ && detail[ts] == "") {
        frame[ts] = $f
        proto[ts] = $p
        detail[ts] = ($e != "" ? "emm=" $e : ($x != "" ? "esm=" $x : "nothing to dissect"))
        if ($v != "" && $v != 2) note[ts] = append(note[ts], "gsmtap-version=" $v)
        if ($h != "" && $h != 16) note[ts] = append(note[ts], "gsmtap-hdr_len=" $h)
        # The GSMTAP payload type 0x12 is the one this front-end reads NAS out
        # of; any other is a statement about the frame that the counts cannot show.
        if ($g != "" && $g != 18) note[ts] = append(note[ts], "gsmtap type " $g)
        if ($r != "") note[ts] = append(note[ts], "ip-fragment")
      }
    }
    END {
      for (i = 1; i <= n; i++) {
        t = order[i]
        print t, count[t], frame[t], proto[t], (detail[t] == "" ? "not NAS-EPS" : detail[t]),
          (note[t] == "" ? "-" : note[t])
      }
    }
  ' "$keys" | sort >"$tshark_per_ts"

  canary_events_per_ts >"$WORK/canary_per_ts"

  awk -F'\t' '
    # Which side a line came from is told by how many fields it has, not by
    # whether `NR == FNR` happened to hold: with one of these files empty, that
    # test reads the second file as if it were the first, and the disagreement
    # then comes out as a one-sided count instead of a mismatched pair.
    NF == 2 { ev[$1] = $2; seen[$1] = 1; next }
    {
      nas[$1] = $2; frame[$1] = $3; proto[$1] = $4; detail[$1] = $5; note[$1] = $6; seen[$1] = 1
    }
    END {
      for (k in seen)
        if ((nas[k] + 0) != (ev[k] + 0))
          # The note column is "-" when the frame looked ordinary: `read` with a
          # tab separator collapses an empty field between two others, and every
          # column after it would land one to the left.
          printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", k, frame[k], proto[k], detail[k],
            (note[k] == "" ? "-" : note[k]), (ev[k] + 0), (nas[k] + 0)
    }
  ' "$WORK/canary_per_ts" "$tshark_per_ts" | sort >"$WORK/disagree.tsv"

  rows=$(awk 'END { print NR }' "$WORK/disagree.tsv")
  echo "  disagreements per frame"
  if [ "$rows" -eq 0 ]; then
    echo "        none"
  elif [ "$rows" -le "$ROW_CAP" ] || [ "${ORACLE_DETAIL:-}" = "1" ]; then
    [ "$rows" -gt "$ROW_CAP" ] &&
      printf '        %s frame(s), every one listed\n' "$rows"
    while IFS=$'\t' read -r ts frame_ proto_ detail_ note_ events_ nasframes_; do
      [ "$note_" = "-" ] && note_=""
      printf '        %s  frame %-4s tshark: %-16s %-18s canary: %s event(s) vs %s frame(s)%s\n' \
        "$ts" "$frame_" "$proto_" "$detail_" "$events_" "$nasframes_" "${note_:+  [ $note_ ]}"
    done <"$WORK/disagree.tsv"
  else
    # Past a few dozen rows the list is one story told many times, so it is
    # collapsed by shape: the same protocol column, the same kind of thing
    # tshark found, the same header the frame presented, the same two counts. The
    # octet in the message type is a detail of the shape, not part of it, so it
    # becomes `emm=...` and the message-type table above stays the place where
    # the individual octets are counted.
    printf '        %s frame(s) differ, in these shapes (most frequent first, one example each)\n' "$rows"
    # Two stages because the groups have to be sorted by size: the first counts
    # them, the second formats, so nothing here has to re-read a formatted line.
    awk -F'\t' '
      {
        d = $4
        sub(/=0x[0-9a-fA-F][0-9a-fA-F]$/, "=...", d)
        key = $3 "\t" d "\t" $5 "\t" $6 "\t" $7
        n[key]++
        if (!(key in first)) first[key] = $1 "  frame " $2 "  " $4
      }
      END { for (k in n) print n[k] "\t" k "\t" first[k] }
    ' "$WORK/disagree.tsv" | sort -t"$(printf '\t')" -k1,1nr -k2,2 |
      awk -F'\t' '{
        note = ($4 == "-" ? "" : "  [ " $4 " ]")
        printf "        %6sx  tshark: %-16s %-18s canary: %s event(s) vs %s frame(s)%s\n",
          $1, $2, $3, $5, $6, note
        printf "              e.g. %s\n", $7
      }'
    printf '        ORACLE_DETAIL=1 lists every frame instead of the shapes\n'
  fi

  # --- what CANARY made of the container, which tshark has no reason to agree
  # with, but which has to say something true about a capture full of skips.
  # Reproduced from the report rather than re-derived, so that these numbers are
  # the ones the tool actually printed. `section` prints the lines under one
  # heading and stops at the next, because both tables are at the tail.
  section() {
    awk -v want="== $1 ==" '
      $0 == want { in_section = 1; next }
      /^== / { in_section = 0 }
      in_section && NF { count = $1; $1 = ""; sub(/^ /, ""); print "        " count "  " $0 }
    ' "$WORK/report"
  }

  echo "  canary's stream tallies"
  section stream
  echo "  canary's container, as read"
  section container
  echo "  canary's GSMTAP payload types"
  section "GSMTAP frame types"
done
