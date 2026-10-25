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
# Four tables per capture, then the disagreements frame by frame:
#
#   coverage     does tshark find NAS in the frames this front-end says it found?
#   message type EMM counts, keyed by the message-type octet
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

set -euo pipefail

BIN="target/debug/canary-cellular-nas"
TSHARK="${TSHARK:-tshark}"

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
  captures=("$WORK"/captures/*.pcap)
fi

# Columns, in this order, of the per-frame table tshark writes. The GSMTAP
# header fields this used to ask for (`gsmtap.version`, `gsmtap.hdr_len`) turned
# out to duplicate what the verbose print in the disagreement table already
# says, in fewer characters, so they are not extracted per frame.
TS=1 FRAME=2 EMM=3 ID_REQ=4 ID_RESP=5 PROTO=6

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
# is the set tshark's EMM field is comparable against.
canary_codes() {
  awk '$1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ {
    for (i = 1; i <= NF; i++) if ($i ~ /^emm=0x[0-9a-f][0-9a-f]$/) { sub(/^emm=/, "", $i); print $i }
  }' "$WORK/report"
}

# Events per timestamp, which is the canary side of the frame-by-frame join.
canary_events_per_ts() {
  awk '$1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ { ev[$1]++ }
     END { for (t in ev) print t "\t" ev[t] }' "$WORK/report" | sort
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
    -e _ws.col.Protocol >"$rows" 2>/dev/null

  "$BIN" "$capture" >"$WORK/report" || true

  # tshark prints nanosecond precision and a numeric zone; CANARY prints
  # microseconds and `Z`. Six digits and `Z` is enough to be the same instant.
  keys="$WORK/keys.tsv"
  awk -F'\t' -v OFS='\t' '{ $1 = substr($1, 1, 26) "Z"; print }' "$rows" >"$keys"

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

  : >"$tree_codes"
  while read -r frame; do
    # tshark names an untabled message type only in the tree, as an expert
    # warning, so the octet has to be read back out of the verbose print.
    TZ=UTC "$TSHARK" -r "$capture" -Y "frame.number==$frame" -V 2>/dev/null |
      grep -m1 -oE 'Unknown Message Type 0x[0-9a-fA-F]{2}' |
      grep -m1 -oE '0x[0-9a-fA-F]{2}' >>"$tree_codes" || true
  done < <(awk -F'\t' -v e="$EMM" -v p="$PROTO" -v f="$FRAME" '$p ~ /NAS-EPS/ && $e == "" { print $f }' "$keys")

  # --- the report's own tallies -------------------------------------------
  frames=$(awk 'END { print NR }' "$keys")
  tshark_nas=$(awk -F'\t' -v p="$PROTO" '$p ~ /NAS-EPS/ { n++ } END { print n + 0 }' "$keys")
  canary_records=$(awk '/ records read$/ { print $1 }' "$WORK/report")
  canary_events=$(awk '/ NAS events$/ { print $1 }' "$WORK/report")
  canary_malformed=$(awk '/ skipped, malformed$/ { print $1 }' "$WORK/report")
  canary_frames=$(awk '/ LTE NAS frames/ { print $1 }' "$WORK/report")

  echo
  echo "### $name"
  printf '  coverage      tshark: %s frames, %s dissected as NAS-EPS\n' "$frames" "$tshark_nas"
  printf '                canary: %s records read, %s LTE NAS frames, %s events, %s malformed\n' \
    "$canary_records" "$canary_frames" "$canary_events" "$canary_malformed"

  echo "  message type  tshark  canary"
  join -t' ' -a1 -a2 -e 0 -o '0,1.2,2.2' \
    <(cat "$field_codes" "$tree_codes" | sort | uniq -c | awk '{ print $2, $1 }' | sort -k1,1) \
    <(canary_codes | sort | uniq -c | awk '{ print $2, $1 }' | sort -k1,1) |
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
  # For each such frame, one more tshark pass asks it to describe the frame in
  # its own words, so the row carries the evidence rather than this script's
  # guess about it.
  tshark_per_ts="$WORK/tshark_per_ts"
  awk -F'\t' -v OFS='\t' -v p="$PROTO" -v e="$EMM" -v f="$FRAME" '
    {
      ts = $1
      if (!(ts in seen)) { seen[ts] = 1; order[++n] = ts; frame[ts] = $f; proto[ts] = $p }
      count[ts] += ($p ~ /NAS-EPS/)
      # The first NAS-EPS frame at this instant is the one worth naming, and its
      # message type is what the reader will want beside the disagreement. The
      # else-branch keeps this field non-empty: the table below is tab-separated
      # and `read` collapses an empty field between two tabs.
      if ($p ~ /NAS-EPS/ && detail[ts] == "") {
        detail[ts] = ($e == "" ? "nothing to dissect" : "emm=" $e)
      }
    }
    END {
      for (i = 1; i <= n; i++) {
        t = order[i]
        print t, count[t], frame[t], proto[t], (detail[t] == "" ? "not NAS-EPS" : detail[t])
      }
    }
  ' "$keys" | sort >"$tshark_per_ts"

  canary_events_per_ts >"$WORK/canary_per_ts"

  awk -F'\t' '
    NR == FNR { ev[$1] = $2; seen[$1] = 1; next }
    { nas[$1] = $2; frame[$1] = $3; proto[$1] = $4; detail[$1] = $5; seen[$1] = 1 }
    END {
      for (k in seen)
        if ((nas[k] + 0) != (ev[k] + 0))
          printf "%s\t%s\t%s\t%s\t%s\n", k, frame[k], proto[k], detail[k], (ev[k] + 0)
    }
  ' "$WORK/canary_per_ts" "$tshark_per_ts" | sort >"$WORK/disagree.tsv"

  echo "  disagreements per frame"
  if [ ! -s "$WORK/disagree.tsv" ]; then
    echo "        none"
  fi
  while IFS=$'\t' read -r ts frame_ proto_ detail_ events_; do
    # What tshark read in the frame's own headers, asked as fields rather than
    # grepped out of the tree: the GSMTAP version and header length as it
    # understood them, and whether the frame was an IP fragment. Only the
    # deviating ones are named, since a normal frame adds nothing to the row.
    # Tab-separated fields through a pipe would lose an empty middle one.
    header=$(TZ=UTC "$TSHARK" -r "$capture" -Y "frame.number==$frame_" -T fields \
      -e gsmtap.version -e gsmtap.hdr_len -e ip.fragment 2>/dev/null | head -1)
    version="${header%%$'\t'*}"
    rest="${header#*$'\t'}"
    hdr_len="${rest%%$'\t'*}"
    fragment="${rest#*$'\t'}"
    note=""
    [ -n "$version" ] && [ "$version" != "2" ] && note="$note gsmtap-version=$version"
    [ -n "$hdr_len" ] && [ "$hdr_len" != "16" ] && note="$note gsmtap-hdr_len=$hdr_len"
    [ -n "$fragment" ] && note="$note ip-fragment"
    printf '        %s  frame %-4s tshark: %-16s %-18s canary: %s event(s)%s\n' \
      "$ts" "$frame_" "$proto_" "$detail_" "$events_" "${note:+  [$note ]}"
  done <"$WORK/disagree.tsv"

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
  echo "  canary's GSMTAP payload types"
  section "GSMTAP frame types"
done
