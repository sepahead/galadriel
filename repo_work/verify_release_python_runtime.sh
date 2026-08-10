#!/bin/bash -p

# Verify and launch the pinned release Python without an unverified startup gap.

set -euo pipefail

export LC_ALL=C
original_umask="$(builtin umask)"
builtin umask 077

while IFS= read -r selector; do
  case "$selector" in
    DYLD_*|LD_*|PYTHON*) unset "$selector" ;;
  esac
done < <(compgen -A variable)

runtime_root=/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14
release_python="$runtime_root/bin/python3.14"
expected_entries=4098
expected_regular_files=3765
expected_regular_bytes=83397069
expected_tree_sha256=16b62407fe5fd2d03b56abd0e5c30308a41eb84e83f53a7143d2c859f538070b
maximum_entries=5000
maximum_depth=16
maximum_regular_bytes=100663296

fail() {
  echo "release Python native preflight failed: $1" >&2
  exit 1
}

require_unlinked_parent_chain() {
  local path parent next_parent
  path=$1
  parent=${path%/*}
  test -n "$parent" || parent=/
  while :; do
    test -d "$parent" || fail "pinned native parent is unavailable"
    test ! -L "$parent" || fail "pinned native parent is a symbolic link"
    test "$parent" = / && break
    next_parent=${parent%/*}
    test -n "$next_parent" || next_parent=/
    parent=$next_parent
  done
}

native_tools='/bin/bash
/bin/rm
/usr/bin/cmp
/usr/bin/env
/usr/bin/find
/usr/bin/id
/usr/bin/mktemp
/usr/bin/openssl
/usr/bin/readlink
/usr/bin/sort
/usr/bin/stat'

while IFS= read -r tool; do
  test -n "$tool" || continue
  test -f "$tool" || fail "required operating-system tool is unavailable"
  test ! -L "$tool" || fail "required operating-system tool is a symbolic link"
  tool_identity="$(/usr/bin/stat -f '%u|%g|%Lp' "$tool")"
  tool_mode="${tool_identity##*|}"
  test "${tool_identity%|*}" = '0|0' || fail "required operating-system tool is not root-owned"
  (( (8#$tool_mode & 8#22) == 0 )) || fail "required operating-system tool is writable by another identity"
done <<< "$native_tools"

while IFS='|' read -r path expected_mode expected_size expected_sha256; do
  test -n "$path" || continue
  require_unlinked_parent_chain "$path"
  test -f "$path" || fail "pinned native file is unavailable"
  test ! -L "$path" || fail "pinned native file is a symbolic link"
  native_identity_before="$(/usr/bin/stat -f '%d|%i|%Lp|%u|%g|%z|%l|%m|%c|%HT' "$path")"
  test "$(/usr/bin/stat -f '%Lp|%z|%l|%HT' "$path")" = \
    "$expected_mode|$expected_size|1|Regular File" || \
    fail "pinned native file metadata differs"
  observed_sha256="$(/usr/bin/env -i OPENSSL_CONF=/dev/null /usr/bin/openssl dgst -sha256 -r "$path")"
  test "${observed_sha256%% *}" = "$expected_sha256" || fail "pinned native file bytes differ"
  native_identity_after="$(/usr/bin/stat -f '%d|%i|%Lp|%u|%g|%z|%l|%m|%c|%HT' "$path")"
  test "$native_identity_after" = "$native_identity_before" || \
    fail "pinned native file changed while hashed"
done <<'PINNED_NATIVE_INPUTS'
/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/bin/python3.14|755|52448|b502cb4c5b46b8d4192ec6bcb600ce8922f1afc396fcf646e8765c6eba74a0bf
/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Python|755|5454512|696ffa2cf9562522c387f7c2b3a990ef67e574df2d921822fe310ea35587cce0
/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python|755|51392|0c9a985712bb1235d8fe474a6a99810dc118bcae0dfb429a237aac0c907fa3af
/opt/homebrew/Cellar/mpdecimal/4.0.1/lib/libmpdec.4.0.1.dylib|444|188176|14286ba02244c25537b3b5c74902c5fa81959d5d2c1fcf06f89808badb67dea8
/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib|444|4856256|a12805a18cd5e4f733fa8727b91afa08b587f9da5a760517cd79cb508a3a3f71
/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libssl.3.dylib|444|872080|ffd8ac6981000def0928367924b6cb1e7a98712efbc06e2a2f3f750138bd89ca
/opt/homebrew/Cellar/sqlite/3.53.4/lib/libsqlite3.3.53.4.dylib|444|1276320|75feed7151d3e496343ffee9c25960d85188ed99b2ffb1051fe016f912c6c808
/opt/homebrew/Cellar/xz/5.8.3/lib/liblzma.5.dylib|444|184512|3d5bfa2f097c31463642b1daab5e662b44368bb4da368f85e412e7f9adcbaa10
/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib|444|649648|e2847c4613b386683c234913ae3b7b04299254096caf7616e3b3cd9bb97a39ab
PINNED_NATIVE_INPUTS

while IFS='|' read -r path expected_target; do
  test -n "$path" || continue
  require_unlinked_parent_chain "$path"
  test -L "$path" || fail "pinned native load path is not a symbolic link"
  link_identity_before="$(/usr/bin/stat -f '%d|%i|%Lp|%u|%g|%z|%l|%m|%c|%HT' "$path")"
  test "$(/usr/bin/readlink "$path")" = "$expected_target" || \
    fail "pinned native load path differs"
  link_identity_after="$(/usr/bin/stat -f '%d|%i|%Lp|%u|%g|%z|%l|%m|%c|%HT' "$path")"
  test "$link_identity_after" = "$link_identity_before" || \
    fail "pinned native load path changed while read"
done <<'PINNED_NATIVE_LINKS'
/opt/homebrew/opt/python@3.14|../Cellar/python@3.14/3.14.6
/opt/homebrew/opt/mpdecimal|../Cellar/mpdecimal/4.0.1
/opt/homebrew/opt/openssl@3|../Cellar/openssl@3/3.6.3
/opt/homebrew/opt/sqlite|../Cellar/sqlite/3.53.4
/opt/homebrew/opt/xz|../Cellar/xz/5.8.3
/opt/homebrew/opt/zstd|../Cellar/zstd/1.5.7_1
PINNED_NATIVE_LINKS

require_unlinked_parent_chain "$runtime_root"
test -d "$runtime_root" || fail "runtime root is unavailable"
test ! -L "$runtime_root" || fail "runtime root is a symbolic link"
test "$(/usr/bin/stat -f '%Lp' "$runtime_root")" = 755 || fail "runtime root mode differs"

temporary_root="$(/usr/bin/mktemp -d /private/tmp/galadriel-python-runtime.XXXXXX)"
test -d "$temporary_root" || fail "private temporary directory is unavailable"
test ! -L "$temporary_root" || fail "private temporary directory is a symbolic link"
test "$(/usr/bin/stat -f '%u|%Lp' "$temporary_root")" = "$(/usr/bin/id -u)|700" || fail "private temporary directory is unsafe"

cleanup() {
  /bin/rm -rf -- "$temporary_root"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

raw_paths="$temporary_root/paths.raw"
sorted_paths="$temporary_root/paths.sorted"
canonical_rows="$temporary_root/runtime.rows"
regular_digests="$temporary_root/regular.digests"
batch_output="$temporary_root/hash-batch.out"
metadata_raw="$temporary_root/metadata.raw"
metadata_before="$temporary_root/metadata.before"
metadata_after="$temporary_root/metadata.after"
metadata_final="$temporary_root/metadata.final"
: > "$raw_paths"
: > "$sorted_paths"
: > "$canonical_rows"
: > "$regular_digests"
: > "$batch_output"
: > "$metadata_raw"
: > "$metadata_before"
: > "$metadata_after"
: > "$metadata_final"

/usr/bin/find -x "$runtime_root" -print0 > "$raw_paths"

entries=0
while IFS= read -r -d '' path; do
  case "$path" in
    *$'\n'*|*$'\r'*|*$'\t'*|*'|'*|*\\*) fail "runtime path contains an unsafe character" ;;
  esac
  relative="${path#"$runtime_root"}"
  relative="${relative#/}"
  separators="${relative//[!\/]/}"
  depth=0
  if test -n "$relative"; then
    depth=$(( ${#separators} + 1 ))
  fi
  (( depth <= maximum_depth )) || fail "runtime tree exceeds its depth bound"
  entries=$(( entries + 1 ))
  (( entries <= maximum_entries )) || fail "runtime tree exceeds its entry bound"
  printf '%s\n' "$path" >> "$sorted_paths"
done < "$raw_paths"

test "$entries" -eq "$expected_entries" || fail "runtime tree entry count differs"
/usr/bin/sort -o "$sorted_paths" "$sorted_paths"

capture_runtime_metadata() {
  local destination=$1
  : > "$metadata_raw"
  /usr/bin/find -x "$runtime_root" -exec \
    /usr/bin/stat -f '%N|%d|%i|%Lp|%u|%g|%z|%l|%m|%c|%HT' {} + \
    > "$metadata_raw"
  /usr/bin/sort -t '|' -k 1,1 -o "$destination" "$metadata_raw"
}

batch_paths=()

flush_hash_batch() {
  local count index line digest expected_line
  count=${#batch_paths[@]}
  (( count > 0 )) || return
  : > "$batch_output"
  /usr/bin/env -i OPENSSL_CONF=/dev/null /usr/bin/openssl dgst -sha256 -r \
    "${batch_paths[@]}" > "$batch_output"
  index=0
  while IFS= read -r line; do
    (( index < count )) || fail "runtime hash batch emitted an extra row"
    digest="${line%% *}"
    case "$digest" in
      ''|*[!0-9a-f]*) fail "runtime regular file digest is malformed" ;;
    esac
    test "${#digest}" -eq 64 || fail "runtime regular file digest is malformed"
    expected_line="$digest *${batch_paths[$index]}"
    test "$line" = "$expected_line" || fail "runtime hash batch path differs"
    printf '%s\n' "$digest" >> "$regular_digests"
    index=$(( index + 1 ))
  done < "$batch_output"
  test "$index" -eq "$count" || fail "runtime hash batch omitted a row"
  batch_paths=()
}

capture_runtime_metadata "$metadata_before"
exec 5< "$metadata_before"
while IFS= read -r path; do
  IFS='|' read -r metadata_path _device _inode mode _uid _gid size links _mtime _ctime kind <&5 || \
    fail "runtime metadata inventory ended early"
  test "$metadata_path" = "$path" || fail "runtime metadata path differs"
  (( (8#$mode & 8#22) == 0 )) || fail "runtime entry is writable by another identity"
  case "$kind" in
    'Regular File')
      test "$links" -eq 1 || fail "runtime regular file has multiple hard links"
      batch_paths+=("$path")
      if (( ${#batch_paths[@]} == 128 )); then
        flush_hash_batch
      fi
      ;;
    'Directory'|'Symbolic Link') ;;
    *) fail "runtime tree contains a special file" ;;
  esac
done < "$sorted_paths"
if IFS= read -r _extra_metadata <&5; then
  fail "runtime metadata inventory contains an extra row"
fi
exec 5<&-
flush_hash_batch

capture_runtime_metadata "$metadata_after"
/usr/bin/cmp -s "$metadata_before" "$metadata_after" || fail "runtime tree changed while hashed"

exec 3< "$regular_digests"
exec 5< "$metadata_after"
regular_files=0
regular_bytes=0
while IFS= read -r path; do
  IFS='|' read -r metadata_path _device _inode mode _uid _gid size links _mtime _ctime kind <&5 || \
    fail "runtime metadata inventory ended early"
  test "$metadata_path" = "$path" || fail "runtime metadata path differs"
  relative="${path#"$runtime_root"}"
  relative="${relative#/}"
  relative_length="${#relative}"
  case "$kind" in
    'Symbolic Link')
      target="$(/usr/bin/readlink "$path")"
      case "$target" in
        ''|/*|*$'\n'*|*$'\r'*|*$'\t'*|*'|'*) fail "runtime link target is unsafe" ;;
      esac
      printf 'L|%s|%s:%s|%s:%s\n' \
        "$mode" "$relative_length" "$relative" "${#target}" "$target" >> "$canonical_rows"
      ;;
    'Directory')
      printf 'D|%s|%s:%s\n' "$mode" "$relative_length" "$relative" >> "$canonical_rows"
      ;;
    'Regular File')
      IFS= read -r digest <&3 || fail "runtime digest inventory ended early"
      test "$links" -eq 1 || fail "runtime regular file has multiple hard links"
      regular_bytes=$(( regular_bytes + size ))
      (( regular_bytes <= maximum_regular_bytes )) || fail "runtime tree exceeds its byte bound"
      printf 'F|%s|%s|%s|%s:%s\n' \
        "$mode" "$size" "$digest" "$relative_length" "$relative" >> "$canonical_rows"
      regular_files=$(( regular_files + 1 ))
      ;;
    *) fail "runtime tree contains a special file" ;;
  esac
done < "$sorted_paths"

if IFS= read -r _extra_digest <&3 || IFS= read -r _extra_metadata <&5; then
  fail "runtime inventory contains an extra row"
fi
exec 3<&-
exec 5<&-

capture_runtime_metadata "$metadata_final"
/usr/bin/cmp -s "$metadata_after" "$metadata_final" || fail "runtime tree changed during verification"

test "$regular_files" -eq "$expected_regular_files" || fail "runtime regular-file count differs"
test "$regular_bytes" -eq "$expected_regular_bytes" || fail "runtime regular-byte count differs"
tree_digest_line="$(/usr/bin/env -i OPENSSL_CONF=/dev/null /usr/bin/openssl dgst -sha256 -r "$canonical_rows")"
observed_tree_sha256="${tree_digest_line%% *}"
test "$observed_tree_sha256" = "$expected_tree_sha256" || \
  fail "runtime tree digest differs: $observed_tree_sha256"

if (( $# == 0 )); then
  exit 0
fi
case "$-" in
  *p*) ;;
  *) fail "launch mode requires privileged Bash startup" ;;
esac
if (( $# >= 3 )) && test "$1" = -E && test "$2" = -s && test "$3" = -S; then
  shift 3
fi
(( $# > 0 )) || fail "launch mode requires a Python command"
cleanup
trap - EXIT
builtin umask "$original_umask"
builtin exec "$release_python" -E -s -S "$@"
