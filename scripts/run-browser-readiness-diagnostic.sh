#!/usr/bin/env bash
set -euo pipefail

readonly LABEL='CANARY-FREE browser readiness diagnostic'
readonly WORK_ROOT="${RUNNER_TEMP:-/tmp}"
readonly READINESS_LOG="$(mktemp "${WORK_ROOT}/smesh-browser-readiness-log.XXXXXX")"
readonly KERNEL_LOG="$(mktemp "${WORK_ROOT}/smesh-browser-kernel-log.XXXXXX")"
trap 'rm -f "$READINESS_LOG" "$KERNEL_LOG"' EXIT

start_epoch=$(date +%s)
set +e
timeout --signal=TERM --kill-after=5s 25s \
  bwrap --unshare-net --die-with-parent --dev-bind / / --proc /proc -- \
  node demo/operational-browser-readiness.mjs 2>&1 | tee "$READINESS_LOG"
status=${PIPESTATUS[0]}
set -e

if [[ "$status" -eq 0 ]]; then
  exit 0
fi

# This failure branch runs before returning the readiness status. It emits only
# fixed runner authority and allowlisted AppArmor network-denial fields.
echo "[$LABEL] runner_kernel=$(uname -r)"
readarray -t browser_authority < <(node demo/filter-apparmor-denials.mjs --authority "$READINESS_LOG")
browser_pid=${browser_authority[0]:-}
browser_apparmor_label=${browser_authority[1]:-}

if [[ ! "$browser_pid" =~ ^[1-9][0-9]*$ ]] || [[ -z "$browser_apparmor_label" ]]; then
  echo "[$LABEL] browser AppArmor authority unavailable; no valid browser PID was emitted"
  exit "$status"
fi

kernel_source=journalctl
if ! sudo timeout --signal=TERM --kill-after=5s 10s \
  journalctl --dmesg --since "@${start_epoch}" --no-pager --output=cat >"$KERNEL_LOG" 2>/dev/null; then
  kernel_source=dmesg
  if ! sudo timeout --signal=TERM --kill-after=5s 10s \
    dmesg --color=never >"$KERNEL_LOG" 2>/dev/null; then
    kernel_source=unavailable
    : >"$KERNEL_LOG"
  fi
fi

echo "[$LABEL] kernel_audit_source=$kernel_source browser_pid=$browser_pid class=net"
denials=$(node demo/filter-apparmor-denials.mjs "$browser_pid" "$browser_apparmor_label" <"$KERNEL_LOG")
if [[ -n "$denials" ]]; then
  printf '%s\n' "$denials"
else
  echo "[$LABEL] APPARMOR_DENIAL none matched browser_pid=$browser_pid class=net"
fi

exit "$status"
