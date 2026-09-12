#!/usr/bin/env bash
set -euo pipefail

readonly APPARMOR_RESTRICTION=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
readonly PACKAGED_PROFILE=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
readonly ACTIVE_PROFILE=/etc/apparmor.d/bwrap-userns-restrict

bwrap_smoke_probe() {
  timeout --signal=TERM --kill-after=10s 30s bwrap --unshare-net --die-with-parent --dev-bind / / -- /bin/true
}

if bwrap_smoke_probe; then
  echo 'bubblewrap network namespace smoke probe passed'
  exit 0
fi

if [[ ! -r "$APPARMOR_RESTRICTION" ]] || [[ "$(<"$APPARMOR_RESTRICTION")" != 1 ]]; then
  echo 'bubblewrap smoke probe failed without an active AppArmor unprivileged-userns restriction' >&2
  exit 1
fi

if [[ ! -f "$PACKAGED_PROFILE" ]]; then
  echo "required packaged AppArmor profile is unavailable: $PACKAGED_PROFILE" >&2
  exit 1
fi

echo "activating packaged AppArmor profile: $PACKAGED_PROFILE"
sudo timeout --signal=TERM --kill-after=10s 30s install -m 0644 "$PACKAGED_PROFILE" "$ACTIVE_PROFILE"
sudo timeout --signal=TERM --kill-after=10s 30s apparmor_parser -r "$ACTIVE_PROFILE"

# Readiness is mandatory: profile installation alone is not sufficient evidence.
bwrap_smoke_probe
