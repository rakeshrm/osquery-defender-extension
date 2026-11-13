#!/usr/bin/env bash
# Multi-day soak test of a released extension on GCE Windows Server VMs.
#
#   PROJECT=p ZONE=europe-west2-a SUBNET=s [VERSION=v0.1.0] scripts/soak/gce-soak.sh start
#   scripts/soak/gce-soak.sh status     # progress from the serial console + last upload
#   scripts/soak/gce-soak.sh collect    # download latest results and analyze
#   scripts/soak/gce-soak.sh teardown   # delete VMs, bucket, service account
#
# Each VM runs osqueryd as a service with the extension autoloaded (extensions
# watchdog on), the pack scheduled at <=5 min intervals, hourly Defender
# activity, and uploads results every 30 min. VMs have no external IP (the
# subnet needs Cloud NAT). State is kept in scripts/soak/.soak-state.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="$HERE/.soak-state"
REPO="${REPO:-rakeshrm/osquery-defender-extension}"
IMAGES=(windows-2022 windows-2025)

cmd="${1:-}"
case "$cmd" in
start)
  : "${PROJECT:?set PROJECT}" "${ZONE:?set ZONE}" "${SUBNET:?set SUBNET}"
  [ -e "$STATE" ] && { echo "a soak is already recorded in $STATE; run teardown first"; exit 1; }
  VERSION="${VERSION:-$(gh release view -R "$REPO" --json tagName --jq .tagName)}"
  SUFFIX="$(openssl rand -hex 3)"
  BUCKET="osqdef-soak-$SUFFIX" SA="osqdef-soak-$SUFFIX"
  SA_EMAIL="$SA@$PROJECT.iam.gserviceaccount.com"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

  echo "release $VERSION"
  gh release download "$VERSION" -R "$REPO" -D "$TMP" \
    -p 'defender-mpengine-windows-amd64.ext.exe' -p 'defender_mpengine.conf' -p SHA256SUMS
  (cd "$TMP" && grep -E ' (defender-mpengine-windows-amd64\.ext\.exe|defender_mpengine\.conf)$' SHA256SUMS \
    | { command -v sha256sum >/dev/null && sha256sum -c - || shasum -a 256 -c -; })

  cat > "$STATE" <<EOF
PROJECT=$PROJECT
ZONE=$ZONE
BUCKET=$BUCKET
SA_EMAIL=$SA_EMAIL
VERSION=$VERSION
VMS="$(printf "osqdef-soak-%s-$SUFFIX " "${IMAGES[@]#windows-}")"
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

  gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT" --location="${ZONE%-*}" \
    --uniform-bucket-level-access --public-access-prevention --quiet
  echo '{"rule":[{"action":{"type":"Delete"},"condition":{"age":14}}]}' > "$TMP/lc.json"
  gcloud storage buckets update "gs://$BUCKET" --lifecycle-file="$TMP/lc.json" --quiet
  gcloud iam service-accounts create "$SA" --project="$PROJECT" --display-name="osqdef soak (temporary)" --quiet
  sleep 10
  for role in roles/storage.objectViewer roles/storage.objectCreator; do
    gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member="serviceAccount:$SA_EMAIL" \
      --role="$role" --quiet >/dev/null
  done
  gcloud storage cp --quiet "$TMP/defender-mpengine-windows-amd64.ext.exe" "gs://$BUCKET/soak/defender-mpengine.ext.exe"
  gcloud storage cp --quiet "$TMP/defender_mpengine.conf" "$HERE/soak-agent.ps1" "gs://$BUCKET/soak/"
  sed "s/__BUCKET__/$BUCKET/" "$HERE/soak-startup.ps1" > "$TMP/startup.ps1"

  for img in "${IMAGES[@]}"; do
    vm="osqdef-soak-${img#windows-}-$SUFFIX"
    gcloud compute instances create "$vm" --project="$PROJECT" --zone="$ZONE" \
      --machine-type=e2-standard-2 --image-family="$img" --image-project=windows-cloud \
      --boot-disk-size=50GB --subnet="$SUBNET" --no-address --shielded-secure-boot \
      --service-account="$SA_EMAIL" --scopes=https://www.googleapis.com/auth/devstorage.read_write \
      --labels=purpose=osqdef-soak --metadata-from-file=windows-startup-script-ps1="$TMP/startup.ps1"
  done
  echo "started; state in $STATE. Check progress with: $0 status"
  ;;

status)
  # shellcheck disable=SC1090
  source "$STATE"
  for vm in $VMS; do
    echo "== $vm"
    gcloud compute instances describe "$vm" --project="$PROJECT" --zone="$ZONE" --format='value(status)' 2>&1
    gcloud compute instances get-serial-port-output "$vm" --project="$PROJECT" --zone="$ZONE" 2>/dev/null \
      | grep -oE 'SOAK[-:][^"]*' | tail -3 || true
  done
  echo "== uploads"
  gcloud storage ls -l "gs://$BUCKET/soak/results/*/latest.zip" 2>/dev/null || echo "none yet"
  ;;

collect)
  source "$STATE"
  OUT="${OUT:-$PWD/soak-results}"
  mkdir -p "$OUT"
  gcloud storage cp --quiet -r "gs://$BUCKET/soak/results/*" "$OUT/"
  for z in "$OUT"/*/latest.zip; do
    d="$(dirname "$z")/latest"; rm -rf "$d"; mkdir -p "$d"
    # Compress-Archive writes backslash separators; unzip warns but extracts.
    (cd "$d" && unzip -oq ../latest.zip 2>/dev/null || true)
  done
  python3 -I "$HERE/analyze.py" "$OUT"
  ;;

teardown)
  source "$STATE"
  for vm in $VMS; do
    gcloud compute instances delete "$vm" --project="$PROJECT" --zone="$ZONE" --quiet || true
  done
  gcloud storage rm -r "gs://$BUCKET" --quiet || true
  gcloud iam service-accounts delete "$SA_EMAIL" --project="$PROJECT" --quiet || true
  rm -f "$STATE"
  echo "teardown complete"
  ;;

*)
  sed -n '2,12p' "$0"; exit 2 ;;
esac
