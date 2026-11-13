#!/usr/bin/env bash
# Smoke-test the extension on a throwaway GCE Windows Server VM, as SYSTEM,
# against its live Defender database. Creates a temporary bucket and a
# service account scoped to that bucket only; the VM has no external IP
# (needs a subnet with Cloud NAT for egress to pkg.osquery.io). Everything
# is deleted at the end, also on failure.
#
#   PROJECT=my-proj ZONE=europe-west2-a SUBNET=my-subnet scripts/gce-smoke.sh
#
# Results (diagnostics only) land in ./gce-smoke-results/.
set -euo pipefail

: "${PROJECT:?set PROJECT}" "${ZONE:?set ZONE}" "${SUBNET:?set SUBNET}"
REGION="${ZONE%-*}"
IMAGE_FAMILY="${IMAGE_FAMILY:-windows-2022}"
SUFFIX="$(openssl rand -hex 3)"
VM="osqdef-smoke-$SUFFIX" BUCKET="osqdef-smoke-$SUFFIX" SA="osqdef-smoke-$SUFFIX"
SA_EMAIL="$SA@$PROJECT.iam.gserviceaccount.com"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$PWD/gce-smoke-results}"
TMP="$(mktemp -d)"

cleanup() {
  echo "cleaning up"
  gcloud compute instances delete "$VM" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --quiet >/dev/null 2>&1 || true
  gcloud iam service-accounts delete "$SA_EMAIL" --project="$PROJECT" --quiet >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

(cd "$ROOT/defender" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.Version=smoke" -o "$TMP/defender-mpengine.ext.exe" .)

gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT" --location="$REGION" \
  --uniform-bucket-level-access --public-access-prevention --quiet
echo '{"rule":[{"action":{"type":"Delete"},"condition":{"age":1}}]}' > "$TMP/lc.json"
gcloud storage buckets update "gs://$BUCKET" --lifecycle-file="$TMP/lc.json" --quiet
gcloud iam service-accounts create "$SA" --project="$PROJECT" --display-name="osqdef smoke (temporary)" --quiet
sleep 10
for role in roles/storage.objectViewer roles/storage.objectCreator; do
  gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member="serviceAccount:$SA_EMAIL" --role="$role" --quiet >/dev/null
done
gcloud storage cp --quiet "$TMP/defender-mpengine.ext.exe" "$ROOT/scripts/windows-smoke.ps1" "gs://$BUCKET/"
sed "s/__BUCKET__/$BUCKET/" "$ROOT/scripts/gce-startup.ps1" > "$TMP/startup.ps1"

gcloud compute instances create "$VM" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=e2-standard-2 --image-family="$IMAGE_FAMILY" --image-project=windows-cloud \
  --boot-disk-size=50GB --subnet="$SUBNET" --no-address --shielded-secure-boot \
  --service-account="$SA_EMAIL" --scopes=https://www.googleapis.com/auth/devstorage.read_write \
  --labels=purpose=osqdef-smoke --metadata-from-file=windows-startup-script-ps1="$TMP/startup.ps1"

echo "waiting for the startup script (10-15 min)"
for _ in $(seq 1 60); do
  if gcloud compute instances get-serial-port-output "$VM" --project="$PROJECT" --zone="$ZONE" 2>/dev/null \
      | grep -q "SMOKE-DONE"; then break; fi
  sleep 30
done

mkdir -p "$OUT"
gcloud storage cp --quiet "gs://$BUCKET/results/results.zip" "$OUT/"
(cd "$OUT" && unzip -oq results.zip)
cat "$OUT"/*/summary.json 2>/dev/null || echo "no summary - check the serial console"
