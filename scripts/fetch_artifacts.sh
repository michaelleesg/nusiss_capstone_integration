#!/usr/bin/env bash
set -euo pipefail

# Replace these with real links (GitHub Releases, S3, GDrive)
: "${DATASET_URL:=https://example.com/cybersage/dataset-v1.zip}"
: "${MODELS_URL:=https://example.com/cybersage/models-v1.zip}"

# Optional SHA256 lines exactly as in `sha256sum` output:
: "${DATASET_SHA256:=}"
: "${MODELS_SHA256:=}"

ART_DIR="artifacts"
mkdir -p "${ART_DIR}"

fetch() {
  local url="$1"; local out="$2"
  echo "[+] Downloading: $url -> $out"
  curl -L --fail --retry 3 --retry-delay 2 "$url" -o "$out"
}

verify_sha256() {
  local expected="$1"; local file="$2"
  [ -z "$expected" ] && return 0
  echo "$expected" | sha256sum --check --status --strict - || {
    echo "[-] SHA256 mismatch for $file"; exit 1;
  }
  echo "[+] SHA256 OK for $file"
}

unpack() {
  local file="$1"
  case "$file" in
    *.zip)         echo "[+] Unzipping $file"; unzip -o "$file" -d "$ART_DIR" >/dev/null ;;
    *.tar.gz|*.tgz)echo "[+] Extracting $file"; tar -xzf "$file" -C "$ART_DIR" ;;
    *)             echo "[i] Skipping unpack for $file";;
  esac
}

DATASET_FILE="${ART_DIR}/$(basename "$DATASET_URL")"
fetch "$DATASET_URL" "$DATASET_FILE"
[ -n "$DATASET_SHA256" ] && verify_sha256 "$DATASET_SHA256" "$DATASET_FILE"
unpack "$DATASET_FILE"

if [ -n "${MODELS_URL}" ]; then
  MODELS_FILE="${ART_DIR}/$(basename "$MODELS_URL")"
  fetch "$MODELS_URL" "$MODELS_FILE"
  [ -n "$MODELS_SHA256" ] && verify_sha256 "$MODELS_SHA256" "$MODELS_FILE"
  unpack "$MODELS_FILE"
fi

echo "[✓] Artifacts ready in ${ART_DIR}/"