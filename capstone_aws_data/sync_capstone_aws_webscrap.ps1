param(
  [Parameter(Mandatory=$true)]
  [string]$Bucket = "cyber-threat-feed-raw-data",

  [Parameter(Mandatory=$false)]
  [string]$Region = "ap-southeast-1",

  [Parameter(Mandatory=$false)]
  [string]$ParentPrefix = "exports/cti/"
)

# --- Setup & logging ---
$DestRoot = "C:\Users\mike\Downloads\capstone\capstone_aws_data"
New-Item -ItemType Directory -Path $DestRoot -Force | Out-Null
$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$LogFile  = Join-Path $DestRoot ("list_log_{0}.txt" -f $ts)
$ListFile = Join-Path $DestRoot ("prefixes_{0}.json" -f $ts)

function Log([string]$msg) {
  $line = "{0} {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $msg
  Write-Host $line
  Add-Content -Path $LogFile -Value $line
}

Log "==== Listing started ===="

# --- Call AWS CLI directly ---
aws s3api list-objects-v2 `
  --bucket $Bucket `
  --region $Region `
  --prefix $ParentPrefix `
  --delimiter "/" `
  --request-payer requester `
  --output json `
  > $ListFile 2>> $LogFile

if (-not (Test-Path $ListFile)) {
  Log "ERROR: List output file not created."
  Log "==== Listing finished ===="
  exit 1
}

# --- Parse JSON ---
try {
  $data = Get-Content $ListFile -Raw | ConvertFrom-Json
} catch {
  Log "ERROR: Failed to parse JSON: $($_.Exception.Message)"
  Log "==== Listing finished ===="
  exit 1
}

$prefixObjs = $data.CommonPrefixes
if (-not $prefixObjs -or $prefixObjs.Count -eq 0) {
  Log "No sub-prefixes found under $ParentPrefix."
  Log "==== Listing finished ===="
  exit 0
}

Log ("Found {0} sub-prefix(es):" -f $prefixObjs.Count)
$prefixObjs | ForEach-Object { Log (" - {0}" -f $_.Prefix) }

Log "==== Listing finished ===="
