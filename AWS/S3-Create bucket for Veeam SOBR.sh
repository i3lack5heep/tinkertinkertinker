#!/usr/bin/env bash
# veeam_s3_bucket_create.sh
# Creates an S3 bucket for Veeam Capacity Tier with:
# - Object Lock enabled at creation
# - Versioning enabled
# - Block Public Access enabled
# - Default encryption (SSE-KMS if provided/created, otherwise SSE-S3)
# - TLS-only bucket policy
#
# Defaults for your request:
#   BUCKET=veeam-1180
#   REGION=us-west-1   # N. California
#
# Usage (defaults already set; overrides optional):
#   ./veeam_s3_bucket_create.sh
#   ./veeam_s3_bucket_create.sh --create-kms --kms-alias alias/veeam-s3-veeam-1180
#   ./veeam_s3_bucket_create.sh --kms-key-arn arn:aws:kms:us-west-1:123456789012:key/abcd-...
#   ./veeam_s3_bucket_create.sh --profile myprofile

set -euo pipefail

########################
# Defaults & helpers
########################
AWS_PROFILE=""
REGION="${REGION:-us-west-1}"   # N. California
BUCKET="${BUCKET:-veeam-1180}"

KMS_KEY_ARN=""
CREATE_KMS=false
KMS_ALIAS=""

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
Usage: $0 [--kms-key-arn <arn> | --create-kms [--kms-alias <alias>]] [--profile <aws-profile>]

Defaults:
  Bucket: $BUCKET
  Region: $REGION

Options:
      --kms-key-arn    Existing CMK ARN for SSE-KMS default encryption
      --create-kms     Create a new CMK for the bucket's default encryption
      --kms-alias      Alias for the new CMK (default: alias/veeam-s3-\$BUCKET)
      --profile        AWS CLI profile to use

Notes:
- Object Lock is enabled at creation and cannot be added later.
- Script intentionally does NOT set bucket-level default retention or lifecycle rules (Veeam controls retention).
EOF
  exit 1
}

bucket_exists() {
  local b="$1"
  if aws s3api head-bucket --bucket "$b" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

create_bucket_with_object_lock() {
  local b="$1"; local region="$2"
  echo "Creating bucket '$b' in region '$region' with Object Lock enabled..."
  if [[ "$region" == "us-east-1" ]]; then
    aws s3api create-bucket \
      --bucket "$b" \
      --object-lock-enabled-for-bucket >/dev/null
  else
    aws s3api create-bucket \
      --bucket "$b" \
      --object-lock-enabled-for-bucket \
      --create-bucket-configuration "LocationConstraint=$region" >/dev/null
  fi
  echo "Bucket created."
}

enable_versioning() {
  local b="$1"
  echo "Enabling bucket versioning..."
  aws s3api put-bucket-versioning \
    --bucket "$b" \
    --versioning-configuration Status=Enabled >/dev/null
  echo "Versioning enabled."
}

enable_block_public_access() {
  local b="$1"
  echo "Enabling Block Public Access..."
  aws s3api put-public-access-block \
    --bucket "$b" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
  echo "Public access blocked."
}

put_default_encryption_sse_s3() {
  local b="$1"
  echo "Setting default encryption to SSE-S3 (AES256)..."
  aws s3api put-bucket-encryption \
    --bucket "$b" \
    --server-side-encryption-configuration '{
      "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]
    }' >/dev/null
  echo "Default encryption set to SSE-S3."
}

put_default_encryption_sse_kms() {
  local b="$1"; local kms_arn="$2"
  echo "Setting default encryption to SSE-KMS using $kms_arn ..."
  aws s3api put-bucket-encryption \
    --bucket "$b" \
    --server-side-encryption-configuration "{
      \"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$kms_arn\"},\"BucketKeyEnabled\":true}]
    }" >/dev/null
  echo "Default encryption set to SSE-KMS."
}

put_tls_only_policy() {
  local b="$1"
  echo "Applying bucket policy to deny non-TLS access..."
  local policy
  policy=$(cat <<POL
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$b",
        "arn:aws:s3:::$b/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
POL
)
  aws s3api put-bucket-policy --bucket "$b" --policy "$policy" >/dev/null
  echo "TLS-only policy applied."
}

create_cmk_if_requested() {
  local alias_name="$1"
  echo "Creating new KMS CMK..."
  local key_id
  key_id=$(aws kms create-key \
    --description "CMK for default SSE-KMS on Veeam S3 bucket" \
    --origin "AWS_KMS" \
    --query "KeyMetadata.KeyId" \
    --output text)
  local arn
  arn=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.Arn" --output text)

  if [[ -n "$alias_name" ]]; then
    if aws kms list-aliases --query "Aliases[?AliasName=='$alias_name'].AliasName" --output text | grep -q "$alias_name"; then
      aws kms update-alias --alias-name "$alias_name" --target-key-id "$key_id"
    else
      aws kms create-alias --alias-name "$alias_name" --target-key-id "$key_id"
    fi
  fi

  echo "$arn"
}

########################
# Parse args
########################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kms-key-arn) KMS_KEY_ARN="${2:-}"; shift 2;;
    --create-kms) CREATE_KMS=true; shift 1;;
    --kms-alias) KMS_ALIAS="${2:-}"; shift 2;;
    --profile) AWS_PROFILE="${2:-}"; shift 2;;
    -h|--help) usage;;
    *) die "Unknown argument: $1";;
  esac
done

export AWS_REGION="$REGION"
[[ -n "$AWS_PROFILE" ]] && export AWS_PROFILE

echo "Target bucket: $BUCKET"
echo "Region:        $REGION"

if bucket_exists "$BUCKET"; then
  die "Bucket '$BUCKET' already exists. Choose a different name."
fi

# Create bucket with Object Lock
create_bucket_with_object_lock "$BUCKET" "$REGION"

# Enable versioning
enable_versioning "$BUCKET"

# Block public access
enable_block_public_access "$BUCKET"

# Set default encryption
if [[ -n "$KMS_KEY_ARN" ]]; then
  put_default_encryption_sse_kms "$BUCKET" "$KMS_KEY_ARN"
elif [[ "$CREATE_KMS" == true ]]; then
  KMS_ALIAS="${KMS_ALIAS:-alias/veeam-s3-$BUCKET}"
  NEW_KMS_ARN=$(create_cmk_if_requested "$KMS_ALIAS")
  echo "Created KMS key: $NEW_KMS_ARN (alias: $KMS_ALIAS)"
  put_default_encryption_sse_kms "$BUCKET" "$NEW_KMS_ARN"
else
  put_default_encryption_sse_s3 "$BUCKET"
fi

# Apply TLS-only policy
put_tls_only_policy "$BUCKET"

cat <<SUMMARY

Done.

Bucket:            $BUCKET
Region:            $REGION  (N. California)
Object Lock:       ENABLED (no default retention set)
Versioning:        ENABLED
Public Access:     BLOCKED
Default encryption: $( [[ -n "${KMS_KEY_ARN:-}" || "${CREATE_KMS:-false}" == "true" ]] && echo "SSE-KMS" || echo "SSE-S3" )
KMS key ARN:       ${KMS_KEY_ARN:-${NEW_KMS_ARN:-(none)}}

Next steps for Veeam:
- Do NOT set S3 bucket default retention or lifecycle rules; Veeam applies object lock per object.
- Ensure the IAM principal Veeam uses has least-privilege S3 and KMS permissions scoped to this bucket/prefix.

SUMMARY
