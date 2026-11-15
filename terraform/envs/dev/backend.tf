# Remote state in GCS. Create the bucket first (see terraform/README.md, "Bootstrap state").
# Replace the placeholder, or pass it at init time:
#   terraform init -backend-config="bucket=YOUR-STATE-BUCKET"
terraform {
  backend "gcs" {
    bucket = "REPLACE-WITH-STATE-BUCKET-dev"
    prefix = "vaultgate/dev"
  }
}
