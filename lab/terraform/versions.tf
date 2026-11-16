terraform {
  required_version = ">= 1.6"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Sign-in comes from the environment:
#   locally  - `az login --tenant <lab tenant id> --allow-no-subscriptions`
#   in CI    - GitHub OIDC (ARM_USE_OIDC, ARM_CLIENT_ID, ARM_TENANT_ID); no secret is stored
provider "azuread" {
  tenant_id = var.tenant_id
}
