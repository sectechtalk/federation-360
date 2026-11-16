variable "tenant_id" {
  description = "Directory (tenant) ID of the LAB tenant. Never point this at a production tenant."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "tenant_name" {
  description = "Display name used for this tenant in the Federation 360 inventory."
  type        = string
  default     = "Federation 360 lab"
}

variable "live_test_redirect_uris" {
  description = "Where Federation 360 runs. These become single-page-app redirect URIs on F360-LiveTest."
  type        = list(string)
  default     = ["http://localhost:5173/"]
}

variable "lab_user_upns" {
  description = "UPNs of test users created by the bootstrap script. They are added to the lab group and assigned to the apps."
  type        = list(string)
  default     = []
}

variable "testapp_acs_url" {
  description = "Reply URL (ACS) of the lab test app's SAML endpoint. The test app runs in Docker on your PC."
  type        = string
  default     = "http://localhost:5174/saml/acs"
}

variable "testapp_cloud_acs_url" {
  description = "Optional second reply URL for the test app when it also runs on Azure Static Web Apps Free, e.g. https://<name>.azurestaticapps.net/api/saml/acs. lab/testapp/azure/Deploy-F360TestAppAzure.ps1 sets it (GitHub variable LAB_TESTAPP_CLOUD_ACS). Empty = PC only."
  type        = string
  default     = ""

  validation {
    condition     = var.testapp_cloud_acs_url == "" || can(regex("^https://[a-z0-9.-]+\\.azurestaticapps\\.net/api/saml/acs$", var.testapp_cloud_acs_url))
    error_message = "testapp_cloud_acs_url must be empty or https://<host>.azurestaticapps.net/api/saml/acs."
  }
}
