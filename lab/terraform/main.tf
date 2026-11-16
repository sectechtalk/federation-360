# Federation 360 lab build-out.
# Everything here works on the free Entra ID tier and creates no client secrets,
# so the Terraform state holds nothing sensitive.

locals {
  prefix = "LAB-"

  # Well-known IDs
  graph_app_id = "00000003-0000-0000-c000-000000000000"
  graph_scopes = {
    openid      = "37f7f235-527c-4136-accd-4a02d197296e"
    profile     = "14dad69e-099b-42c9-810b-d002981feec1"
    email       = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
    "User.Read" = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
  }

  # Read-only delegated Graph permissions for discovery.
  discovery_scopes = {
    openid                 = "37f7f235-527c-4136-accd-4a02d197296e"
    profile                = "14dad69e-099b-42c9-810b-d002981feec1"
    "Application.Read.All" = "c79f8feb-a9db-4090-85f9-90d820caa0eb"
    "Directory.Read.All"   = "06da0dbc-49e2-44d2-8312-53f166ab848a"
  }

  issuer_v1 = "https://sts.windows.net/${var.tenant_id}/"
  issuer_v2 = "https://login.microsoftonline.com/${var.tenant_id}/v2.0"

  saml_entity_id    = "api://${var.tenant_id}/f360-lab-saml"
  testapp_entity_id = "api://${var.tenant_id}/f360-testapp-saml"
  saml_acs_url      = "https://jwt.ms"
}

data "azuread_client_config" "current" {}

data "azuread_service_principal" "graph" {
  client_id = local.graph_app_id
}

# ---------------------------------------------------------------- people

# Users in LAB_USER_UPNS that don't exist yet are skipped (and listed in the lab_users_missing output)
# instead of failing the whole apply. Create them in Entra, then apply again to assign them.
data "azuread_users" "lab" {
  count                = length(var.lab_user_upns) > 0 ? 1 : 0
  user_principal_names = var.lab_user_upns
  ignore_missing       = true
}

locals {
  lab_users_found = { for u in try(data.azuread_users.lab[0].users, []) : lower(u.user_principal_name) => u }
  # Keyed by the UPN exactly as listed, so existing assignments keep their addresses.
  lab_users         = { for upn in var.lab_user_upns : upn => local.lab_users_found[lower(upn)] if contains(keys(local.lab_users_found), lower(upn)) }
  lab_users_missing = [for upn in var.lab_user_upns : upn if !contains(keys(local.lab_users_found), lower(upn))]
}

resource "azuread_group" "lab_users" {
  display_name     = "${local.prefix}Users"
  description      = "Test users for Federation 360 lab scenarios."
  security_enabled = true
  owners           = [data.azuread_client_config.current.object_id]
  members          = [for u in local.lab_users : u.object_id]
}

# ---------------------------------------------------------------- OIDC: live test (single-page app, auth code + PKCE)

resource "azuread_application" "live_test" {
  display_name     = "F360-LiveTest"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  single_page_application {
    redirect_uris = var.live_test_redirect_uris
  }

  required_resource_access {
    resource_app_id = local.graph_app_id

    dynamic "resource_access" {
      for_each = local.graph_scopes
      content {
        id   = resource_access.value
        type = "Scope"
      }
    }
  }

  # Live test's OIDC run asks for an access token for LAB-API (delegated Jobs.Read) and hands it to the
  # test app's API to check.
  required_resource_access {
    resource_app_id = azuread_application.api.client_id

    resource_access {
      id   = random_uuid.api_scope.result
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "live_test" {
  client_id = azuread_application.live_test.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# Admin consent for the basic sign-in scopes, so test users aren't prompted.
resource "azuread_service_principal_delegated_permission_grant" "live_test" {
  service_principal_object_id          = azuread_service_principal.live_test.object_id
  resource_service_principal_object_id = data.azuread_service_principal.graph.object_id
  claim_values                         = keys(local.graph_scopes)
}

# Admin consent for Jobs.Read on LAB-API, so the Live test OIDC run gets an API token without a prompt.
resource "azuread_service_principal_delegated_permission_grant" "live_test_api" {
  service_principal_object_id          = azuread_service_principal.live_test.object_id
  resource_service_principal_object_id = azuread_service_principal.api.object_id
  claim_values                         = ["Jobs.Read"]
}

# ---------------------------------------------------------------- Discovery: read-only tenant scan from Federation 360

# Lets Federation 360's Discover page sign you in and read app registrations and enterprise apps.
# Delegated only: it can never read more than the person signed in can. No consent is granted here;
# the first admin to sign in consents on the Microsoft screen.
resource "azuread_application" "discovery" {
  display_name     = "F360-Discovery"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  single_page_application {
    redirect_uris = var.live_test_redirect_uris
  }

  required_resource_access {
    resource_app_id = local.graph_app_id

    dynamic "resource_access" {
      for_each = local.discovery_scopes
      content {
        id   = resource_access.value
        type = "Scope"
      }
    }
  }
}

resource "azuread_service_principal" "discovery" {
  client_id = azuread_application.discovery.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# ---------------------------------------------------------------- OIDC: jwt.ms playground (implicit ID token, for learning only)

resource "azuread_application" "oidc_playground" {
  display_name     = "${local.prefix}OIDC-Playground"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  web {
    redirect_uris = ["https://jwt.ms/"]

    implicit_grant {
      id_token_issuance_enabled = true
    }
  }
}

resource "azuread_service_principal" "oidc_playground" {
  client_id = azuread_application.oidc_playground.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# ---------------------------------------------------------------- OAuth: a protected API and a daemon that calls it

resource "random_uuid" "api_scope" {}
resource "random_uuid" "api_role" {}

resource "azuread_application" "api" {
  display_name     = "${local.prefix}API"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      id                         = random_uuid.api_scope.result
      value                      = "Jobs.Read"
      type                       = "User"
      admin_consent_display_name = "Read jobs"
      admin_consent_description  = "Read jobs on behalf of the signed-in user."
      user_consent_display_name  = "Read your jobs"
      user_consent_description   = "Read jobs on your behalf."
      enabled                    = true
    }
  }

  app_role {
    id                   = random_uuid.api_role.result
    value                = "Jobs.Read.All"
    display_name         = "Read all jobs"
    description          = "Application permission: read all jobs without a signed-in user."
    allowed_member_types = ["Application"]
    enabled              = true
  }
}

resource "azuread_application_identifier_uri" "api" {
  application_id = azuread_application.api.id
  identifier_uri = "api://${azuread_application.api.client_id}"
}

resource "azuread_service_principal" "api" {
  client_id = azuread_application.api.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_application" "daemon" {
  display_name     = "${local.prefix}Daemon"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  required_resource_access {
    resource_app_id = azuread_application.api.client_id

    resource_access {
      id   = random_uuid.api_role.result
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "daemon" {
  client_id = azuread_application.daemon.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# This is what "Grant admin consent" does for an application permission.
resource "azuread_app_role_assignment" "daemon_to_api" {
  app_role_id         = random_uuid.api_role.result
  principal_object_id = azuread_service_principal.daemon.object_id
  resource_object_id  = azuread_service_principal.api.object_id
}

# ---------------------------------------------------------------- SAML: enterprise app that posts its response to jwt.ms

resource "azuread_application" "saml" {
  display_name     = "${local.prefix}SAML-App"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]
  identifier_uris  = [local.saml_entity_id]

  web {
    redirect_uris = ["${local.saml_acs_url}/"]
  }
}

resource "azuread_service_principal" "saml" {
  client_id                     = azuread_application.saml.client_id
  owners                        = [data.azuread_client_config.current.object_id]
  preferred_single_sign_on_mode = "saml"
  app_role_assignment_required  = true

  feature_tags {
    enterprise            = true
    custom_single_sign_on = true
  }
}

resource "azuread_service_principal_token_signing_certificate" "saml" {
  service_principal_id = azuread_service_principal.saml.id
  display_name         = "CN=F360 Lab SAML Signing"
}

# Only members of the lab group may sign in (others get AADSTS50105).
# Group assignment needs Entra ID P1, so on the free tier each user is assigned directly.
resource "azuread_app_role_assignment" "saml_users" {
  for_each            = local.lab_users
  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = each.value.object_id
  resource_object_id  = azuread_service_principal.saml.object_id
}

# ---------------------------------------------------------------- SAML: the lab test app (lab/testapp) as a service provider

# Federation 360's Live test page starts SAML sign-ins from the test app running in Docker on your PC.
# Entra posts the response through your browser, so a localhost reply URL works with no tunnel.
# When the test app also runs on Azure Static Web Apps Free, its reply URL is added as a second one.
resource "azuread_application" "testapp_saml" {
  display_name     = "${local.prefix}TestApp-SAML"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]
  identifier_uris  = [local.testapp_entity_id]

  web {
    redirect_uris = compact([var.testapp_acs_url, var.testapp_cloud_acs_url])
  }
}

resource "azuread_service_principal" "testapp_saml" {
  client_id                     = azuread_application.testapp_saml.client_id
  owners                        = [data.azuread_client_config.current.object_id]
  preferred_single_sign_on_mode = "saml"
  app_role_assignment_required  = true

  feature_tags {
    enterprise            = true
    custom_single_sign_on = true
  }
}

resource "azuread_service_principal_token_signing_certificate" "testapp_saml" {
  service_principal_id = azuread_service_principal.testapp_saml.id
  display_name         = "CN=F360 Lab TestApp SAML Signing"
}

resource "azuread_app_role_assignment" "testapp_saml_users" {
  for_each            = local.lab_users
  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = each.value.object_id
  resource_object_id  = azuread_service_principal.testapp_saml.object_id
}
