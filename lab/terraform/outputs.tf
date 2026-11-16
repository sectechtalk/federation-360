output "tenant_id" {
  value = var.tenant_id
}

output "live_test_client_id" {
  description = "Client ID for Federation 360's live sign-in test."
  value       = azuread_application.live_test.client_id
}

output "lab_users_missing" {
  description = "Users listed in LAB_USER_UPNS that don't exist in the tenant, so they were not assigned. Create them, then apply again."
  value       = local.lab_users_missing
}

output "testapp_saml_entity_id" {
  description = "Identifier (Entity ID) of LAB-TestApp-SAML, used by lab/testapp."
  value       = local.testapp_entity_id
}

output "testapp_saml_client_id" {
  value = azuread_application.testapp_saml.client_id
}

output "discovery_client_id" {
  description = "Client ID for Federation 360's Discover page (Sign in and scan)."
  value       = azuread_application.discovery.client_id
}

output "oidc_playground_url" {
  description = "Open in a private window to get a real ID token shown on jwt.ms."
  value       = "https://login.microsoftonline.com/${var.tenant_id}/oauth2/v2.0/authorize?client_id=${azuread_application.oidc_playground.client_id}&response_type=id_token&redirect_uri=https%3A%2F%2Fjwt.ms%2F&scope=openid%20profile%20email&nonce=f360lab&response_mode=fragment"
}

output "saml_test_url" {
  description = "IdP-initiated SAML sign-in. The signed response is shown on jwt.ms."
  value       = "https://launcher.myapps.microsoft.com/api/signin/${azuread_application.saml.client_id}?tenantId=${var.tenant_id}"
}

output "saml_metadata_url" {
  value = "https://login.microsoftonline.com/${var.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${azuread_application.saml.client_id}"
}

# Paste this into Federation 360 > Inventory > Back up / import.
output "f360_inventory" {
  description = "The lab tenant and its apps in Federation 360's import format."
  value = jsonencode({
    format  = "federation-360"
    version = 1
    tenants = [{
      id          = "lab-tenant"
      name        = var.tenant_name
      platform    = "entra"
      tenantRef   = var.tenant_id
      domain      = ""
      environment = "test"
      notes       = "Built by lab/terraform."
      updatedAt   = ""
    }]
    apps = [
      {
        id           = "lab-saml"
        tenantId     = "lab-tenant"
        name         = azuread_application.saml.display_name
        protocol     = "saml"
        environment  = "test"
        owner        = "Lab"
        status       = "testing"
        provisioning = "none"
        notes        = "ACS is jwt.ms, which displays the SAML response."
        updatedAt    = ""
        saml = {
          entityId       = local.saml_entity_id
          acsUrl         = "${local.saml_acs_url}/"
          signOnUrl      = ""
          idpEntityId    = local.issuer_v1
          nameIdFormat   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          nameIdSource   = "user.userprincipalname"
          certThumbprint = azuread_service_principal_token_signing_certificate.saml.thumbprint
          certExpires    = substr(azuread_service_principal_token_signing_certificate.saml.end_date, 0, 10)
        }
        oidc = local.empty_oidc
      },
      {
        id           = "lab-livetest"
        tenantId     = "lab-tenant"
        name         = azuread_application.live_test.display_name
        protocol     = "oidc"
        environment  = "test"
        owner        = "Lab"
        status       = "testing"
        provisioning = "none"
        notes        = "Single-page app, auth code + PKCE."
        updatedAt    = ""
        saml         = local.empty_saml
        oidc = merge(local.empty_oidc, {
          clientId     = azuread_application.live_test.client_id
          redirectUris = join("\n", var.live_test_redirect_uris)
          clientType   = "public"
          scopes       = "openid profile email User.Read"
          audience     = azuread_application.live_test.client_id
          issuer       = local.issuer_v2
        })
      },
      {
        id           = "lab-oidc-playground"
        tenantId     = "lab-tenant"
        name         = azuread_application.oidc_playground.display_name
        protocol     = "oidc"
        environment  = "test"
        owner        = "Lab"
        status       = "testing"
        provisioning = "none"
        notes        = "Implicit ID token to jwt.ms. For learning only; the inventory flags implicit flow on purpose."
        updatedAt    = ""
        saml         = local.empty_saml
        oidc = merge(local.empty_oidc, {
          clientId     = azuread_application.oidc_playground.client_id
          redirectUris = "https://jwt.ms/"
          grantType    = "implicit"
          clientType   = "public"
          audience     = azuread_application.oidc_playground.client_id
          issuer       = local.issuer_v2
        })
      },
      {
        id           = "lab-daemon"
        tenantId     = "lab-tenant"
        name         = azuread_application.daemon.display_name
        protocol     = "oauth"
        environment  = "test"
        owner        = "Lab"
        status       = "testing"
        provisioning = "none"
        notes        = "Client credentials to LAB-API with app role Jobs.Read.All. Add your own certificate to request tokens."
        updatedAt    = ""
        saml         = local.empty_saml
        oidc = merge(local.empty_oidc, {
          clientId  = azuread_application.daemon.client_id
          grantType = "client_credentials"
          scopes    = "api://${azuread_application.api.client_id}/.default"
          audience  = azuread_application.api.client_id
          issuer    = local.issuer_v2
        })
      },
    ]
  })
}

locals {
  empty_saml = {
    entityId       = ""
    acsUrl         = ""
    signOnUrl      = ""
    idpEntityId    = ""
    nameIdFormat   = ""
    nameIdSource   = ""
    certThumbprint = ""
    certExpires    = ""
  }
  empty_oidc = {
    clientId      = ""
    redirectUris  = ""
    grantType     = "authorization_code"
    clientType    = "confidential"
    scopes        = "openid profile email"
    audience      = ""
    issuer        = ""
    secretExpires = ""
  }
}
