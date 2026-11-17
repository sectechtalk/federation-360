# Federation credentials export (contract v1)

Federation 360 is the source of truth for **federation credentials**. Other tools, starting with certificates-360,
read them from this export (the **expiry report**) instead of asking a person to type them in twice. Federation 360
does not build an all-up secrets view; certificates-360 does.

The file holds names, IDs, certificate thumbprints, owners and dates only. Secret values, private keys and tokens are
never included: the builder refuses to write a document with any property named `secretText`, `hint`, `key`, `value`,
`password`, `token`, `secret` or `privateKey`. It still maps your apps and what expires when, so keep it internal.

- Owner of the contract: the shared package `@sectechtalk/f360-collector` (included in this repo as `vendor/sectechtalk-f360-collector-<version>.tgz`). It holds the types, the status rule, the item IDs, the Entra rotation links, the secret guard and the JSON Schema. certificates-360 uses it to build the same document straight from a tenant scan (`credentialsFromSnapshot`).
- JSON Schema: `schema/f360-federation-credentials.v1.schema.json` in that package (in this repo: `node_modules/@sectechtalk/f360-collector/schema/f360-federation-credentials.v1.schema.json`). There is no second copy in this repo.
- Federation 360's builder: `src/lib/credentialExport.ts` (`buildCredentialsExport`). It adds what only Federation 360 knows: recorded items (SCIM tokens, hand-entered expiries) and the Federation 360 app ID and environment.
- Tests: `tests/credential-export.test.ts` (fails if the builder writes a field the package schema doesn't list)
- Scan-only documents set `generator.name` to `f360-collector` and leave `app.f360Id` and `app.environment` as `null`.

## Who owns what

| Credential | Owner | Notes |
|---|---|---|
| App registration client secrets | Federation 360 | Read by Discover from Graph (names and dates only) |
| App registration certificates | Federation 360 | Read by Discover, with SHA-1 thumbprint |
| SAML signing certificates (enterprise apps) | Federation 360 | Read by Discover from the service principal, one item per certificate |
| SCIM provisioning secret tokens | Federation 360 | Always typed into Federation 360. Graph's `synchronization/secrets` is write-only, so no tool can read the expiry |
| DKIM, Azure resource keys, Key Vault, Intune certificates | certificates-360 | Not in this export |
| DMARC, SPF | nobody | Out of scope |

## How to produce it

In Federation 360 open **Inventory** (`http://localhost:5173/#inventory` in the local container), press
**Export expiry report**, then **Download expiry report**. The file is
`f360-credentials-YYYY-MM-DD.json`. Fictional example apps are left out unless you tick
**Include the fictional example apps**; included ones carry `"example": true`.

The file name, `format` (`f360.federation-credentials`) and `generator.name` (`f-360` for a file from Federation 360,
`f360-collector` for one built straight from a tenant scan) are fixed identifiers in format v1. They keep the short
names on purpose so existing readers keep working.

## Document

```json
{
  "format": "f360.federation-credentials",
  "version": 1,
  "generatedAt": "2026-11-15T23:50:00.000Z",
  "generator": { "name": "f-360", "version": "0.1.0" },
  "expiringDays": 30,
  "counts": { "total": 2, "expired": 1, "expiring": 0, "ok": 1, "unknown": 0 },
  "items": [
    {
      "id": "f360:entra:8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10:<appId>:app:<keyId>",
      "type": "app-client-secret",
      "name": "prod-2024",
      "status": "expired",
      "daysLeft": -10,
      "expiresAt": "2026-11-05T00:00:00Z",
      "createdAt": "2024-11-05T00:00:00Z",
      "thumbprint": null,
      "keyId": "<keyId>",
      "source": "tenant-scan",
      "observedAt": "2026-11-15T20:00:00Z",
      "app": {
        "f360Id": "k3x9ab12cd",
        "name": "Payroll Web",
        "protocol": "oidc",
        "environment": "prod",
        "owner": "Finance Apps team",
        "appId": "<appId>",
        "objectId": "<application object id>",
        "servicePrincipalId": "<service principal object id>",
        "missingFromTenant": false
      },
      "tenant": { "id": "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10", "name": "Contoso Lab", "domain": "contoso.onmicrosoft.com", "platform": "entra" },
      "manageUrl": "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/<appId>"
    }
  ]
}
```

## Item fields

| Field | Meaning |
|---|---|
| `id` | Stable across exports. Use it as the upsert key. Scanned: `f360:<provider>:<tenantId>:<appId>:<app\|sp>:<keyId>`. Recorded: `f360:recorded:<f360AppId>:<type>` |
| `type` | `app-client-secret`, `app-certificate`, `app-credential` (recorded by hand, secret or certificate unknown), `saml-signing-certificate`, `scim-token` |
| `name` | Credential display name from the tenant, or a fixed label for recorded items |
| `status` | `expired` (daysLeft < 0), `expiring` (0 to `expiringDays`), `ok`, `unknown` (no expiry date) |
| `daysLeft` | Whole days until `expiresAt`, negative once expired, `null` when unknown |
| `expiresAt` | ISO 8601 date or date-time, or `null` |
| `createdAt` | ISO 8601, or `null`. In Entra a rotation adds a new credential, so this is also the last-rotated date. Use it for age when there is no expiry |
| `thumbprint` | SHA-1 hex, upper case, certificates only |
| `keyId` | Entra credential keyId |
| `source` | `tenant-scan` (read from the identity provider) or `recorded` (typed into Federation 360) |
| `observedAt` | When Federation 360 last saw the fact: the scan time, or the last edit of the inventory entry |
| `example` | Present and `true` only for fictional example data |
| `app` | The integration it belongs to. `missingFromTenant: true` means the last scan no longer found the app |
| `tenant` | `id` is the directory (tenant) ID for Entra |
| `manageUrl` | Entra admin center page where a person rotates it, or `null` |

## Rules

1. **No secret values, ever.** No `secretText`, `hint`, certificate bodies or tokens. The builder only copies names, IDs, thumbprints and dates, and `assertNoSecretMaterial` refuses to render an export that contains a secret-like field name.
2. **Scanned beats recorded.** A recorded date is exported only when the scan has no credential of that kind for the app. SCIM tokens are always recorded.
3. **One file is a full snapshot.** An item missing from a newer export for the same tenant was removed in Federation 360 or the tenant; the consumer decides whether to mark it gone or drop it.
4. **Compatibility.** Adding optional fields keeps `version: 1`; consumers must ignore fields they don't know. Renaming, removing or changing the meaning of a field bumps `version` and the schema file name, in the collector package first.
