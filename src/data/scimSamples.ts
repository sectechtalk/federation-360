/** Example SCIM messages, shaped like what the Microsoft Entra provisioning service sends and receives. */
export interface ScimSample {
  id: string;
  label: string;
  note: string;
  /** Identifier to preload into the "sent at sign-in" box. */
  signInId?: string;
  text: string;
}

const j = (o: unknown) => JSON.stringify(o, null, 2);
const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERR = "urn:ietf:params:scim:api:messages:2.0:Error";

export const SCIM_SAMPLES: ScimSample[] = [
  {
    id: "create",
    label: "Create a user",
    note: "A joiner. Entra creates the account in the app, and the sign-in identifier matches userName.",
    signInId: "avery.lee@contoso.example",
    text: `POST /scim/v2/Users HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/scim+json

${j({
  schemas: [USER, ENT],
  externalId: "avery.lee",
  userName: "avery.lee@contoso.example",
  active: true,
  displayName: "Avery Lee",
  name: { givenName: "Avery", familyName: "Lee", formatted: "Avery Lee" },
  emails: [{ value: "avery.lee@contoso.example", type: "work", primary: true }],
  title: "Analyst",
  [ENT]: { department: "Finance", employeeNumber: "100482" },
})}`,
  },
  {
    id: "mismatch",
    label: "Sign-in name mismatch",
    note: "The app's stored account. Sign-in sends the short UPN, but the account was provisioned with the email address. Entra sign-in succeeds; the app says “user not found”.",
    signInId: "alee@contoso.example",
    text: j({
      schemas: [USER],
      id: "u-58213",
      externalId: "avery.lee",
      userName: "avery.lee@contoso.example",
      active: true,
      name: { givenName: "Avery", familyName: "Lee" },
      emails: [{ value: "avery.lee@contoso.example", type: "work", primary: true }],
      meta: { resourceType: "User", created: "2026-10-02T08:14:11Z", lastModified: "2026-10-02T08:14:11Z" },
    }),
  },
  {
    id: "disable",
    label: "Disable a leaver",
    note: "Entra's default PATCH when a user is unassigned or disabled. Note the capitalised op and the text \"False\".",
    text: `PATCH /scim/v2/Users/u-58213 HTTP/1.1
Content-Type: application/scim+json

${j({ schemas: [PATCH], Operations: [{ op: "Replace", path: "active", value: "False" }] })}`,
  },
  {
    id: "lookup",
    label: "Lookup, no match",
    note: "Before creating anyone, Entra asks the app whether the user already exists. This is the app's answer.",
    text: `GET /scim/v2/Users?filter=userName%20eq%20%22jordan.kim%40contoso.example%22 HTTP/1.1

HTTP/1.1 200 OK

${j({ schemas: [LIST], totalResults: 0, Resources: [], startIndex: 1, itemsPerPage: 20 })}`,
  },
  {
    id: "conflict",
    label: "409 duplicate",
    note: "The app already has an account with this userName, typically one created by hand before provisioning was switched on.",
    text: `HTTP/1.1 409 Conflict

${j({ schemas: [ERR], status: "409", scimType: "uniqueness", detail: "User with userName avery.lee@contoso.example already exists." })}`,
  },
  {
    id: "unauthorized",
    label: "401 expired token",
    note: "The secret token in the Entra provisioning settings has expired. Every request fails until it's replaced.",
    text: `HTTP/1.1 401 Unauthorized

${j({ schemas: [ERR], status: "401", detail: "The access token is expired." })}`,
  },
  {
    id: "group",
    label: "Add group members",
    note: "Entra adds two users to a group in the app. Each value is the app's own id for the user.",
    text: `PATCH /scim/v2/Groups/g-204 HTTP/1.1

${j({ schemas: [PATCH], Operations: [{ op: "Add", path: "members", value: [{ value: "u-58213" }, { value: "u-58377" }] }] })}`,
  },
];
