// Learn page: the "SSO vs OAuth vs OIDC vs SAML" animation topic, first on the page and linked from Getting started.
import { existsSync, readFileSync, statSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BASICS_CARDS, BASICS_ID, BASICS_TITLE } from "../src/data/identityBasics";
import { START_STEPS } from "../src/data/gettingStarted";

const learn = readFileSync("src/views/Learn.tsx", "utf8");

describe("SSO vs OAuth vs OIDC vs SAML Learn topic", () => {
  it("is the first topic on the Learn page", () => {
    expect(BASICS_TITLE).toBe("SSO vs OAuth vs OIDC vs SAML");
    expect(learn.indexOf("<IdentityBasics />")).toBeGreaterThan(-1);
    expect(learn.indexOf("<IdentityBasics />")).toBeLessThan(learn.indexOf("<Lifecycle />"));
  });

  it("shows the dark animation in both themes, with a reduced-motion still", () => {
    for (const ext of ["gif", "png"]) {
      const f = `src/assets/learn/sso-oauth-oidc-saml-dark.${ext}`;
      expect(existsSync(f)).toBe(true);
      expect(statSync(f).size).toBeLessThan(1_200_000);
    }
    expect(readFileSync("src/assets/learn/sso-oauth-oidc-saml-dark.gif").subarray(0, 6).toString()).toBe("GIF89a");
    expect(learn).not.toContain("-light.gif");
  });

  it("keeps the protocol facts straight in the text version", () => {
    const by = (n: string) => BASICS_CARDS.find((c) => c.name.startsWith(n))!;
    expect(by("SSO").what).toMatch(/Not a protocol/);
    expect(by("OAuth").role).toBe("Authorization");
    expect(by("OAuth").token).toMatch(/Access token, meant for the API/);
    expect(by("OpenID").role).toBe("Authentication");
    expect(by("OpenID").token).toMatch(/ID token/);
    expect(by("SAML").token).toMatch(/assertion/);
  });

  it("is opened straight from the first Getting started step", () => {
    const step = START_STEPS.find((s) => s.id === "learn")!;
    expect(step.open.route).toBe("learn");
    expect(step.open.params?.section).toBe(BASICS_ID);
  });
});
