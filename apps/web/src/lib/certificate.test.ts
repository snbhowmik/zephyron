import type { CertificateFacts } from "@/api/types";
import { describe, expect, it } from "vitest";
import { certificateRole, commonName, validityYears } from "./certificate";

const cert = (over: Partial<CertificateFacts>): CertificateFacts => ({
  sha256_fingerprint: "a",
  spki_sha256: "b",
  subject: "CN=x,O=y",
  issuer: "CN=x,O=y",
  not_before: "2026-01-01T00:00:00+00:00",
  not_after: "2046-01-01T00:00:00+00:00",
  is_ca: false,
  self_signed: false,
  ...over,
});

describe("certificate helpers", () => {
  it("derives the role from the facts", () => {
    expect(certificateRole(cert({ is_ca: true, self_signed: true }))).toBe("root CA");
    expect(certificateRole(cert({ is_ca: true }))).toBe("intermediate CA");
    expect(certificateRole(cert({}))).toBe("leaf");
  });
  it("extracts the common name", () => {
    expect(commonName("CN=pay.acme.example,O=Acme")).toBe("pay.acme.example");
    expect(commonName("O=Only")).toBe("O=Only");
  });
  it("never reports negative remaining validity", () => {
    expect(validityYears(cert({ not_after: "2000-01-01T00:00:00+00:00" }))).toBe(0);
  });
});
