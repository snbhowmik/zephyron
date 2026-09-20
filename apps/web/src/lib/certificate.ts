import type { CertificateFacts } from "@/api/types";

/** Root / intermediate / leaf, from the certificate's own facts (never guessed). */
export function certificateRole(c: CertificateFacts): "root CA" | "intermediate CA" | "leaf" {
  if (c.is_ca && c.self_signed) return "root CA";
  return c.is_ca ? "intermediate CA" : "leaf";
}

export function commonName(subject: string): string {
  const match = /(?:^|,)CN=([^,]+)/.exec(subject);
  return match?.[1] ?? subject;
}

export function validityYears(c: CertificateFacts, now = new Date()): number {
  const ms = new Date(c.not_after).getTime() - now.getTime();
  return Math.max(0, ms / (365.25 * 24 * 3600 * 1000));
}
