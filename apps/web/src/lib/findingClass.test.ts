import { describe, expect, it } from "vitest";
import { BAND, FINDING, FINDING_CLASSES, isFindingClass, styleFor } from "./findingClass";

const colourOf = (badge: string) => badge.match(/text-(\w+)-\d+/)?.[1];

describe("finding-class visual language (I1, I8)", () => {
  it("never renders GROVER_AFFECTED in the same colour or severity as QUANTUM_VULNERABLE", () => {
    const grover = FINDING["grover-affected"];
    const vulnerable = FINDING["quantum-vulnerable"];
    expect(colourOf(grover.badge)).not.toBe(colourOf(vulnerable.badge));
    expect(grover.bar).not.toBe(vulnerable.bar);
    expect(grover.severity).not.toBe(vulnerable.severity);
    expect(grover.severity).toBe("informational");
  });

  it("gives CLASSICAL_WEAK its own treatment and says it is not a quantum issue", () => {
    const weak = FINDING["classical-weak"];
    expect(colourOf(weak.badge)).not.toBe(colourOf(FINDING["quantum-vulnerable"].badge));
    expect(weak.copy).toMatch(/not a quantum issue/i);
    expect(weak.copy).toMatch(/urgent/i);
  });

  it("renders UNKNOWN as a hatched grey coverage failure, never green and never a risk colour", () => {
    const unknown = FINDING.unknown;
    expect(unknown.hatched).toBe(true);
    expect(unknown.badge).toContain("hatched");
    expect(unknown.badge).not.toMatch(/emerald|green/);
    expect(unknown.badge).not.toMatch(/red|orange|amber/);
    expect(unknown.copy).toMatch(/never counted as safe/i);
    expect(colourOf(unknown.badge)).not.toBe(colourOf(FINDING["quantum-safe"].badge));
  });

  it("gives every class a distinct colour", () => {
    const colours = FINDING_CLASSES.map((c) => colourOf(FINDING[c].badge));
    expect(new Set(colours).size).toBe(FINDING_CLASSES.length);
  });

  it("treats an unrecognised class as a coverage gap, not as safe", () => {
    expect(isFindingClass("something-new")).toBe(false);
    expect(styleFor("something-new")).toBe(FINDING.unknown);
  });

  it("gives the coverage-gap band the same hatched treatment", () => {
    expect(BAND["coverage-gap"].badge).toContain("hatched");
    expect(BAND["coverage-gap"].badge).not.toMatch(/emerald|green/);
  });
});
