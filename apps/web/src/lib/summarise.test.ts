import type { RegisterEntry } from "@/api/types";
import { describe, expect, it } from "vitest";
import { assetLevel, bindingConstraint, humaniseBound, outcomeCounts } from "./summarise";

const entry = (over: Partial<RegisterEntry>): RegisterEntry =>
  ({
    bom_ref: "r",
    system_id: "s",
    finding_class: "quantum-vulnerable",
    migration_authority: "self",
    authority_basis: "",
    band: "planned",
    outcome: "migrate",
    reason: "x",
    disputed: false,
    capability_only: false,
    mosca: null,
    expected_value: null,
    z_effective: null,
    recommendation: null,
    roadmap: null,
    explanations: [],
    ...over,
  }) as RegisterEntry;

const mosca = (gap: number | null) => ({
  x_conf_years: 1,
  x_integ_years: 0,
  y_years: 1,
  y_is_heuristic: true,
  z_years: 2,
  gap_years: gap,
  mitigation: null,
  note: "",
});

describe("bindingConstraint", () => {
  it("is null when nothing was scored", () => {
    expect(bindingConstraint([entry({})])).toBeNull();
  });

  it("names the earliest Z and says when a compliance deadline, not physics, bound it", () => {
    const c = bindingConstraint([
      entry({
        z_effective: {
          date: "2033-01-01",
          bound_by: "scenario:nominal",
          binding: false,
          scenario: "nominal",
        },
        mosca: mosca(-1),
      }),
      entry({
        z_effective: {
          date: "2028-12-31",
          bound_by: "deadline:in_dst_cii_m2_highpriority",
          binding: false,
          scenario: "nominal",
        },
        mosca: mosca(2),
      }),
    ]);
    expect(c?.boundBy).toBe("deadline:in_dst_cii_m2_highpriority");
    expect(c?.isDeadline).toBe(true);
    expect(c?.binding).toBe(false);
    expect(c?.late).toBe(1);
    expect(c?.evaluated).toBe(2);
  });

  it("does not count an unevaluated Mosca (no gap) as late or as evaluated", () => {
    const c = bindingConstraint([
      entry({
        z_effective: {
          date: "2030-01-01",
          bound_by: "scenario:aggressive",
          binding: false,
          scenario: "aggressive",
        },
        mosca: mosca(null),
      }),
    ]);
    expect(c?.late).toBe(0);
    expect(c?.evaluated).toBe(0);
    expect(c?.isDeadline).toBe(false);
  });
});

describe("outcomeCounts", () => {
  it("keeps 'no outcome' visible rather than dropping it", () => {
    expect(
      outcomeCounts([
        entry({ outcome: "migrate" }),
        entry({ outcome: null }),
        entry({ outcome: null }),
      ]),
    ).toEqual({
      migrate: 1,
      "no outcome": 2,
    });
  });
});

describe("humaniseBound", () => {
  it("strips the prefix", () => {
    expect(humaniseBound("deadline:in_dst_cii_m2_highpriority")).toBe("in dst cii m2 highpriority");
  });
});

describe("assetLevel", () => {
  it("counts an asset scored under two systems once, not twice", () => {
    const twice = [
      entry({ bom_ref: "a", system_id: "s1" }),
      entry({ bom_ref: "a", system_id: "s2" }),
      entry({ bom_ref: "b", system_id: "s1", finding_class: "unknown", capability_only: true }),
      entry({ bom_ref: "b", system_id: "s2", finding_class: "unknown", capability_only: true }),
    ];
    const level = assetLevel(twice);
    expect(level.total).toBe(2);
    expect(level.byClass).toEqual({ "quantum-vulnerable": 1, unknown: 1 });
    expect(level.coverageFailures).toBe(1);
    expect(level.coverageCapabilityOnly).toBe(1);
  });
});
