import { activationBlocker, parseEvent, type Rule } from "@/lib/detections";

const base: Rule = {
  id: "1", title: "t", description: "", format: "sigma", content: "", version: 1, status: "TESTING", severity: "HIGH", executable: true,
  unsupported: [], warnings: [], techniques: [], tactics: [], hunt_id: null, tests_passed: true, tests_run_at: null, last_evaluated_at: null,
  last_run_status: "", last_run_error: "", updated_at: "", test_count: 2, open_alerts: 0,
};

describe("activationBlocker", () => {
  it("allows a compiled rule with passing tests", () => expect(activationBlocker(base)).toBeNull());
  it("explains each blocker", () => {
    expect(activationBlocker({ ...base, executable: false, unsupported: ["regex"] })).toContain("regex");
    expect(activationBlocker({ ...base, test_count: 0 })).toContain("at least one test");
    expect(activationBlocker({ ...base, tests_passed: false })).toContain("fail");
    expect(activationBlocker({ ...base, tests_passed: null })).toContain("Run the tests");
  });
});

describe("parseEvent", () => {
  it("accepts objects only and reports JSON errors", () => {
    expect(parseEvent('{"a":1}').event).toEqual({ a: 1 });
    expect(parseEvent("[1]").error).toBeTruthy();
    expect(parseEvent("{bad").error).toContain("Invalid JSON");
  });
});
