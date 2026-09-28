import { test } from "node:test";
import assert from "node:assert/strict";
import { sparklineGeometry, fuzzyScore, catchAllAliasPayload, plainAliasPayload, firewallRuleRows } from "../src/consoleLogic.ts";

test("sparkline geometry renders two-point minimum and pads the box", () => {
  const single = sparklineGeometry([5], 100, 30);
  assert.equal(single.line, "", "a single point must not render a path");
  const flat = sparklineGeometry([4, 4, 4], 100, 30);
  assert.ok(flat.line.startsWith("M3"), "degenerate span still produces a padded path");
  const rising = sparklineGeometry([0, 10], 103, 33, 3);
  assert.match(rising.line, /^M3(\.\d+)?,\d+(\.\d+)? L100(\.\d+)?,3(\.\d+)?$/, "ramp spans pad..width and ends at the top pad");
  assert.match(rising.area, /Z$/, "area path closes back to the baseline");
});

test("sparkline normalizes descending series into an upward line", () => {
  const { line } = sparklineGeometry([10, 0], 103, 33, 3);
  const yCoordinates = [...line.matchAll(/,(\d+(?:\.\d+)?)/g)].map((match) => Number(match[1]));
  assert.ok(yCoordinates[0] < yCoordinates[1], "first value maps higher on the box than the second");
});

test("fuzzy scoring ranks word starts and rejects non-matches", () => {
  assert.equal(fuzzyScore("zzz", "Create site"), 0, "missing character must score zero");
  const wordStart = fuzzyScore("cr", "Create site");
  const midWord = fuzzyScore("re", "Create site");
  assert.ok(wordStart > midWord, "matching a word start outranks a mid-word match");
  assert.ok(fuzzyScore("", "anything") > 0, "the empty query matches everything");
});

test("catch-all payload builds the domain-source alias and validates input", () => {
  assert.equal("error" in catchAllAliasPayload({ domainId: "example.invalid", target: "nope" }), true, "target without @ is rejected");
  assert.equal("error" in catchAllAliasPayload({ domainId: "bad", target: "a@b.c" }), true, "invalid domain is rejected");
  const built = catchAllAliasPayload({ domainId: "Example.INVALID", target: "Owner@Example.invalid" });
  assert.equal("error" in built, false);
  assert.deepEqual(built.alias, { domain: "example.invalid", source: "example.invalid", targets: ["owner@example.invalid"], catch_all: true });
});

test("plain alias payload composes the full source address", () => {
  const invalid = plainAliasPayload({ domainId: "example.invalid", source: "info@example.invalid", targets: ["a@b.c"] });
  assert.equal("error" in invalid, true, "source containing @ is rejected");
  const noTargets = plainAliasPayload({ domainId: "example.invalid", source: "info", targets: [] });
  assert.equal("error" in noTargets, true, "at least one target is required");
  const built = plainAliasPayload({ domainId: "example.invalid", source: "Info", targets: ["a@b.c", "  "] });
  assert.deepEqual(built.alias, { domain: "example.invalid", source: "info@example.invalid", targets: ["a@b.c"], catch_all: false });
});

test("firewall rows summarize direction, protocol, port, and sources with stable keys", () => {
  const rows = firewallRuleRows([{ id: "r1", action: "allow", protocol: "tcp", port: 443, source_cidrs: ["0.0.0.0/0"], direction: "inbound" }, { protocol: "udp" }]);
  assert.equal(rows[0].summary, "inbound · tcp 443 · 0.0.0.0/0");
  assert.equal(rows[0].key, "r1");
  assert.equal(rows[1].summary, "inbound · udp any · anywhere");
  assert.match(rows[1].key, /^inbound:udp:any:anywhere:1$/, "missing identity falls back to a stable synthetic key");
});
