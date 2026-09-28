// Pure console logic with no Vue imports so node --test can exercise it
// directly. Components import from here; behavior changes need a test.

export interface SparkPoint { x: number; y: number }

// Builds a centered sparkline path plus a closing area polygon. Values are
// normalized to the box; an empty or single-point series yields "" so callers
// can render their placeholder instead.
export function sparklineGeometry(values: number[], width: number, height: number, pad = 3): { line: string; area: string } {
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length < 2 || width <= pad * 2 || height <= pad * 2) return { line: "", area: "" };
  const min = Math.min(...finite);
  const max = Math.max(...finite);
  const span = max - min || 1;
  const stepX = (width - pad * 2) / (finite.length - 1);
  const points: SparkPoint[] = finite.map((value, index) => ({
    x: pad + index * stepX,
    y: pad + (height - pad * 2) * (1 - (value - min) / span)
  }));
  const line = points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  const area = `${line} L${points[points.length - 1]!.x.toFixed(1)},${height - pad} L${points[0]!.x.toFixed(1)},${height - pad} Z`;
  return { line, area };
}

// Subsequence fuzzy score; higher is better, 0 means no match. Prefers
// consecutive and word-start hits so "createsite" ranks Create site first.
export function fuzzyScore(query: string, target: string): number {
  const needle = query.trim().toLowerCase();
  const haystack = target.toLowerCase();
  if (!needle) return 1;
  let score = 0;
  let cursor = 0;
  let streak = 0;
  for (const character of needle) {
    const found = haystack.indexOf(character, cursor);
    if (found < 0) return 0;
    streak = found === cursor ? streak + 1 : 1;
    score += 10 + streak * 4 + (found === 0 || /[\s/._-]/.test(haystack[found - 1] ?? "") ? 8 : 0);
    cursor = found + 1;
  }
  return score - Math.max(0, haystack.length - needle.length) / 8;
}

export interface CatchAllAliasInput { domainId: string; target: string; capability?: string }

// Payload for mail.alias.create/update when the operator chooses the
// catch-all representation: source is the bare domain, targets carry the
// delivery destination, and catch_all is the distinguishing flag.
export function catchAllAliasPayload(input: CatchAllAliasInput): { alias: { domain: string; source: string; targets: string[]; catch_all: boolean; capability?: string } } | { error: string } {
  const domain = input.domainId.trim().toLowerCase();
  const target = input.target.trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return { error: "Enter the mail domain this catch-all receives for." };
  if (!target || !target.includes("@")) return { error: "Enter a delivery target mailbox for unmatched addresses." };
  const alias: { domain: string; source: string; targets: string[]; catch_all: boolean; capability?: string } = {
    domain, source: domain, targets: [target], catch_all: true
  };
  if (input.capability && input.capability.trim()) alias.capability = input.capability.trim();
  return { alias };
}

export interface PlainAliasInput { domainId: string; source: string; targets: string[]; capability?: string }

// A regular forwarding alias: an exact local address on the domain forwards
// to one or more targets.
export function plainAliasPayload(input: PlainAliasInput): { alias: { domain: string; source: string; targets: string[]; catch_all: boolean; capability?: string } } | { error: string } {
  const domain = input.domainId.trim().toLowerCase();
  const source = input.source.trim().toLowerCase();
  const targets = input.targets.map((address) => address.trim().toLowerCase()).filter(Boolean);
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return { error: "Enter the mail domain." };
  if (!source || source.includes("@")) return { error: "Enter the local address without the domain (for example info)." };
  if (!targets.length || targets.some((address) => !address.includes("@"))) return { error: "Enter at least one full target address." };
  const alias: { domain: string; source: string; targets: string[]; catch_all: boolean; capability?: string } = {
    domain, source: `${source}@${domain}`, targets, catch_all: false
  };
  if (input.capability && input.capability.trim()) alias.capability = input.capability.trim();
  return { alias };
}

export interface FirewallRuleShape {
  id?: string;
  action?: string;
  protocol?: string;
  port?: string | number;
  source_cidrs?: string[];
  destination_cidrs?: string[];
  direction?: string;
  description?: string;
}

// One display row per firewall rule: a stable identity, a compact summary
// ("allow tcp 443 from 0.0.0.0/0"), and the original shape for the editor.
export interface FirewallRuleRow { key: string; summary: string; rule: FirewallRuleShape }

export function firewallRuleRows(rules: FirewallRuleShape[]): FirewallRuleRow[] {
  return rules.map((rule, index) => {
    const direction = String(rule.direction ?? "inbound");
    const protocol = String(rule.protocol ?? "any");
    const port = rule.port === undefined || rule.port === "" ? "any" : String(rule.port);
    const sources = (rule.source_cidrs ?? []).join(", ") || "anywhere";
    const key = String(rule.id ?? `${direction}:${protocol}:${port}:${sources}:${index}`);
    return { key, summary: `${direction} · ${protocol} ${port} · ${sources}`, rule };
  });
}
