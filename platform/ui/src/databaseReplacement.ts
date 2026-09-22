export type ReplacementImportJob = { id: string; database_generation: number; [key: string]: unknown };
type ReplacementScope = { tenant: string; site: string; database: string; generation: number };

// This is a display/admission check only. Inspection and retirement remain
// authorized against current server state; a browser-supplied job is not proof.
export function resumableReplacement(value: unknown, requestedID: string, scope: ReplacementScope): ReplacementImportJob {
  const invalid = () => new Error("This is not a completed replacement for the selected tenant, site, database, and current generation.");
  if (!value || typeof value !== "object" || !("status" in value) || value.status !== "completed" || !("job" in value)) throw invalid();
  const candidate = value.job;
  if (!candidate || typeof candidate !== "object") throw invalid();
  const job = candidate as Record<string, unknown>;
  if (job.id !== requestedID || job.direction !== "import" || job.conflict_policy !== "replace" ||
      job.tenant_id !== scope.tenant || job.site_id !== scope.site || job.database_id !== scope.database ||
      !Number.isSafeInteger(scope.generation) || scope.generation < 2 || job.database_generation !== scope.generation - 1 ||
      typeof job.restore_point_ref !== "string" || !job.restore_point_ref ||
      typeof job.restore_point_digest !== "string" || !/^[a-f0-9]{64}$/.test(job.restore_point_digest) ||
      typeof job.digest !== "string" || !/^[a-f0-9]{64}$/.test(job.digest)) throw invalid();
  return candidate as ReplacementImportJob;
}
