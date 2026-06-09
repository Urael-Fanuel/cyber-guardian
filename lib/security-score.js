"use strict";

function securityScoreForResult(result, decisionOverride = "") {
  const threatScore = Math.max(0, Math.min(100, Number(result?.threat_score || 0)));
  const threats = Array.isArray(result?.threats) ? result.threats : [];
  const threatCount = Math.max(0, Number(result?.threat_count || threats.length || 0));
  const hasThreatSummary = Boolean(String(result?.threats_summary || "").trim());
  const hasThreatEvidence = threats.length > 0 || threatCount > 0 || hasThreatSummary;
  const status = String(result?.status || "STATUS_AMBIGUOUS");
  const decision = String(decisionOverride || result?.decision || "").toLowerCase();
  const isSafe = !hasThreatEvidence
    && (decision === "safe" || (status === "STATUS_SAFE" && threatScore < 20));
  const isBlocked = decision === "blocked";

  if (isSafe) return Math.max(96, Math.min(100, 100 - Math.round(threatScore / 4)));
  if (isBlocked) return Math.max(0, Math.min(39, 100 - Math.round(threatScore)));
  if (status === "STATUS_MODERATE" || status === "STATUS_CRITICAL" || hasThreatEvidence || decision === "review") {
    return Math.max(40, Math.min(95, 100 - Math.round(threatScore)));
  }
  return Math.max(40, Math.min(79, 100 - Math.round(threatScore)));
}

function sandboxRanClean(result) {
  const sandbox = result?.dynamic_sandbox && typeof result.dynamic_sandbox === "object"
    ? result.dynamic_sandbox
    : null;
  if (!sandbox) return false;
  return String(sandbox.status || "").toLowerCase() === "completed"
    && String(sandbox.verdict || "").toLowerCase() === "clean";
}

function cleanAutomatedReview(result, decisionOverride = "") {
  const decision = String(decisionOverride || result?.decision || "").toLowerCase();
  const threats = Array.isArray(result?.threats) ? result.threats : [];
  const threatCount = Math.max(0, Number(result?.threat_count || threats.length || 0));
  const hasThreatSummary = Boolean(String(result?.threats_summary || "").trim());
  return decision === "safe"
    && threats.length === 0
    && threatCount === 0
    && !hasThreatSummary
    && securityScoreForResult(result, decision) >= 96;
}

function isVerifiedInstallResult(result, decisionOverride = "") {
  return cleanAutomatedReview(result, decisionOverride) && sandboxRanClean(result);
}

function verificationLevelForResult(result, decisionOverride = "") {
  if (!cleanAutomatedReview(result, decisionOverride)) return "";
  return sandboxRanClean(result) ? "verified" : "no_issues_detected";
}

module.exports = {
  securityScoreForResult,
  isVerifiedInstallResult,
  verificationLevelForResult,
};
