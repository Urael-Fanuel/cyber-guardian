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

function isVerifiedInstallResult(result, decisionOverride = "") {
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

module.exports = {
  securityScoreForResult,
  isVerifiedInstallResult,
};
