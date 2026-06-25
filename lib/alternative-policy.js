"use strict";

const {
  isVerifiedInstallResult,
  securityScoreForResult,
} = require("./security-score");

const VERIFIED_ALTERNATIVE_SCORE = 96;

function isVerifiedAlternativeCandidate(candidate, decisionOverride = "") {
  const decision = String(decisionOverride || candidate?.decision || "").toLowerCase();
  const sourceUrl = String(candidate?.source_url || "").trim();
  const explicitScore = Number(candidate?.security_score);
  if (decision !== "safe" || !sourceUrl) return false;
  if (Number.isFinite(explicitScore) && explicitScore < VERIFIED_ALTERNATIVE_SCORE) return false;
  return isVerifiedInstallResult(candidate, decision)
    && securityScoreForResult(candidate, decision) >= VERIFIED_ALTERNATIVE_SCORE;
}

module.exports = {
  VERIFIED_ALTERNATIVE_SCORE,
  isVerifiedAlternativeCandidate,
};
