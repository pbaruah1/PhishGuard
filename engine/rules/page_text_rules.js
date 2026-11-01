(function (root, factory) {
  const mod = factory(root);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (root) {
  'use strict';

  const SECRET_REQUEST = /\b(?:enter|type|provide|share|send|submit|re[- ]?enter|confirm|reply(?:\s+with)?|paste)\b[^.!?;:\n]{0,70}\b(?:password|passcode|one[- ]?time (?:password|code)|otp|verification code|security code|pin|cvv|cvc|card number|bank details|routing number|social security number|ssn|recovery phrase|seed phrase|private key)\b/i;
  const SECRET_TARGET = /\b(?:password|passcode|one[- ]?time (?:password|code)|otp|verification code|security code|pin|cvv|cvc|card number|bank details|routing number|social security number|ssn|recovery phrase|seed phrase|private key)\b/i;
  const ACCOUNT_EVENT = /\b(?:account|profile|mailbox|email|bank(?:ing)?|card|subscription|payroll|payment|wallet|tax|delivery|parcel|package|shipment|document)\b[^.!?;\n]{0,100}\b(?:unusual|suspicious|unauthori[sz]ed|compromis(?:ed|e)|locked|lockout|suspend(?:ed|sion)?|restrict(?:ed|ion)?|block(?:ed)?|disable(?:d)?|deactivat(?:ed|ion)|expir(?:e|ed|ing)|pending|on hold|full|failed|declined|limited|overdue|problem|issue|alert)\b|\b(?:unusual activity|suspicious activity|security alert|new sign[ -]?in|unknown device|unauthori[sz]ed access|account locked|account suspended|account restricted|payment failed|deposit pending|mailbox(?: is)? full|storage(?: is)? full)\b/i;
  const ACTION_INTENT = /\b(?:click|tap|open|visit|follow|go to|sign in|log in|verify|confirm|update|review|complete|resolve|restore|unlock|reactivate|submit|enter|provide|reply|call|contact|pay|settle|release|download|install)\b/i;
  const SENSITIVE_REQUEST = /\b(?:identity|personal information|personal details|account details|billing information|billing details|payment details|card details|card information|bank details|banking details|direct deposit|routing number|social security|\bssn\b|tax id|passport|driver'?s license|email address|phone number|password|passcode|verification code|otp|pin|cvv|recovery phrase|seed phrase|private key)\b/i;
  const DELIVERY_CONTEXT = /\b(?:parcel|package|shipment|delivery|courier|customs|postal|tracking number)\b/i;
  const PAYMENT_DEMAND = /\b(?:pay|payment|fee|charge|billing|wire transfer|bank transfer|gift cards?|cryptocurrency|crypto|bitcoin|wallet deposit|refundable deposit|processing cost)\b/i;
  const AUTHORITY_CONTEXT = /\b(?:bank|credit union|payroll|human resources|microsoft|google|apple|amazon|irs|tax authority|customs|postal service|courier|delivery service|support team|help desk|it department|security team|administrator)\b/i;
  const URGENCY = /\b(?:immediately|right away|today|within\s+\d+\s+(?:minutes?|hours?|days?)|before\s+(?:midnight|\d)|by\s+(?:midnight|\d)|final notice|last chance|expires?\s+(?:today|soon))\b/i;
  const CLICKFIX = /\b(?:press|hold|open)\s+(?:the\s+)?(?:windows?\s*)?(?:win\s*\+\s*r|windows\s*\+\s*r|run dialog|run box)\b|\b(?:paste|type)\s+(?:this|the)\s+(?:command|code)\b/i;
  const REMOTE_SUPPORT = /\b(?:install|download)\s+(?:anydesk|teamviewer|remote support|remote access)|\b(?:give|grant)\s+(?:me|them|support)\s+remote access\b/i;
  const NEGATION = /\b(?:do not|don't|dont|never|should not|shouldn't|will not|won't|will never)\b[^.!?;:\n]{0,36}$/i;

  function normalize(text) {
    return String(text == null ? '' : text).normalize('NFKC')
      .replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, '')
      .replace(/[\u2010-\u2015]/g, '-')
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }

  function hasUnnegated(text, regex) {
    const re = new RegExp(regex.source, 'gi');
    let match;
    while ((match = re.exec(text))) {
      const prefix = text.slice(Math.max(0, match.index - 110), match.index);
      const clause = prefix.split(/[.!?;:\n]|,\s*(?:but|however|instead|please|now)\b/i).pop() || '';
      if (!NEGATION.test(clause)) return true;
      if (!match[0]) re.lastIndex++;
    }
    return false;
  }

  function scorePageText(input, context) {
    const text = normalize(input).slice(0, 60000);
    const ctx = context || {};
    const formCount = Math.max(0, Number(ctx.formCount) || 0);
    const linkCount = Math.max(0, Number(ctx.linkCount) || 0);
    const ctaCount = Math.max(0, Number(ctx.ctaCount) || 0);
    const hasPasswordField = !!ctx.hasPasswordField;
    const hasCardInput = !!ctx.hasCardInput;
    const hasActionSurface = formCount > 0 || ctaCount > 0;
    const reasoner = root.PhishGuard || {};
    const pageContext = ctx.pageContext || (typeof reasoner.classifyPageContext === 'function'
      ? reasoner.classifyPageContext(text, ctx) : null);
    if (pageContext && pageContext.passiveInformational && ctx.forceAnalyzeContent !== true) {
      return {
        score: 0, reasons: [], flags: [], suppressed: 'passive-informational-context',
        signals: { educationalContext: true, searchResults: !!pageContext.isSearchResultsPage },
        context: pageContext
      };
    }
    const accountEvent = ACCOUNT_EVENT.test(text);
    const actionIntent = ACTION_INTENT.test(text);
    const sensitiveRequest = SENSITIVE_REQUEST.test(text);
    const secretRequest = hasUnnegated(text, SECRET_REQUEST);
    const recoveryRequest = hasUnnegated(text, /\b(?:enter|type|provide|share|send|submit|paste|confirm)\b[^.!?;:\n]{0,65}\b(?:recovery phrase|seed phrase|private key|wallet recovery words)\b/i);
    const deliveryContext = DELIVERY_CONTEXT.test(text);
    const paymentDemand = PAYMENT_DEMAND.test(text);
    const authorityContext = AUTHORITY_CONTEXT.test(text);
    const deadlinePressure = URGENCY.test(text);
    const clickfix = CLICKFIX.test(text);
    const remoteSupport = REMOTE_SUPPORT.test(text);
    let score = 0;
    const flags = [];
    const reasons = [];
    let label = '';

    if (clickfix) { score = 0.96; flags.push('page-text-command-execution'); label = 'command execution disguised as verification'; }
    if (recoveryRequest) { score = Math.max(score, 0.97); flags.push('page-text-recovery-secret'); label = 'request for a wallet recovery secret'; }
    else if (secretRequest && (hasPasswordField || hasCardInput || hasActionSurface || linkCount > 0)) {
      score = Math.max(score, 0.78); flags.push('page-text-secret-request'); label = 'request to disclose an account or payment secret';
    }
    if (deliveryContext && paymentDemand && actionIntent && (hasActionSurface || linkCount > 0)) {
      score = Math.max(score, 0.76); flags.push('page-text-delivery-payment'); label = 'delivery notice paired with a payment demand';
    }
    if (accountEvent && actionIntent && (hasActionSurface || linkCount > 0)) {
      let contextual = 0.64;
      if (authorityContext) contextual += 0.04;
      if (sensitiveRequest) contextual += 0.05;
      if (deadlinePressure) contextual += 0.04;
      if (hasPasswordField || hasCardInput) contextual += 0.05;
      score = Math.max(score, Math.min(0.78, contextual));
      flags.push('page-text-account-pressure');
      label = label || 'account or security warning paired with an action request';
    }
    if (remoteSupport && actionIntent) {
      score = Math.max(score, 0.78); flags.push('page-text-remote-support'); label = 'remote-access installation request';
    }
    if (!score && hasCardInput && paymentDemand && (actionIntent || hasActionSurface)) {
      score = 0.66; flags.push('page-text-card-payment'); label = 'payment request on a page collecting card information';
    }

    if (score >= 0.5) reasons.push({ code: 'contentPhishingPattern', kind: 'page', params: [label] });
    return {
      score: Number(Math.min(1, score).toFixed(4)), reasons, flags,
      signals: { accountEvent, actionIntent, sensitiveRequest, secretRequest, recoveryRequest, deliveryContext, paymentDemand, authorityContext, deadlinePressure, clickfix, remoteSupport },
      context: pageContext
    };
  }

  function mergePageTextRules(base, textRules) {
    const current = base || { score: 0, reasons: [], flags: [] };
    if (!textRules) return current;
    const currentScore = Number(current.score) || 0;
    const evidenceScore = Number(textRules.score) || 0;
    const higherEvidence = evidenceScore > currentScore;
    const reasons = [];
    const seen = new Set();
    for (const reason of [...(current.reasons || []), ...(textRules.reasons || [])]) {
      const key = reason && typeof reason === 'object' ? reason.code + '|' + JSON.stringify(reason.params || []) : String(reason);
      if (!seen.has(key)) { seen.add(key); reasons.push(reason); }
    }
    const evidence = [...(current.evidence || []), ...(textRules.evidence || [])];
    const evidenceSeen = new Set();
    const uniqueEvidence = evidence.filter((item) => {
      const key = item && (item.code || item.detail) || String(item);
      if (evidenceSeen.has(key)) return false;
      evidenceSeen.add(key); return true;
    });
    return Object.assign({}, current, {
      score: Math.max(currentScore, evidenceScore),
      independentScore: Number.isFinite(Number(current.independentScore)) ? Number(current.independentScore) : currentScore,
      reasons,
      flags: higherEvidence ? [...new Set([...(current.flags || []), ...(textRules.flags || [])])] : (current.flags || []),
      evidence: uniqueEvidence
    });
  }

  return { scorePageText, normalizePageText: normalize, mergePageTextRules };
});
