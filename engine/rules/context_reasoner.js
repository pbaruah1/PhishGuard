(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  // Exact search hosts only. Do not treat accounts.google.com or other Google
  // services as search-result pages simply because they share the parent domain.
  const SEARCH_HOST = /^(?:(?:www\.)?google\.(?:com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})|(?:www\.)?bing\.com|(?:www\.)?duckduckgo\.com|html\.duckduckgo\.com|search\.brave\.com|(?:www\.)?ecosia\.org|search\.yahoo\.com|(?:www\.)?startpage\.com|search\.qwant\.com)$/i;
  const EDUCATION_TERMS = /\b(?:phishing|phish|scam|fraud|malware|social engineering|cybersecurity|cyber security)\b.{0,110}\b(?:examples?|samples?|training|awareness|simulation|research|study|lesson|tutorial|guide|explained|recogni[sz]e|identify|spot|detect|prevent|analysis|case study|classroom|assignment|demonstration|demo)\b|\b(?:examples?|samples?)\s+(?:of\s+)?(?:phishing|phish|scam|fraud|malware|social engineering)\b|\b(?:how to|learn to|guide to|training on|study of|case study of)\s+(?:recogni[sz]e|identify|spot|detect|prevent|understand)?\s*(?:phishing|scams?|fraud|malware)\b/i;
  const EDUCATION_META = /\b(?:security awareness|anti[- ]phishing|educational (?:resource|material|content)|for (?:a )?class|class assignment|research paper|academic (?:study|research)|training (?:exercise|material|module)|phishing simulation|article|overview|discussion|lesson|report)\b.{0,90}\b(?:phishing|phish|scam|fraud|malware|social engineering)\b|\b(?:phishing|phish|scam|fraud|malware|social engineering)\b.{0,90}\b(?:article|overview|discussion|lesson|report|explains?|explained)\b/i;
  const ACCOUNT_EVENT = /\b(?:account|profile|mailbox|email|bank(?:ing)?|card|subscription|payroll|payment|wallet|tax|delivery|parcel|package|shipment)\b[^.!?;:\n]{0,100}\b(?:unusual|unauthori[sz]ed|compromis(?:ed|e)|locked|suspend(?:ed|sion)?|restrict(?:ed|ion)?|disable(?:d)?|expir(?:e|ed|ing)|pending|failed|declined|overdue|alert)\b|\b(?:unusual activity|account locked|account suspended|payment failed|mailbox full)\b/i;
  const SECRET_ASK = /\b(?:enter|type|provide|share|send|submit|reply with|paste|confirm|verify|validate|sign in with|log in with)\b[^.!?;:\n]{0,80}\b(?:password|passcode|one[- ]time (?:password|code)|otp|verification code|security code|pin|cvv|cvc|card number|bank details|routing number|social security number|ssn|recovery phrase|seed phrase|private key)\b/i;
  const SEED_ASK = /\b(?:enter|type|provide|share|send|submit|paste|confirm)\b[^.!?;:\n]{0,80}\b(?:recovery phrase|seed phrase|private key|wallet recovery words)\b/i;
  const ACTION = /\b(?:click|tap|open|visit|follow|go to|sign in|log in|verify|confirm|update|review|complete|resolve|restore|unlock|submit|enter|provide|reply|call|pay|settle|download|install)\b/i;
  const URGENCY = /\b(?:immediately|right away|urgent|within\s+\d+\s+(?:minutes?|hours?|days?)|before\s+(?:midnight|\d)|final notice|last chance|expires?\s+(?:today|soon))\b/i;
  const DELIVERY = /\b(?:parcel|package|shipment|delivery|courier|customs|postal|tracking number)\b/i;
  const PAYMENT = /\b(?:pay|payment|fee|charge|billing|wire transfer|bank transfer|gift cards?|cryptocurrency|crypto|bitcoin|wallet deposit|processing cost)\b/i;
  const COMMAND_EXECUTION = /\b(?:press|hold|open)\s+(?:the\s+)?(?:windows?\s*)?(?:win\s*\+\s*r|windows\s*\+\s*r|run dialog|run box)\b|\b(?:paste|type)\s+(?:this|the)\s+(?:command|code)\b/i;
  const REMOTE_ACCESS = /\b(?:install|download)\s+(?:anydesk|teamviewer|remote support|remote access)|\b(?:give|grant)\s+(?:me|them|support)\s+remote access\b/i;

  function normalize(value) {
    return String(value == null ? '' : value).normalize('NFKC')
      .replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, '')
      .replace(/[\u2010-\u2015]/g, '-')
      .replace(/\s+/g, ' ').trim().toLowerCase();
  }

  function classifyPageContext(input, context) {
    const text = normalize(input).slice(0, 60000);
    const ctx = context || {};
    let host = String(ctx.pageHost || ctx.host || '');
    try { if (!host && ctx.url) host = new URL(ctx.url).hostname; } catch (_) {}
    const isSearchResultsPage = ctx.isSearchResultsPage === true || SEARCH_HOST.test(host);
    const hasEducationalCue = EDUCATION_TERMS.test(text) || EDUCATION_META.test(text) || EDUCATION_TERMS.test(normalize(ctx.title || ''));
    const articleLike = Number(ctx.articleCount || 0) > 0 || Number(ctx.mainCount || 0) > 0 ||
      Number(ctx.blockquoteCount || 0) > 0 || Number(ctx.codeBlockCount || 0) > 0 ||
      ctx.semanticArticle === true;
    const activeText = normalize(ctx.activeText == null ? text : ctx.activeText).slice(0, 40000);
    const activeSecretRequest = SECRET_ASK.test(activeText);
    const activeSeedRequest = SEED_ASK.test(activeText);
    const activeAccountPressure = ACCOUNT_EVENT.test(activeText) && ACTION.test(activeText);
    const clickfixPattern = /\b(?:win(?:dows)?\s*(?:key|logo)?\s*(?:\+|plus|and|,)\s*r|run (?:dialog|box))\b/i.test(activeText) &&
      /\b(?:paste|ctrl\s*(?:\+|plus)\s*v|powershell|command prompt|terminal)\b/i.test(activeText) &&
      /\b(?:captcha|human verification|verify (?:that )?you(?:'re| are) human|robot verification)\b/i.test(activeText);
    const hasOperationalClickfix = !!ctx.clickfixAction || (clickfixPattern &&
      (!articleLike || Number(ctx.formCount || 0) > 0 || Number(ctx.ctaCount || 0) >= 3));
    const hasDirectThreatSurface = !!(ctx.hasForeignCredentialForm || ctx.hasCrossOriginCredentialPost ||
      ctx.seedPhraseForm || ctx.dangerousDownload || ctx.knownMaliciousHost || ctx.confirmedFeedBlock ||
      (activeSeedRequest && Number(ctx.formCount || 0) > 0) ||
      (activeSecretRequest && (ctx.hasPasswordField || ctx.hasCardInput) ) ||
      (activeAccountPressure && Number(ctx.formCount || 0) > 0 && Number(ctx.ctaCount || 0) > 0));
    const educationalPage = hasEducationalCue && (articleLike || ctx.isSelectedText === true || ctx.educationalPage === true);
    const passiveInformational = !hasDirectThreatSurface && !hasOperationalClickfix &&
      (isSearchResultsPage || educationalPage);

    let pageKind = 'general';
    if (isSearchResultsPage) pageKind = 'search-results';
    else if (educationalPage) pageKind = 'educational-reference';
    else if (Number(ctx.articleCount || 0) > 0) pageKind = 'article';
    else if (Number(ctx.formCount || 0) > 0) pageKind = 'interactive';

    return {
      pageKind,
      isSearchResultsPage,
      hasEducationalCue,
      articleLike,
      hasDirectThreatSurface,
      hasOperationalClickfix,
      activeSecretRequest, activeSeedRequest, activeAccountPressure,
      passiveInformational,
      rationale: passiveInformational
        ? (isSearchResultsPage
          ? 'Search-result snippets are third-party quoted content, not proof that the search page is attacking the user.'
          : 'The page appears to discuss phishing or scams educationally; passive descriptions are not treated as active attacks.')
        : 'The page is assessed using its active controls, destinations, behavior, and threat indicators.'
    };
  }

  function suppressPassiveContentEvidence(textRules, pageContext) {
    if (!pageContext || !pageContext.passiveInformational || !textRules) return textRules;
    return Object.assign({}, textRules, {
      score: 0,
      reasons: [],
      flags: [],
      suppressed: 'passive-informational-context',
      originalTextScore: Number(textRules.score) || 0
    });
  }

  function analyzeSelectedText(input, context) {
    const text = normalize(input).slice(0, 12000);
    const ctx = context || {};
    if (!text) return {
      level: 'unknown', score: 0, category: 'empty',
      summary: 'No selected text was available to analyze. The page was still rescanned.', reasons: []
    };

    const educational = EDUCATION_TERMS.test(text) || EDUCATION_META.test(text) ||
      /\b(?:sample|example|excerpt|quoted|hypothetical)\b/i.test(text) && /\b(?:phishing|scam|fraud|malware)\b/i.test(text);
    const seedAsk = SEED_ASK.test(text);
    const secretAsk = SECRET_ASK.test(text);
    const accountPressure = ACCOUNT_EVENT.test(text) && ACTION.test(text);
    const urgency = URGENCY.test(text);
    const linkedAction = /https?:\/\/|\b(?:link below|this link|click here|button below|visit this page)\b/i.test(text);
    const deliveryPayment = DELIVERY.test(text) && PAYMENT.test(text) && ACTION.test(text);
    const commandExecution = COMMAND_EXECUTION.test(text);
    const remoteAccess = REMOTE_ACCESS.test(text);
    const safeWarning = /\b(?:never|do not|don't|dont|should not|shouldn't|will never)\b[^.!?;:\n]{0,100}\b(?:share|send|enter|provide|paste)\b[^.!?;:\n]{0,70}\b(?:password|otp|verification code|seed phrase|private key|card number)\b/i.test(text);

    if (educational && !seedAsk && !commandExecution && !remoteAccess) {
      return {
        level: 'informational', score: 0.08, category: 'educational-example',
        summary: 'This selection appears to be an educational, quoted, or example discussion of phishing. It is not evidence that the page hosting it is malicious. Treat any real message with the same instructions cautiously.',
        reasons: [{ code: 'selection-educational-context', kind: 'selection' }, { code: 'selection-no-active-behavior', kind: 'selection' }]
      };
    }
    if (safeWarning && !secretAsk) {
      return { level: 'safe', score: 0.04, category: 'security-advice',
        summary: 'The selected text appears to warn users against sharing sensitive information. This does not certify the surrounding page as safe.',
        reasons: [{ code: 'selection-protective-warning', kind: 'selection' }] };
    }

    let score = 0;
    const reasons = [];
    if (seedAsk) { score = Math.max(score, 0.94); reasons.push({ code: 'selection-recovery-secret-request', kind: 'selection' }); }
    if (secretAsk) { score = Math.max(score, 0.62); reasons.push({ code: 'selection-secret-request', kind: 'selection' }); }
    if (accountPressure) { score += 0.14; reasons.push({ code: 'selection-account-pressure', kind: 'selection' }); }
    if (urgency) { score += 0.08; reasons.push({ code: 'selection-urgency', kind: 'selection' }); }
    if (linkedAction) { score += 0.08; reasons.push({ code: 'selection-external-action', kind: 'selection' }); }
    if (deliveryPayment) { score = Math.max(score, 0.76); reasons.push({ code: 'selection-delivery-payment', kind: 'selection' }); }
    if (commandExecution) { score = Math.max(score, 0.88); reasons.push({ code: 'selection-command-execution', kind: 'selection' }); }
    if (remoteAccess) { score = Math.max(score, 0.84); reasons.push({ code: 'selection-remote-access', kind: 'selection' }); }
    score = Math.min(0.99, score);
    let level = 'safe', category = 'no-strong-indicators';
    if (score >= 0.85) { level = 'dangerous'; category = 'high-risk-content'; }
    else if (score >= 0.55) { level = 'suspicious'; category = 'phishing-like-content'; }
    const summary = level === 'dangerous'
      ? 'The selected text contains a high-risk instruction. This is a content assessment, not proof that the current page itself is malicious.'
      : level === 'suspicious'
        ? 'The selected text resembles a phishing or scam message. Verify the sender and destination independently; the selection alone does not establish that the hosting page is malicious.'
        : 'No strong phishing indicators were found in the selected text. This does not prove the content or page is safe.';
    return { level, score: Number(score.toFixed(3)), category, summary, reasons };
  }

  return { classifyPageContext, suppressPassiveContentEvidence, analyzeSelectedText, normalizeContextText: normalize };
});
