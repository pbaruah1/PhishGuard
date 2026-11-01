(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const LEVELS = new Set(['safe', 'informational', 'suspicious', 'dangerous', 'uncertain']);
  const textOnly = new Set(['text', 'page-text', 'phrase', 'keyword', 'quote', 'snippet', 'article']);

  function normalizeAssessment(value) {
    if (!value || typeof value !== 'object') return null;
    const verdict = String(value.verdict || '').toLowerCase();
    if (!LEVELS.has(verdict)) return null;
    const confidence = Math.max(0, Math.min(1, Number(value.confidence) || 0));
    const evidence = Array.isArray(value.evidence) ? value.evidence.slice(0, 12).map((item) => ({
      id: String(item && item.id || '').slice(0, 24),
      type: String(item && item.type || '').slice(0, 40),
      severity: ['info', 'low', 'medium', 'high', 'critical'].includes(String(item && item.severity)) ? String(item.severity) : 'info',
      explanation: String(item && item.explanation || '').slice(0, 360)
    })).filter((item) => item.id && item.explanation) : [];
    return {
      verdict,
      confidence,
      engine: ['local-ml', 'onnx-transformer'].includes(value.engine) ? value.engine : 'gemini-nano',
      summary: String(value.summary || '').slice(0, 600),
      evidence,
      selection: value.selection && typeof value.selection === 'object' ? {
        verdict: String(value.selection.verdict || 'uncertain'),
        confidence: Math.max(0, Math.min(1, Number(value.selection.confidence) || 0)),
        summary: String(value.selection.summary || '').slice(0, 500)
      } : null,
      limitations: Array.isArray(value.limitations) ? value.limitations.slice(0, 5).map((x) => String(x).slice(0, 180)) : []
    };
  }

  function isExternalHost(host, pageHost) {
    const h = String(host || '').toLowerCase().replace(/^www\./, '');
    const p = String(pageHost || '').toLowerCase().replace(/^www\./, '');
    return !!h && !!p && h !== p;
  }

  function hasGroundedEvidence(assessment, snapshot) {
    const page = snapshot || {};
    const forms = Array.isArray(page.forms) ? page.forms : [];
    const links = Array.isArray(page.links) ? page.links : [];
    const downloads = Array.isArray(page.downloads) ? page.downloads : [];
    const elements = Array.isArray(page.elements) ? page.elements : [];
    const remote = Array.isArray(page.remoteLinkScans) ? page.remoteLinkScans : [];
    const grounded = { suspicious: false, dangerous: false, evidence: [] };

    for (const ev of assessment.evidence) {
      if (/^F\d+$/.test(ev.id)) {
        const form = forms[Number(ev.id.slice(1))];
        // A different origin is not inherently suspicious. Require a genuinely
        // cross-site form that collects a secret/payment field. Subdomains and
        // same-site identity flows are deliberately not treated as exfiltration.
        if (form && form.crossSite === true &&
            (form.hasPassword || form.hasPaymentField || form.hasSensitiveField)) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (/^R\d+$/.test(ev.id)) {
        const scan = remote[Number(ev.id.slice(1))];
        const result = scan && scan.result;
        const remoteScripts = result && result.inventory && Array.isArray(result.inventory.scripts)
          ? result.inventory.scripts : [];
        const coordinatedInlineScript = remoteScripts.some((script) => {
          const flags = new Set(script && Array.isArray(script.behaviorSignals) ? script.behaviorSignals : []);
          return script && script.inline === true && script.executable === true &&
            flags.has('dynamic-code-execution') && flags.has('runtime-decoding') &&
            (flags.has('scripted-network-request') || flags.has('dynamic-script-insertion') || flags.has('clipboard-access'));
        });
        if (result && (result.criticalFindings > 0 ||
            (Array.isArray(result.evidence) && result.evidence.some((x) => ['critical', 'high'].includes(x.severity))) ||
            coordinatedInlineScript)) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
        if (result && result.confirmedMalware === true) {
          grounded.dangerous = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (/^D\d+$/.test(ev.id)) {
        const item = downloads[Number(ev.id.slice(1))];
        // Executables are common on legitimate vendor sites. They can support
        // a cautious warning, never a dangerous verdict on their own.
        if (item && item.executable && item.href && item.downloadAction === true) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (/^L\d+$/.test(ev.id)) {
        const link = links[Number(ev.id.slice(1))];
        if (link && (link.remoteRisk === 'malicious' || link.remoteRisk === 'warn')) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
        if (link && link.confirmedMalware === true) {
          grounded.dangerous = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (ev.id === 'B0') {
        const behavior = page.pageBehavior || {};
        const activeBehaviors = [
          behavior.fullscreenOnLoad === true,
          behavior.alarmAudio === true,
          Number(behavior.dialogFloodCount) >= 5,
          Number(behavior.beforeUnloadCount) >= 2,
          behavior.notificationPermissionRequested === true
        ].filter(Boolean).length;
        // A single event is common on legitimate sites. Multiple independent
        // observations may support AI-agreed suspicion, never danger alone.
        if (activeBehaviors >= 2) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (/^E\d+$/.test(ev.id)) {
        const element = elements[Number(ev.id.slice(1))];
        const flags = new Set(element && Array.isArray(element.evidenceFlags) ? element.evidenceFlags : []);
        const behaviors = new Set(element && Array.isArray(element.behaviorSignals) ? element.behaviorSignals : []);
        // Element-level reasoning is allowed only when the snapshot contains
        // specific executable/redirect behavior, never because an element is
        // merely hidden, external, scripted, or unfamiliar.
        const multiBehaviorScript = element && element.kind === 'script' && element.inline === true &&
          element.executable === true && behaviors.size >= 2 && flags.has('multi-behavior-inline-script');
        const activeLink = element && element.kind === 'interactive-control' && flags.has('active-link-scheme');
        const externalRedirect = element && element.kind === 'dom-element' && flags.has('external-meta-refresh');
        const scriptableFrame = element && element.kind === 'dom-element' && flags.has('scriptable-srcdoc-frame');
        if (multiBehaviorScript || activeLink || externalRedirect || scriptableFrame) {
          grounded.suspicious = true;
          grounded.evidence.push(ev.id);
        }
      }
      if (textOnly.has(ev.type.toLowerCase())) continue;
    }
    return grounded;
  }

  function resolveAiVerdict(rawAssessment, snapshot, hardSignals) {
    const hard = hardSignals || {};
    const page = snapshot || {};
    const links = Array.isArray(page.links) ? page.links : [];
    const hasLinkedFeedBlock = links.some((link) => link && link.verifiedThreatFeed === true);
    const baseReasons = [];
    if (hard.confirmedFeedBlock) baseReasons.push({ code: 'feedBlock', kind: 'link' });
    if (hasLinkedFeedBlock) baseReasons.push({ code: 'linkedDestinationFeedBlock', kind: 'link' });
    if (hard.confirmedRemoteMalware) baseReasons.push({ code: 'remoteDestinationConfirmedMalicious', kind: 'link' });
    if (baseReasons.length) return {
      level: 'dangerous', score: 0.99, confidence: 1, source: 'verified-evidence',
      summary: 'PhishGuard confirmed a high-confidence technical threat.', reasons: baseReasons,
      reasonCodes: baseReasons.map((x) => x.code), aiAvailable: !!rawAssessment
    };

    const assessment = normalizeAssessment(rawAssessment);
    if (!assessment) return {
      level: 'unknown', score: 0, confidence: 0, source: 'ai-unavailable',
      summary: 'On-device AI is not active. Passive wording and keyword matches are not treated as threats.',
      reasons: [], reasonCodes: [], aiAvailable: false
    };

    const grounded = hasGroundedEvidence(assessment, snapshot);
    if (assessment.engine === 'local-ml' || assessment.engine === 'onnx-transformer') {
      const ml = page.localMl || {};
      const pageProbability = Number(ml.pageProbability);
      const onnxProbability = Number(ml.onnxTextProbability);
      // Neither text classification nor the old page classifier is sufficient
      // alone. A local ONNX page warning additionally needs a grounded
      // cross-site secret-collecting form and a strong text-model signal. On
      // devices where the page model is disabled, require a stricter ONNX
      // confidence threshold. Educational/search context suppresses passive
      // text-only classification, but never hides a verified feed block above.
      const corroboratedForm = assessment.evidence.some((item) => /^F\d+$/.test(item.id) &&
        grounded.evidence.includes(item.id));
      const hasPageModelSupport = Number.isFinite(pageProbability) && pageProbability >= 0.8;
      const hasOnnxSupport = Number.isFinite(onnxProbability) && onnxProbability >=
        (page.deviceProfile && page.deviceProfile.usePageModelFallback === false ? 0.96 : 0.88);
      const educational = !!(page.pageContext && (page.pageContext.isSearchResultsPage ||
        page.pageContext.hasEducationalCue || page.pageContext.articleLike));
      const modelCorroborated = assessment.engine === 'onnx-transformer'
        ? hasOnnxSupport && (hasPageModelSupport || onnxProbability >= 0.97)
        : hasPageModelSupport;
      const suspicious = assessment.verdict === 'suspicious' && corroboratedForm && modelCorroborated &&
        assessment.confidence >= 0.75 && !educational;
      const level = suspicious ? 'suspicious' :
        (assessment.verdict === 'informational' || educational || assessment.verdict === 'dangerous' && !grounded.dangerous)
          ? 'informational' : 'unknown';
      const reasons = suspicious ? assessment.evidence.filter((item) => grounded.evidence.includes(item.id))
        .slice(0, 3).map((item) => ({ code: 'aiEvidence', kind: 'page', params: [item.explanation] })) : [];
      return {
        level, score: suspicious ? 0.62 : 0, confidence: assessment.confidence,
        source: assessment.engine === 'onnx-transformer' ? 'local-onnx-fallback' : 'local-ml-fallback',
        summary: assessment.summary,
        reasons, reasonCodes: reasons.map((item) => item.code), aiAvailable: true,
        aiGenerative: false, aiEngine: assessment.engine, aiGrounded: suspicious,
        aiEvidence: suspicious ? assessment.evidence : [],
        modelScores: { pageProbability: Number.isFinite(pageProbability) ? pageProbability : null,
          onnxTextProbability: Number.isFinite(onnxProbability) ? onnxProbability : null },
        limitations: assessment.limitations
      };
    }
    let level = assessment.verdict;
    if (level === 'uncertain') level = 'unknown';

    // A language model must not be able to escalate a page based on its own
    // narrative. Suspicious needs corroborated page structure or a remote scan.
    // Dangerous requires independent confirmation from a trusted source, not
    // merely a cross-site form or an executable download.
    if (level === 'dangerous') {
      if (grounded.dangerous && assessment.confidence >= 0.9) level = 'dangerous';
      else if (grounded.suspicious && assessment.confidence >= 0.58) level = 'suspicious';
      else level = 'informational';
    }
    if (level === 'suspicious' && (!grounded.suspicious || assessment.confidence < 0.58)) level = 'informational';
    if ((level === 'informational' || level === 'safe') && assessment.confidence < 0.35) level = 'unknown';

    const reasons = assessment.evidence.filter((x) => !textOnly.has(x.type.toLowerCase()) && grounded.evidence.includes(x.id))
      .slice(0, 5).map((x) => ({ code: 'aiEvidence', kind: 'page', params: [x.explanation] }));
    return {
      level, score: level === 'dangerous' ? 0.95 : level === 'suspicious' ? 0.62 : 0,
      confidence: assessment.confidence, source: 'on-device-generative-ai', aiGenerative: true, aiEngine: 'gemini-nano',
      summary: assessment.summary || 'The page structure and available destination observations were assessed by on-device AI.',
      reasons, reasonCodes: reasons.map((x) => x.code), aiAvailable: true,
      aiGrounded: grounded.suspicious, aiConfirmed: grounded.dangerous, aiEvidence: assessment.evidence
    };
  }


  return { normalizeAiAssessment: normalizeAssessment, hasGroundedAiEvidence: hasGroundedEvidence, resolveAiVerdict };
});
