(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(
    req ? require('../core/constants') : root.PhishGuard,
    req ? require('./heuristics') : root.PhishGuard
  );
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C, H) {
  'use strict';

  const { THRESHOLDS, SCAM_PHRASES = [] } = C;
  const MAX_LINKS = 12;
  const MAX_MESSAGE_CHARS = 20000;
  const TRIM_URL_END = /[.,;:!?]+$/;
  const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g;
  const CONFUSABLES = new Map(Object.entries({
    'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'о': 'o',
    'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y', 'ԁ': 'd', 'һ': 'h',
    'ɑ': 'a', 'ϲ': 'c', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x'
  }));

  const PHRASES = {
    delivery: [
      'held at customs', 'customs fee', 'delivery fee', 'redelivery fee',
      'shipping fee required', 'pay to release', 'parcel is held',
      'package is on hold', 'unpaid customs', 'address is incomplete, update'
    ],
    'account-threat': [
      'account will be blocked', 'account will be suspended', 'account has been frozen',
      'card will be deactivated', 'kyc has expired', 'update your kyc',
      'net banking will be suspended', 'debit card blocked', 'pan card update',
      'unusual activity detected', 'verify your account now', 'account access will be limited',
      'unblock your account', 'unblock the account', 'restore account access',
      'reactivate your account', 'unlock your account'
    ],
    employment: [
      'work from home', 'working from home', 'earn per day', 'no experience needed',
      'no experience required', 'limited slots', 'part-time job offer', 'daily payout',
      'hiring urgently', 'reply yes', 'pay a registration fee', 'training fee required'
    ],
    investment: [
      'double your investment', 'guaranteed returns', 'risk-free investment',
      'profit daily', 'investment plan', 'crypto giveaway', 'trading signals',
      'double your crypto', 'send crypto to receive', 'guaranteed profit',
      'guaranteed return', 'risk-free returns', 'no-risk returns', 'double your money'
    ],
    reward: [
      'lucky draw', 'lottery', 'you have been selected', 'claim your prize',
      'you won', 'you have won', 'congratulations you', 'claim your reward',
      'winner of our promotion', 'prize is waiting'
    ],
    urgency: [
      'within 24 hours', 'within 48 hours', 'act now', 'final notice',
      'last warning', 'immediately or', 'offer expires', 'expires today',
      'account closes today', 'avoid suspension', 'urgent action required', 'limited slots', 'reply yes', 'today only', 'join today'
    ],
    payment: [
      'gift card payment', 'pay with gift cards', 'wire the money', 'send a wire transfer',
      'pay in crypto', 'pay using cryptocurrency', 'processing fee', 'refundable deposit',
      'payment to unlock', 'release the funds', 'buy gift cards', 'buy two gift cards',
      'gift card codes', 'share gift card codes', 'gift cards to claim', 'send money to claim',
      'pay a fee to receive', 'pay to unlock your account'
    ],
    remoteAccess: [
      'install anydesk', 'install teamviewer', 'remote access app', 'share your screen',
      'give me remote access', 'download remote support', 'let me control your computer'
    ],
    clickfix: [
      'press win+r', 'press windows+r', 'paste this command', 'paste the command',
      'open the run dialog', 'paste into the run box', 'run this command',
      'execute this command', 'copy and paste this command', 'verify you are human by running'
    ],
    recoverySecret: [
      'recovery phrase', 'seed phrase', 'wallet recovery words', 'private key',
      'secret recovery phrase', 'wallet passphrase'
    ]
  };

  const AMPLIFIERS = new Set(['urgency']);
  const SECRET_RE = /\b(?:share|send|reply(?:\s+with)?|provide|give|confirm|tell\s+(?:us|me)|submit|enter|read\s+out)\b[^.!?;,:\n]{0,54}\b(?:otp|one[- ]?time password|pin|cvv|passcode|password|card number|recovery phrase|seed phrase|private key)\b/i;
  const SECRET_NEGATION_RE = /\b(?:do not|don't|dont|never|not to|will never ask (?:you )?to|will not ask (?:you )?to|won't ask (?:you )?to|will never request|will not request|won't request)\b/i;
  const URL_RE = /\b(?:javascript|vbscript):[^\s<>"'`]+|\bdata:text\/html[^\s<>"'`]*|\b(?:https?:\/\/|hxxps?:\/\/)[^\s<>"'`]+|\bwww\.[^\s<>"'`]+|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::[0-9]{1,5})?(?:\/[^\s<>"'`]*)?|(?<![@\w.-])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:\/[^\s<>"'`]*)?/gi;
  const HOST_NAME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
  const ACCOUNT_EVENT_RE = /\b(?:account|profile|mailbox|email|bank(?:ing)?|card|subscription|payroll|payment|wallet|tax filing|delivery|parcel|package|shipment|document|cloud storage)\b[^.!?;\n]{0,90}\b(?:unusual|suspicious|unauthori[sz]ed|compromis(?:ed|e)|locked|lockout|suspend(?:ed|sion)?|restrict(?:ed|ion)?|block(?:ed)?|disable(?:d)?|deactivat(?:ed|ion)|expir(?:e|ed|ing)|pending|on hold|full|failed|declined|limited|overdue|problem|issue|alert)\b|\b(?:unusual activity|suspicious activity|security alert|new sign[ -]?in|unknown device|unauthori[sz]ed access|payment failed|deposit pending|mailbox(?: is)? full|storage(?: is)? full|account locked|account suspended|account restricted)\b/i;
  const AUTHORITY_RE = /\b(?:bank|credit union|payroll|human resources|\bhr\b|microsoft|google|apple|amazon|irs|tax authority|customs|postal service|courier|delivery service|support team|help desk|it department|security team|administrator)\b/i;
  const ACTION_INTENT_RE = /\b(?:click|tap|open|visit|follow|go to|sign in|log in|verify|confirm|update|review|complete|resolve|restore|unlock|reactivate|submit|enter|provide|reply|call|contact|pay|settle|release|download|install)\b/i;
  const SENSITIVE_TARGET_RE = /\b(?:identity|personal information|personal details|account details|billing information|billing details|payment details|card details|card information|bank details|banking details|direct deposit|routing number|social security|\bssn\b|tax id|passport|driver'?s license|email address|phone number|password|passcode|verification code|one[- ]time code|otp|pin|cvv|security code|recovery phrase|seed phrase|private key)\b/i;
  const PAYMENT_DEMAND_RE = /\b(?:pay|payment|fee|charge|billing|wire transfer|bank transfer|gift cards?|cryptocurrency|crypto|bitcoin|wallet deposit|refundable deposit|processing cost)\b/i;
  const DELIVERY_CONTEXT_RE = /\b(?:parcel|package|shipment|delivery|courier|customs|postal|tracking number)\b/i;
  const DEADLINE_RE = /\b(?:immediately|right away|today|within\s+\d+\s+(?:minutes?|hours?|days?)|before\s+(?:midnight|\d)|by\s+(?:midnight|\d)|final notice|last chance|expires?\s+(?:today|soon))\b/i;

  function trimUrlPunctuation(value) {
    let candidate = String(value || '');
    candidate = candidate.replace(TRIM_URL_END, '');
    const pairs = [['(', ')'], ['[', ']'], ['{', '}']];
    for (const [open, close] of pairs) {
      while (candidate.endsWith(close)) {
        const opens = (candidate.match(new RegExp('\\' + open, 'g')) || []).length;
        const closes = (candidate.match(new RegExp('\\' + close, 'g')) || []).length;
        if (closes <= opens) break;
        candidate = candidate.slice(0, -1);
      }
    }
    return candidate;
  }

  // Remove invisible formatting and compatibility variants before matching common scam patterns.
  function normaliseMessage(input) {
    return String(input == null ? '' : input)
      .normalize('NFKC')
      .replace(ZERO_WIDTH, '')
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u201C\u201D]/g, '"')
      .replace(/[\u2010-\u2015]/g, '-')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase()
      .replace(/[\u0430\u0441\u0435\u0456\u0458\u043e\u0440\u0455\u0445\u0443\u0501\u04bb\u0251\u03f2\u03b5\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7]/g, (ch) => CONFUSABLES.get(ch) || ch);
  }

  // Parse candidate links for scoring only; message analysis never opens them or changes navigation.
  function extractMessageLinks(input) {
    const raw = String(input == null ? '' : input);
    const scanText = raw
      .replace(ZERO_WIDTH, '')
      .replace(/[\u3002\uFF0E\uFF61]/g, '.')
      .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)/gi, '.')
      .replace(/\bhxxps?\s*(?:\[\s*:\s*\]|\(\s*:\s*\))\s*\/\//gi, (value) => value.toLowerCase().replace(/\s*(?:\[\s*:\s*\]|\(\s*:\s*\))\s*/, ':').replace(/\s+/g, ''));
    const found = [];
    const seen = new Set();
    const matcher = new RegExp(URL_RE.source, URL_RE.flags);
    let match;
    while ((match = matcher.exec(scanText)) && found.length < MAX_LINKS) {
      const original = trimUrlPunctuation(match[0]);
      if (!original) continue;
      let candidate = original;
      if (/^(?:javascript|vbscript):/i.test(candidate) || /^data:text\/html/i.test(candidate)) {
        const key = candidate.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          found.push({ url: candidate, sourceText: original });
        }
        continue;
      }
      if (/^hxxps?:\/\//i.test(candidate)) candidate = candidate.replace(/^hxxps?/i, (v) => v.toLowerCase() === 'hxxps' ? 'https' : 'http');
      if (/^www\./i.test(candidate) || !HOST_NAME_RE.test(candidate)) candidate = 'https://' + candidate;
      try {
        const parsed = new URL(candidate);
        if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname.includes('.')) continue;
        candidate = parsed.href;
      } catch (_) { continue; }
      const key = candidate.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ url: candidate, sourceText: original });
    }
    return found;
  }

  function clausePrefix(text, index) {
    const prefix = text.slice(Math.max(0, index - 120), index);
    const separator = /[.!?;:\n]|,\s*(?:but|however|instead|rather|yet|please|now)\b|\b(?:but|however|instead|rather|yet)\b/gi;
    let boundary = 0;
    let match;
    while ((match = separator.exec(prefix))) boundary = match.index + match[0].length;
    return prefix.slice(boundary);
  }

  function hasUnnegatedRequest(text, pattern) {
    const matcher = new RegExp(pattern.source, 'gi');
    let match;
    while ((match = matcher.exec(text))) {
      if (!SECRET_NEGATION_RE.test(clausePrefix(text, match.index))) return true;
      if (!match[0]) matcher.lastIndex++;
    }
    return false;
  }

  function hasUnprotectedPhrase(text, phrase) {
    let index = text.indexOf(phrase);
    while (index !== -1) {
      const prefix = clausePrefix(text, index);
      const protectiveInstruction = /\b(?:never|do not|don't|dont|should not|shouldn't|avoid)\s+(?:ever\s+)?(?:share|send|provide|reveal|disclose|enter|paste|submit|give|pay|buy|purchase|wire|transfer|click|open|follow|install|download)\b[^.!?;,:]{0,40}$/i;
      if (!protectiveInstruction.test(prefix)) return true;
      index = text.indexOf(phrase, index + phrase.length);
    }
    return false;
  }

  function collectPhraseEvidence(text) {
    const groups = [];
    let repeatedMatches = 0;
    for (const [group, phrases] of Object.entries(PHRASES)) {
      const matches = phrases.filter((phrase) => hasUnprotectedPhrase(text, phrase));
      if (matches.length) {
        groups.push({ group, hit: matches[0], count: matches.length });
        repeatedMatches += Math.max(0, matches.length - 1);
      }
    }
    const classic = SCAM_PHRASES.find((phrase) => hasUnprotectedPhrase(text, String(phrase).toLowerCase()));
    if (classic && !groups.some((row) => row.hit === classic)) {
      groups.push({ group: 'classic', hit: classic, count: 1 });
    }
    return { groups, repeatedMatches };
  }

  function inspectLinks(input) {
    if (!H || typeof H.scoreUrl !== 'function') return [];
    return extractMessageLinks(input).map(({ url, sourceText }) => {
      let result = { score: 0, reasons: [] };
      try { result = H.scoreUrl(url); } catch (_) {}
      return {
        url,
        sourceText,
        score: Math.max(0, Math.min(1, Number(result.score) || 0)),
        reasons: Array.isArray(result.reasons) ? result.reasons : []
      };
    });
  }

  // These values are heuristic risk indicators, not calibrated probabilities. Strong secret requests can independently trigger a high-risk verdict.
  function scoreMessage(input) {
    const inputText = String(input == null ? '' : input);
    const raw = inputText.slice(0, MAX_MESSAGE_CHARS);
    const text = normaliseMessage(raw);
    const reasons = [];
    const links = inspectLinks(raw);
    const { groups, repeatedMatches } = collectPhraseEvidence(text);
    const substantive = groups.filter((entry) => !AMPLIFIERS.has(entry.group));
    const urgencyFound = groups.some((entry) => AMPLIFIERS.has(entry.group));
    const impliedCredentialRequest = /\b(?:enter|submit|type|paste)\s+(?:it|the code|your code|your details)\b.{0,70}\b(?:unblock|restore|unlock|reactivate|verify|avoid suspension|prevent suspension|keep access)\b/i.test(text) && /\b(?:password|otp|one[- ]?time password|pin|passcode|verification code|account|bank)\b/i.test(text);
    const credentialRequest = hasUnnegatedRequest(text, SECRET_RE) || impliedCredentialRequest;
    const recoveryPattern = /\b(?:send|share|type|enter|paste|confirm|validate|import)\b[^.!?;,:\n]{0,45}\b(?:recovery phrase|seed phrase|private key|wallet recovery words)\b/i;
    const recoverySecretRequest = hasUnnegatedRequest(text, recoveryPattern);
    const remoteControlPressure = groups.some((entry) => entry.group === 'remoteAccess');
    const paymentPressure = groups.some((entry) => entry.group === 'payment');
    const maxLink = links.reduce((best, item) => item.score > best.score ? item : best, { score: 0, reasons: [] });
    const hasLink = links.length > 0;
    const accountEvent = ACCOUNT_EVENT_RE.test(text);
    const authorityContext = AUTHORITY_RE.test(text);
    const actionIntent = ACTION_INTENT_RE.test(text);
    const sensitiveTarget = SENSITIVE_TARGET_RE.test(text);
    const paymentDemand = PAYMENT_DEMAND_RE.test(text);
    const deliveryContext = DELIVERY_CONTEXT_RE.test(text);
    const deadlinePressure = DEADLINE_RE.test(text) || urgencyFound;
    let contextualScore = 0;
    let contextualLabel = '';

    if (accountEvent && actionIntent) {
      contextualScore = 0.54;
      contextualLabel = 'account or security event paired with a requested action';
      if (authorityContext) contextualScore += 0.07;
      if (deadlinePressure) contextualScore += 0.10;
      if (sensitiveTarget) contextualScore += hasLink ? 0.22 : 0.14;
      if (hasLink) contextualScore += 0.13;
    }
    if (authorityContext && actionIntent && sensitiveTarget) {
      contextualScore = Math.max(contextualScore, hasLink ? 0.84 : 0.68);
      contextualLabel = 'organisation-themed request for sensitive information';
      if (deadlinePressure) contextualScore += 0.06;
    }
    if (deliveryContext && paymentDemand && (actionIntent || hasLink)) {
      contextualScore = Math.max(contextualScore, hasLink ? 0.84 : 0.64);
      contextualLabel = 'delivery notice requesting an additional payment';
    }
    if (paymentDemand && actionIntent && (authorityContext || accountEvent) && hasLink) {
      contextualScore = Math.max(contextualScore, 0.82);
      contextualLabel = 'payment request linked to an account or service warning';
    }
    const protectiveWarning = /\b(?:never|do not|don't|dont|should not|shouldn't|avoid)\b[^.!?;\n]{0,110}\b(?:share|send|provide|reveal|disclose|enter|submit|paste|give)\b[^.!?;\n]{0,70}\b(?:password|passcode|otp|one[- ]?time code|pin|cvv|recovery phrase|seed phrase|private key)\b/i.test(text)
      || /\b(?:we|our team|the bank|your bank|support)\s+(?:will )?never ask\b[^.!?;\n]{0,90}\b(?:password|passcode|otp|pin|cvv|recovery phrase|seed phrase|private key)\b/i.test(text);
    if (protectiveWarning && !credentialRequest && !recoverySecretRequest && maxLink.score < THRESHOLDS.suspicious) {
      contextualScore = 0;
      contextualLabel = '';
    }
    // Context alone without a destination or an explicit secret request is a warning, not proof of compromise.
    if (!hasLink && !credentialRequest && !recoverySecretRequest) contextualScore = Math.min(contextualScore, 0.74);
    contextualScore = Math.min(0.96, contextualScore);

    let phraseScore = 0;
    if (substantive.length) {
      phraseScore = 0.25 + Math.min(0.32, substantive.length * 0.12);
      if (substantive.length >= 2) phraseScore = Math.max(phraseScore, 0.52);
      phraseScore += Math.min(0.12, repeatedMatches * 0.035);
      if (repeatedMatches >= 1) phraseScore = Math.max(phraseScore, 0.52);
      if (urgencyFound) phraseScore += 0.10;
      if (paymentPressure) phraseScore += 0.08;
      if (remoteControlPressure) phraseScore += 0.12;
      if (groups.some((entry) => entry.group === 'clickfix')) phraseScore = Math.max(phraseScore, 0.72);
      if (paymentPressure && groups.some((entry) => entry.group === 'reward' || entry.group === 'investment')) phraseScore = Math.max(phraseScore, 0.62);
      phraseScore = Math.min(0.78, phraseScore);
      const lead = substantive[0];
      reasons.push({ code: 'msgScamWording', kind: 'message', params: [lead.hit] });
      if (urgencyFound) reasons.push({ code: 'msgUrgencyDeadline', kind: 'message' });
    }

    let score = Math.max(phraseScore, contextualScore, maxLink.score);
    if (contextualScore >= THRESHOLDS.suspicious && contextualLabel) {
      reasons.push({ code: 'msgScamWording', kind: 'message', params: [contextualLabel] });
    }
    if (credentialRequest) {
      score = Math.max(score, 0.86);
      reasons.push({ code: 'msgOtpAsk', kind: 'message' });
    }
    if (recoverySecretRequest) score = Math.max(score, 0.94);
    if (remoteControlPressure) {
      score = Math.max(score, 0.62);
      if (!reasons.some((reason) => reason.code === 'msgScamWording')) {
        reasons.push({ code: 'msgScamWording', kind: 'message', params: [groups.find((entry) => entry.group === 'remoteAccess').hit] });
      }
    }
    if (maxLink.score >= THRESHOLDS.suspicious) {
      const linkReason = { code: 'msgDangerousLink', kind: 'message', params: [maxLink.url] };
      if (!reasons.some((reason) => reason.code === linkReason.code && reason.params?.[0] === maxLink.url)) reasons.push(linkReason);
      if (substantive.length && maxLink.score < THRESHOLDS.dangerous) score = Math.min(1, score + 0.10);
    }
    if (paymentPressure && substantive.length === 0) score = Math.max(score, 0.48);
    score = Math.max(0, Math.min(1, score));

    let level = 'safe';
    if (score >= THRESHOLDS.dangerous) level = 'dangerous';
    else if (score >= THRESHOLDS.suspicious) level = 'suspicious';

    const seen = new Set();
    const uniqueReasons = reasons.filter((reason) => {
      const signature = `${reason.code}|${JSON.stringify(reason.params || [])}`;
      if (seen.has(signature)) return false;
      seen.add(signature);
      return true;
    });

    const evidence = [];
    const addEvidence = (code, title, detail, severity) => evidence.push({ code, title, detail, severity: severity || 'warning' });
    if (recoverySecretRequest) addEvidence('recovery-secret', 'Wallet recovery secret requested', 'The message asks for a recovery phrase, seed phrase, or private key. Anyone who receives it can potentially take control of the wallet.', 'critical');
    if (credentialRequest) addEvidence('credential-request', 'Authentication secret requested', 'The sender asks the recipient to disclose a password, one-time code, PIN, or similar authentication secret. Treat this as a high-risk request.', 'critical');
    if (accountEvent && actionIntent) addEvidence('account-action', 'Problem-and-action pattern', 'The message claims that an account, payment, mailbox, or delivery has a problem and then directs the recipient to take an action. This combination is commonly used to manufacture urgency.', 'warning');
    if (authorityContext && sensitiveTarget) addEvidence('authority-sensitive', 'Authority claim paired with sensitive data', 'The message invokes an organisation or support role while seeking personal, financial, or account information. Verify through a contact method you already trust.', 'warning');
    if (deliveryContext && paymentDemand) addEvidence('delivery-payment', 'Delivery fee or release payment', 'A shipment or customs notice is paired with a request for money. Check the tracking number on the carrier’s official website instead of using the supplied link.', 'warning');
    if (paymentPressure) addEvidence('payment-pressure', 'Payment or transfer pressure', 'The message encourages a payment, gift-card purchase, bank transfer, or cryptocurrency transfer. These methods can be difficult or impossible to reverse.', 'warning');
    if (remoteControlPressure) addEvidence('remote-control', 'Remote access requested', 'The instructions encourage installing remote-control software or giving another person access to the device.', 'critical');
    if (groups.some((entry) => entry.group === 'clickfix')) addEvidence('command-execution', 'Command execution disguised as verification', 'The message tells the recipient to open a system command interface and paste or execute text. A legitimate CAPTCHA or account verification should not require this.', 'critical');
    if (deadlinePressure) addEvidence('deadline-pressure', 'Artificial urgency', 'A deadline or immediate consequence is used to pressure the recipient to act before independently verifying the request.', 'warning');
    if (substantive.length) addEvidence('scam-language', 'Scam-pattern language', `The text matches ${substantive.length} distinct risk pattern group(s): ${substantive.map((entry) => entry.group).join(', ')}. This is supporting evidence, not a verdict by itself.`, 'warning');
    for (const link of links) {
      if (link.reputationHit === 'block') addEvidence('feed-block:' + link.url, 'Known malicious destination', `${link.url} matches a PhishGuard block-list entry. Do not open it.`, 'critical');
      else if (link.reputationHit === 'warn') addEvidence('feed-warn:' + link.url, 'Destination has a threat warning', `${link.url} appears on a lower-confidence threat list. Verify independently before opening it.`, 'warning');
      else if (link.score >= THRESHOLDS.suspicious) {
        const descriptions = (link.reasons || []).map((reason) => reason.code).filter(Boolean);
        addEvidence('link-risk:' + link.url, 'Suspicious link structure', `${link.url} triggered address checks${descriptions.length ? ': ' + descriptions.join(', ') : ''}.`, 'warning');
      } else if (link.reputationHit === 'no-match') addEvidence('link-no-match:' + link.url, 'No threat-list match found', `${link.url} had no matching entry in the available feed. A feed miss does not establish that a destination is safe.`, 'info');
    }

    return {
      level,
      score: Number(score.toFixed(4)),
      reasons: uniqueReasons,
      links,
      evidence,
      signals: {
        credentialRequest,
        recoverySecretRequest,
        remoteControlPressure,
        paymentPressure,
        urgency: urgencyFound || deadlinePressure,
        accountEvent,
        authorityContext,
        actionIntent,
        sensitiveTarget,
        paymentDemand,
        deliveryContext,
        contextualScore: Number(contextualScore.toFixed(4)),
        phraseGroups: substantive.map((entry) => entry.group),
        repeatedPhraseCount: repeatedMatches,
        linkCount: links.length,
        strongestLinkScore: Number(maxLink.score.toFixed(4))
      }
    };
  }

  return { normaliseMessage, extractMessageLinks, scoreMessage };
});
