(function (root, factory) {
  const mod = factory(typeof module !== 'undefined' && module.exports ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C) {
  'use strict';

  const THRESHOLDS = (C && C.THRESHOLDS) || { suspicious: 0.5, dangerous: 0.8 };

  function getHost(value) {
    try { return new URL(String(value || '')).hostname.toLowerCase(); }
    catch (_) { return ''; }
  }

  function withTimeout(promise, timeoutMs) {
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve(null), Math.max(100, Number(timeoutMs) || 1400));
    });
    return Promise.race([Promise.resolve(promise).catch(() => null), timeout]).finally(() => clearTimeout(timer));
  }

  function uniqueReasons(items) {
    const seen = new Set();
    return (items || []).filter((item) => {
      const key = item && typeof item === 'object' ? item.code + '|' + JSON.stringify(item.params || []) : String(item);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  async function enrichMessageReputation(result, lookup, timeoutMs) {
    const base = result || { level: 'safe', score: 0, reasons: [], links: [] };
    const links = Array.isArray(base.links) ? base.links : [];
    if (!links.length || typeof lookup !== 'function') return Object.assign({}, base, {
      reputation: { hostsChecked: 0, blockHits: 0, warnHits: 0, unavailableHosts: 0 }
    });

    const hosts = [...new Set(links.map((link) => getHost(link && link.url)).filter(Boolean))];
    const matches = new Map();
    await Promise.all(hosts.map(async (host) => {
      const response = await withTimeout(Promise.resolve().then(() => lookup(host)), timeoutMs);
      matches.set(host, response && (response.hit === 'block' || response.hit === 'warn') ? response : response && response.hit === null ? response : null);
    }));

    let score = Math.max(0, Math.min(1, Number(base.score) || 0));
    let blockHits = 0;
    let warnHits = 0;
    let unavailableHosts = 0;
    const reasons = [...(base.reasons || [])];
    const enrichedLinks = links.map((link) => {
      const host = getHost(link && link.url);
      const match = matches.get(host);
      if (!match) {
        if (host && matches.has(host)) unavailableHosts++;
        return Object.assign({}, link);
      }
      if (match.hit === 'block') {
        blockHits++;
        score = Math.max(score, 0.97);
        const reason = { code: 'feedBlock', kind: 'link', params: [String((match.sources || []).length)] };
        reasons.unshift(reason);
        return Object.assign({}, link, { score: Math.max(Number(link.score) || 0, 0.97), reputationHit: 'block', reasons: uniqueReasons([reason].concat(link.reasons || [])) });
      }
      if (match.hit === 'warn') {
        warnHits++;
        score = Math.max(score, 0.60);
        const reason = { code: 'feedWarn', kind: 'link', params: [String(Math.max(1, (match.sources || []).length))] };
        reasons.unshift(reason);
        return Object.assign({}, link, { score: Math.max(Number(link.score) || 0, 0.60), reputationHit: 'warn', reasons: uniqueReasons([reason].concat(link.reasons || [])) });
      }
      return Object.assign({}, link, { reputationHit: 'no-match' });
    });

    score = Math.max(0, Math.min(1, score));
    let level = 'safe';
    if (score >= THRESHOLDS.dangerous) level = 'dangerous';
    else if (score >= THRESHOLDS.suspicious) level = 'suspicious';

    const evidence = [...(base.evidence || [])];
    for (const link of enrichedLinks) {
      if (link.reputationHit === 'block') evidence.unshift({ code: 'feed-block:' + link.url, title: 'Known malicious destination', detail: `${link.url} is present on PhishGuard’s block list. Do not open it.`, severity: 'critical' });
      else if (link.reputationHit === 'warn') evidence.unshift({ code: 'feed-warn:' + link.url, title: 'Destination has a threat warning', detail: `${link.url} appears on a lower-confidence threat list. Verify it independently.`, severity: 'warning' });
      else if (link.reputationHit === 'no-match') evidence.push({ code: 'feed-clear:' + link.url, title: 'No threat-list match found', detail: `${link.url} did not match the available feed. A feed miss is not proof of safety.`, severity: 'info' });
    }
    return Object.assign({}, base, {
      level,
      score: Number(score.toFixed(4)),
      reasons: uniqueReasons(reasons),
      links: enrichedLinks,
      evidence: evidence.filter((item, index, all) => all.findIndex((other) => other.code === item.code) === index),
      reputation: { hostsChecked: hosts.length - unavailableHosts, blockHits, warnHits, unavailableHosts }
    });
  }

  return { enrichMessageReputation };
});
