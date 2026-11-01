(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  // Only decision-relevant data belongs in the model context. Keep original
  // evidence IDs; never renumber a subset and then ground it against another list.
  function compactAiSnapshot(snapshot) {
    const s = snapshot || {};
    const take = (items, n, keys) => (Array.isArray(items) ? items : []).slice(0, n).map((item) => {
      const out = {};
      for (const key of keys) if (item[key] !== undefined) out[key] = typeof item[key] === 'string' ? item[key].slice(0, 180) : item[key];
      return out;
    });
    const out = {
      url: s.url, host: s.host, title: String(s.title || '').slice(0, 180),
      visibleText: String(s.visibleText || '').slice(0, 1600),
      selectedText: String(s.selectedText || '').slice(0, 1400),
      selectedLink: s.selectedLink, selectionRequested: !!s.selectionRequested,
      pageContext: s.pageContext, pageBehavior: s.pageBehavior,
      forms: take(s.forms, 12, ['id','actionHost','crossSite','hasPassword','hasPaymentField','hasSensitiveField','method']),
      links: take((s.links || []).slice().sort((a,b) => Number(!!b.verifiedThreatFeed || !!b.selectedByUser) - Number(!!a.verifiedThreatFeed || !!a.selectedByUser)), 12,
        ['id','host','label','url','verifiedThreatFeed','remoteRisk','selectedByUser']),
      downloads: take(s.downloads, 6, ['id','href','executable','downloadAction']),
      elements: take((s.elements || []).filter(x => (x.evidenceFlags || []).length), 12,
        ['id','kind','tag','inline','executable','evidenceFlags','behaviorSignals','codePreview','hrefHost','srcHost']),
      frameSummaries: take(s.frameSummaries, 8, ['frameId','host','formCount','sensitiveFormCount','crossSiteFormCount','truncated']),
      remoteLinkScans: (s.remoteLinkScans || []).slice(0, 4).map(x => ({ id:x.id, linkId:x.linkId, error:x.error,
        result:x.result ? { confirmedMalware:x.result.confirmedMalware, criticalFindings:x.result.criticalFindings,
          evidence:take(x.result.evidence,4,['severity','explanation']), title:x.result.title, finalUrl:x.result.finalUrl,
          contentPreview:String(x.result.contentPreview || '').slice(0,400) } : null })),
      counts:s.counts, coverage:s.coverage,
      limitations:['This is a bounded security snapshot, not a complete execution trace.']
    };
    // Hard context budget, with valid JSON throughout. Structural evidence has
    // priority over prose and destination samples. The full snapshot stays local.
    const max = 11000;
    for (const key of ['visibleText','selectedText']) {
      if (JSON.stringify(out).length > max) out[key] = out[key].slice(0, 500);
    }
    for (const key of ['remoteLinkScans','links','elements','frameSummaries','downloads']) {
      while (out[key].length && JSON.stringify(out).length > max) out[key].pop();
    }
    return out;
  }

  function assessmentFingerprint(s) {
    // UI counters, model availability and inference timing must not invalidate
    // an otherwise identical page. Include selections and raw route identity.
    return JSON.stringify({ url:s.url, route:s.routeKey, title:s.title, visibleText:s.visibleText,
      selectedText:s.selectedText, selectedLink:s.selectedLink, selectionRequested:s.selectionRequested,
      forms:s.forms, links:(s.links || []).map(({localModelProbability, ...link}) => link),
      downloads:s.downloads, elements:s.elements, pageContext:s.pageContext,
      pageBehavior:s.pageBehavior, remoteLinkChecks:s.remoteLinkChecks, frameSummaries:s.frameSummaries });
  }

  function createAssessmentQueue(maxPending = 8) {
    let active = null;
    const pending = [];
    const entries = new Map();
    const settle = (entry, error, result) => {
      if (entries.get(entry.key) === entry) entries.delete(entry.key);
      error ? entry.reject(error) : entry.resolve(result);
    };
    async function pump() {
      if (active || !pending.length) return;
      const entry = pending.shift(); active = entry;
      try { settle(entry, null, await entry.work(entry.controller.signal)); }
      catch (error) { settle(entry, error); }
      finally { active = null; pump(); }
    }
    function cancel(key) {
      const entry = entries.get(key);
      if (!entry) return;
      entry.controller.abort();
      const i = pending.indexOf(entry);
      if (i >= 0) { pending.splice(i,1); settle(entry, new Error('Assessment superseded')); }
      entries.delete(key);
    }
    return {
      schedule(key, fingerprint, work) {
        const existing = entries.get(key);
        if (existing && existing.fingerprint === fingerprint) return existing.promise;
        cancel(key);
        while (pending.length >= maxPending) cancel(pending[0].key);
        const entry = { key, fingerprint, work, controller:new AbortController() };
        entry.promise = new Promise((resolve,reject) => { entry.resolve=resolve; entry.reject=reject; });
        entries.set(key,entry); pending.push(entry); pump(); return entry.promise;
      },
      cancel,
      cancelPrefix(prefix) { for (const key of entries.keys()) if (key.startsWith(prefix)) cancel(key); },
      get size() { return pending.length + Number(!!active); }
    };
  }

  function describePageAssessment(verdict) {
    const v = verdict || {};
    if (v.level === 'dangerous') return 'High-risk evidence was detected. Review the warning before continuing.';
    if (v.level === 'suspicious') return 'The checks found evidence that needs your attention.';
    if (v.level === 'safe') return 'No significant threat was found in the inspected evidence. This is not a guarantee of safety.';
    if (v.analysisPending) return 'Local checks are complete. Deeper analysis is running in the background; you can keep browsing.';
    if (v.level === 'informational') return v.summary || 'Local checks found no corroborated threat. Some analysis capabilities are limited.';
    return v.summary || 'The available checks could not establish a complete assessment.';
  }
  function combineFrameVerdicts(top, frames) {
    const rank = { unknown:0, informational:1, safe:1, suspicious:2, dangerous:3 };
    let effective = top || null;
    for (const verdict of frames) {
      if (verdict && (!effective || (rank[verdict.level] || 0) > (rank[effective.level] || 0))) effective = verdict;
    }
    return effective;
  }
  function phishingTextWindows(snapshot, maxChars = 1200) {
    const s = snapshot || {};
    const text = String(s.visibleText || '').replace(/\s+/g,' ').trim();
    const title = String(s.title || '').slice(0,160);
    const width = Math.max(300,Math.min(1800,maxChars));
    const offsets = [0, Math.max(0,Math.floor(text.length/2)-Math.floor(width/2)), Math.max(0,text.length-width)];
    return Array.from(new Set(offsets.map(start => (title+' '+text.slice(start,start+width)).trim()).filter(Boolean))).slice(0,3);
  }
  function withAssessmentDeadline(promise, milliseconds, onTimeout) {
    let timer;
    return Promise.race([promise,new Promise((_,reject) => {
      timer=setTimeout(()=>{ if(onTimeout) onTimeout(); reject(new Error('Analysis timed out; local protection remains active.')); },milliseconds);
    })]).finally(()=>clearTimeout(timer));
  }
  return { compactAiSnapshot, assessmentFingerprint, createAssessmentQueue, describePageAssessment, combineFrameVerdicts, phishingTextWindows, withAssessmentDeadline };
});
