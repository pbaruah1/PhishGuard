(function (root) {
  'use strict';
  if (root.__phishguardIsolatedGuard) return;                                             
  root.__phishguardIsolatedGuard = true;
  const api = root.browser || root.chrome;
  const SS = root.PhishGuard;
                                                                               
                                                                            
                                                                             
                                                                               
                                                                              
                                   
  function t(key, subs, fallback) {
    try { const R = root.SSReasons; if (R && R.tOverride) { const o = R.tOverride(key, subs); if (o) return o; } } catch (_) {}
    try { const m = api && api.i18n && api.i18n.getMessage(key, subs); if (m) return m; } catch (_) {}
    return fallback != null ? fallback : key;
  }
  const bidi = (s) => (root.SSReasons && root.SSReasons.bidiWrap) ? root.SSReasons.bidiWrap(s) : (s == null ? '' : String(s));
                                                                      
                                                                             
  function setDir(node) {
    try { node.setAttribute('dir', root.SSReasons && root.SSReasons.isRTL() ? 'rtl' : 'ltr'); } catch (_) {}
  }
                                                                       
                                                                           
                                                                             
  const IS_TOP = (() => { try { return window === window.top; } catch (_) { return false; } })();

  function send(type, extra) {
    return new Promise((res) => {
      try { api.runtime.sendMessage(Object.assign({ type }, extra), (r) => res(r)); }
      catch (_) { res(null); }
    });
  }

  // Local-only page monitoring. It records security-relevant metadata, never
  // keystrokes, typed values, passwords, payment values, or page text snapshots.
  const liveActivity = { counts: Object.create(null), recent: [], mutationCount: 0, lastMutationAt: 0 };
  let liveMonitorStarted = false;
  let liveMutationTimer = null;
  let liveRescanTimer = null;
  let lastLiveScanAt = 0;
  let activeScanPromise = null;
  let pendingAutomaticScan = false;
  let pendingAutomaticOptions = null;
  let pendingManualOptions = null;
  let pendingManualWaiters = [];
  let lastAiSnapshotFingerprint = '';
  let lastAiSnapshotAt = 0;
  let lastAiAssessment = null;
  let lastAiSnapshot = null;
  let pendingAiRequest = null;
  let completedAiResponse = null;
  let aiRequestSequence = 0;
  let activeSelection = { selectedText:'', selectedUrl:'' };
  let inventoryReportTimer = null;
  const observedRoots = new WeakSet();
  const handledActivityEvents = new WeakSet();
  const DEVICE_HINTS = (SS && SS.readDeviceHints) ? SS.readDeviceHints({
    hardwareConcurrency: root.navigator && root.navigator.hardwareConcurrency,
    deviceMemory: root.navigator && root.navigator.deviceMemory,
    connection: root.navigator && root.navigator.connection,
    reducedMotion: (() => { try { return matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (_) { return false; } })()
  }) : {};
  const DEVICE_PROFILE = (SS && SS.deriveDeviceProfile) ? SS.deriveDeviceProfile(DEVICE_HINTS) : {
    tier: 'balanced', label: 'Balanced mode', maxDomElements: 5200, maxInteractive: 400,
    maxElementDetails: 650, maxScripts: 36, maxInlineScriptChars: 2200,
    maxScriptPreviewChars: 280, maxAiElements: 120, maxAiLinks: 24,
    maxAiForms: 16, maxAiScripts: 8, maxVisibleTextChars: 4800,
    maxSerpAnchorScan: 320, serpObserverDebounceMs: 1600,
    mutationDebounceMs: 2800, inventoryDebounceMs: 3800,
    minFullRescanIntervalMs: 28000, minAiIntervalMs: 28000,
    usePageModelFallback: true, maxLinkModelChecks: 12
  };
  // One cached TreeWalker index is shared by all selectors in a scan. The
  // cache is invalidated only by meaningful DOM mutations, avoiding repeated
  // querySelectorAll('*') walks for forms, links, scripts, and shadow roots.
  const MAX_INSPECTED_ELEMENTS = DEVICE_PROFILE.maxDomElements || 7500;
  let domIndexCache = null;
  let domIndexDirty = true;
  let domIndexTruncated = false;
  let cachedAiStatus = null;
  let cachedAiStatusAt = 0;
  let localMlCache = null;
  let localMlCacheMutationCount = -1;
  let localMlCacheUrl = '';
  let lastPresentedVerdictKey = '';
  let lastRenderedRiskLevel = '';

  function isPhishGuardNode(node) {
    try {
      const el = node && (node.nodeType === 1 ? node : node.parentElement);
      return !!(el && (el.closest('[class*="phishguard-"]') || el.closest('[id^="phishguard-"]') || el.closest('.ss-toast,.ss-banner,.ss-overlay')));
    } catch (_) { return false; }
  }

  function getDomIndex() {
    if (!domIndexDirty && Array.isArray(domIndexCache)) return domIndexCache;
    const output = [];
    const roots = [document];
    const visitedRoots = new Set();
    domIndexTruncated = false;
    let visitedElements = 0;
    while (roots.length && output.length < MAX_INSPECTED_ELEMENTS) {
      const current = roots.shift();
      if (!current || visitedRoots.has(current)) continue;
      visitedRoots.add(current);
      let walker;
      try {
        const doc = current.ownerDocument || document;
        walker = doc.createTreeWalker(current, (root.NodeFilter && root.NodeFilter.SHOW_ELEMENT) || 1);
      } catch (_) { continue; }
      let node;
      while ((node = walker.nextNode())) {
        if (++visitedElements > MAX_INSPECTED_ELEMENTS) { domIndexTruncated = true; roots.length = 0; break; }
        if (isPhishGuardNode(node)) continue;
        output.push(node);
        if (node.shadowRoot && roots.length < 128) roots.push(node.shadowRoot);
        if (output.length >= MAX_INSPECTED_ELEMENTS) { domIndexTruncated = true; break; }
      }
    }
    domIndexCache = output;
    domIndexDirty = false;
    return output;
  }

  function deepQueryAll(selector) {
    const indexed = getDomIndex();
    if (selector === '*') return indexed.slice();
    const result = [];
    for (const element of indexed) {
      try { if (element.matches(selector)) result.push(element); } catch (_) {}
    }
    return result;
  }

  function hostOf(value, base) {
    try { return new URL(value || base || location.href, base || location.href).hostname; } catch (_) { return ''; }
  }

  function pageTextSnapshot(limit) {
    const max = Math.max(1000, Math.min(100000, Number(limit) || DEVICE_PROFILE.maxVisibleTextChars || 5600));
    const parts = [];
    let length = 0;
    const roots = [document.body || document.documentElement];
    for (const element of getDomIndex()) if (element.shadowRoot) roots.push(element.shadowRoot);
    const skipTags = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'CANVAS']);
    for (const domRoot of roots) {
      if (!domRoot || length >= max) break;
      let walker;
      try { walker = document.createTreeWalker(domRoot, (root.NodeFilter && root.NodeFilter.SHOW_TEXT) || 4); } catch (_) { continue; }
      let node;
      let visitedTextNodes = 0;
      while ((node = walker.nextNode()) && length < max && visitedTextNodes++ < MAX_INSPECTED_ELEMENTS) {
        const parent = node.parentElement;
        if (!parent || skipTags.has(parent.tagName) || isPhishGuardNode(parent)) continue;
        const text = String(node.nodeValue || '').replace(/\s+/g, ' ').trim();
        if (!text) continue;
        const piece = text.slice(0, max - length);
        parts.push(piece); length += piece.length + 1;
      }
    }
    return parts.join(' ').slice(0, max);
  }

  async function getAiStatusCached(force) {
    if (!force && cachedAiStatus && Date.now() - cachedAiStatusAt < 30000) return cachedAiStatus;
    const status = await send('getAiStatus', { deviceHints: DEVICE_HINTS });
    if (status && typeof status === 'object') {
      cachedAiStatus = status; cachedAiStatusAt = Date.now();
    }
    return cachedAiStatus || status || { engine: { id: 'local-ml' }, deviceProfile: DEVICE_PROFILE };
  }

  async function attachLocalMlScores(snapshot, inventory, visibleText, forceStatusRefresh) {
    const status = await getAiStatusCached(forceStatusRefresh === true);
    if (status && status.engine && status.engine.id === 'gemini-nano') return;
    if (localMlCache && localMlCacheUrl === location.href && localMlCacheMutationCount === liveActivity.mutationCount) {
      snapshot.localMl = JSON.parse(JSON.stringify(localMlCache));
      snapshot.aiEngine = status && status.engine || { id: 'local-ml' };
      snapshot.deviceProfile = DEVICE_PROFILE;
      return;
    }
    const localMl = { pageProbability: null, urlProbability: null, linkScores: [], modelNames: [] };
    try {
      if (SS.extractUrlFeatures && SS.predictUrlProb) {
        const urlFeatures = SS.extractUrlFeatures(location.href);
        const probability = await SS.predictUrlProb(urlFeatures);
        if (Number.isFinite(probability)) localMl.urlProbability = probability;
        localMl.modelNames.push('packaged-url-model');
      }
    } catch (_) {}
    if (IS_TOP && DEVICE_PROFILE.usePageModelFallback && SS.extractPageFeaturesFromInventory &&
        SS.scorePageContent && SS.isPageModelAvailable && SS.isPageModelAvailable()) {
      try {
        const features = SS.extractPageFeaturesFromInventory(inventory || {}, visibleText || '', {
          host: location.hostname, title: document.title || '',
          hasLang: !!(document.documentElement && document.documentElement.lang), hasIconLink: false
        });
        const scored = SS.scorePageContent(features);
        if (Number.isFinite(scored && scored.prob)) localMl.pageProbability = scored.prob;
        localMl.pageSignals = Array.isArray(scored && scored.top) ? scored.top.slice(0, 3) : [];
        localMl.modelNames.push('packaged-page-model-bounded-inventory');
      } catch (_) {}
    }
    if (SS.extractUrlFeatures && SS.predictUrlProb) {
      const maxLinks = Math.min(snapshot.links.length, DEVICE_PROFILE.maxLinkModelChecks || 14);
      for (let i = 0; i < maxLinks; i++) {
        const link = snapshot.links[i];
        try {
          const probability = await SS.predictUrlProb(SS.extractUrlFeatures(link.remoteUrl || link.url));
          if (Number.isFinite(probability)) {
            link.localModelProbability = probability;
            localMl.linkScores.push({ id: link.id, probability });
          }
        } catch (_) {}
      }
    }
    snapshot.localMl = localMl;
    snapshot.aiEngine = status && status.engine || { id: 'local-ml' };
    snapshot.deviceProfile = DEVICE_PROFILE;
    localMlCache = JSON.parse(JSON.stringify(localMl));
    localMlCacheMutationCount = liveActivity.mutationCount;
    localMlCacheUrl = location.href;
  }

  function scheduleInventoryReport() {
    clearTimeout(inventoryReportTimer);
    inventoryReportTimer = setTimeout(() => {
      try { send('reportPageInventory', { inventory: capturePageInventory() }); } catch (_) {}
    }, DEVICE_PROFILE.inventoryDebounceMs || 3000);
  }

  function recordActivity(kind, target) {
    const now = Date.now();
    const node = target && target.nodeType === 1 ? target : target && target.parentElement;
    if (!node || isPhishGuardNode(node)) return;
    const control = node.closest('a[href],button,input,textarea,select,[role="button"],[role="link"],[contenteditable="true"]') || node;
    const link = control.closest && control.closest('a[href]');
    const form = control.closest && control.closest('form');
    const formAction = form ? (form.getAttribute('action') || location.href) : '';
    const entry = {
      type: kind, at: now, tag: String(control.tagName || '').toLowerCase(),
      role: control.getAttribute && (control.getAttribute('role') || ''),
      inputType: control.getAttribute && (control.getAttribute('type') || ''),
      destinationHost: link ? hostOf(link.getAttribute('href'), location.href) : '',
      formActionHost: form ? hostOf(formAction, location.href) : '',
      formMethod: form ? String(form.getAttribute('method') || 'get').toUpperCase() : ''
    };
    liveActivity.counts[kind] = (liveActivity.counts[kind] || 0) + 1;
    if (kind === 'field-input' || kind === 'field-focus' || kind === 'field-change' || kind === 'form-submit') {
      // A form can be inserted after the initial scan. Reconcile it at the
      // capturing submit event before the event reaches the form target.
      try { guardForeignCredentialFormsNow(); } catch (_) {}
    }
    liveActivity.recent.push(entry);
    if (liveActivity.recent.length > 40) liveActivity.recent.splice(0, liveActivity.recent.length - 40);
    try { window.__phishGuardLiveActivity = liveActivity; } catch (_) {}
    // Only actions capable of changing a security decision accelerate a scan.
    // Ordinary focus, typing, scrolling, and pointer movement stay metadata-only.
    if (kind === 'form-submit' || kind === 'paste' || kind === 'drop' ||
        (kind === 'click' && (link || control.hasAttribute('download')))) scheduleLiveRescan(true);
  }

  function capturePageInventory() {
    // One indexed traversal builds all high-value element buckets. The prior
    // implementation made a separate full pass for each selector, multiplying
    // the CPU cost on long pages and web applications with large DOM trees.
    const elements = getDomIndex();
    const allForms = [], allFields = [], allLinks = [], allScriptNodes = [], allFrames = [];
    for (const element of elements) {
      const tag = String(element.tagName || '').toLowerCase();
      if (tag === 'form') allForms.push(element);
      else if (tag === 'input' || tag === 'textarea' || tag === 'select') allFields.push(element);
      else if (tag === 'a' && element.hasAttribute('href')) allLinks.push(element);
      else if (tag === 'script') allScriptNodes.push(element);
      else if (tag === 'iframe' || tag === 'frame') allFrames.push(element);
    }
    const fieldsByForm = new Map();
    const passwordForms = new WeakSet();
    for (const field of allFields) {
      const form = field.form || field.closest('form');
      if (!form) continue;
      const list = fieldsByForm.get(form) || [];
      if (list.length < 100) list.push(field);
      fieldsByForm.set(form, list);
      if (field.type === 'password') passwordForms.add(form);
    }
    const counts = Object.create(null);
    const interactive = [];
    const elementDetails = [];
    const securityAttributes = [];
    let interactiveCount = 0;
    for (const el of elements) {
      const tag = String(el.tagName || '').toLowerCase();
      counts[tag] = (counts[tag] || 0) + 1;
      const role = el.getAttribute('role') || '';
      const isInteractive = /^(a|button|input|textarea|select|option)$/i.test(tag) ||
        /^(button|link|menuitem|checkbox|radio|switch|tab)$/i.test(role) || el.hasAttribute('contenteditable');
      const href = el.getAttribute('href') || '';
      const src = el.getAttribute('src') || '';
      const action = el.getAttribute('action') || '';
      if (isInteractive) interactiveCount++;
      const hidden = isInteractive && (el.hidden || el.getAttribute('aria-hidden') === 'true');
      const needsLabel = isInteractive || !!href || !!action || tag === 'iframe' || tag === 'script';
      const visibleLabel = needsLabel ? (() => {
        try {
          const labels = el.labels ? Array.from(el.labels).slice(0, 2).map((label) => label.textContent || '') : [];
          const fallback = (tag === 'a' || tag === 'button') ? String(el.textContent || '').slice(0, 360) : '';
          return String(labels.join(' ') || el.getAttribute('aria-label') || el.getAttribute('title') ||
            el.getAttribute('placeholder') || fallback).replace(/\s+/g, ' ').trim().slice(0, 140);
        } catch (_) { return String(el.getAttribute('aria-label') || el.getAttribute('title') || '').slice(0, 140); }
      })() : '';
      if (isInteractive && interactive.length < DEVICE_PROFILE.maxInteractive) {
        interactive.push({ tag, id: String(el.id || '').slice(0, 100), role, type: el.getAttribute('type') || '',
          label: visibleLabel, hrefHost: href ? hostOf(href, location.href) : '',
          hrefProtocol: href ? (() => { try { return new URL(href, location.href).protocol; } catch (_) { return 'invalid:'; } })() : '',
          formActionHost: action ? hostOf(action, location.href) : '',
          targetBlank: el.getAttribute('target') === '_blank',
          rel: el.getAttribute('rel') || '', download: el.hasAttribute('download'),
          hidden: !!hidden, disabled: !!el.disabled, required: !!el.required,
          autocomplete: el.getAttribute('autocomplete') || '',
          hasInlineHandler: Array.from(el.attributes || []).some((attribute) => /^on/i.test(attribute.name)),
          hasPasswordAncestor: (() => { const form = el.closest('form'); return !!form && passwordForms.has(form); })() });
      }
      if (elementDetails.length < DEVICE_PROFILE.maxElementDetails) {
        elementDetails.push({ tag, id: String(el.id || '').slice(0, 100),
          className: typeof el.className === 'string' ? el.className.slice(0, 160) : '',
          role, type: el.getAttribute('type') || '', label: visibleLabel,
          ariaLabel: String(el.getAttribute('aria-label') || '').slice(0, 160),
          hrefHost: href ? hostOf(href, location.href) : '', srcHost: src ? hostOf(src, location.href) : '',
          actionHost: action ? hostOf(action, location.href) : '', hidden: !!hidden,
          disabled: !!el.disabled, required: !!el.required,
          hasInlineHandler: Array.from(el.attributes || []).some((attribute) => /^on/i.test(attribute.name)),
          rel: el.getAttribute('rel') || '', target: el.getAttribute('target') || '',
          download: el.hasAttribute('download'), contentEditable: !!el.isContentEditable,
          externalMetaRefresh: tag === 'meta' && /refresh/i.test(el.getAttribute('http-equiv') || '') && (() => {
            try { const raw = String(el.getAttribute('content') || '').match(/url\s*=\s*['"]?([^'";]+)/i); return !!(raw && registrable(hostOf(raw[1].trim(), location.href)) !== registrable(location.hostname)); } catch (_) { return false; }
          })(),
          scriptableSrcdoc: tag === 'iframe' && !!el.getAttribute('srcdoc') && /<script|\son[a-z]+\s*=/i.test(el.getAttribute('srcdoc') || '') && !/\ballow-scripts\b/i.test(el.getAttribute('sandbox') || '') });
      }
      if ((href && /^(javascript:|data:)/i.test(href)) ||
          (el.getAttribute('target') === '_blank' && !/\bnoopener\b/i.test(el.getAttribute('rel') || '')) ||
          (location.protocol === 'https:' && ((href && /^http:/i.test(href)) || (src && /^http:/i.test(src))))) {
        if (securityAttributes.length < 200) securityAttributes.push({ tag, hrefScheme: href ? href.split(':')[0].toLowerCase() : '', srcHost: src ? hostOf(src, location.href) : '', targetBlankWithoutNoopener: el.getAttribute('target') === '_blank' && !/\bnoopener\b/i.test(el.getAttribute('rel') || '') });
      }
    }
    const forms = allForms.slice(0, DEVICE_PROFILE.maxAiForms || 20).map((form) => {
      const fields = fieldsByForm.get(form) || [];
      const actionHost = hostOf(form.getAttribute('action') || location.href, location.href);
      const fieldTypes = fields.map((field) => String(field.type || field.tagName || '').toLowerCase()).slice(0, 30);
      return { actionHost, method: String(form.getAttribute('method') || 'get').toUpperCase(),
        fieldCount: fields.length, fieldTypes,
        fieldLabels: fields.slice(0, 20).map((field) => {
          const label = field.labels && field.labels[0];
          return String((label && label.innerText) || field.getAttribute('aria-label') || field.getAttribute('autocomplete') || field.type || field.tagName || '').slice(0, 80);
        }),
        hasPassword: fields.some((field) => field.type === 'password'),
        hasPaymentField: fields.some((field) => /cc-number|card/i.test((field.autocomplete || '') + ' ' + (field.name || '') + ' ' + (field.id || ''))),
        hasSensitiveField: fields.some((field) => field.type === 'password' || /cc-number|card|one-time-code/i.test((field.autocomplete || '') + ' ' + (field.name || '') + ' ' + (field.id || ''))),
        crossOrigin: actionHost !== location.hostname };
    });
    const links = allLinks.slice(0, Math.max(200, DEVICE_PROFILE.maxAiLinks * 12)).map((a) => ({
      url: (() => { try { const u = new URL(a.getAttribute('href'), location.href); if (!/^https?:$/.test(u.protocol)) return ''; u.username = ''; u.password = ''; u.search = ''; u.hash = ''; return u.href.slice(0, 2048); } catch (_) { return ''; } })(),
      remoteUrl: (() => { try { const u = new URL(a.getAttribute('href'), location.href); if (!/^https?:$/.test(u.protocol)) return ''; u.username = ''; u.password = ''; u.hash = ''; for (const key of Array.from(u.searchParams.keys())) if (/(?:token|auth|session|secret|password|passwd|api.?key|access.?key|signature|(^|_)sig$|csrf|oauth|code|state|email|phone|user(?:name)?)/i.test(key)) u.searchParams.delete(key); return u.href.slice(0, 2048); } catch (_) { return ''; } })(),
      host: hostOf(a.getAttribute('href'), location.href),
      protocol: (() => { try { return new URL(a.getAttribute('href'), location.href).protocol; } catch (_) { return 'invalid:'; } })(),
      label: String(a.innerText || a.textContent || a.getAttribute('aria-label') || a.getAttribute('title') || '').trim().slice(0, 180),
      visible: !a.hidden && a.getAttribute('aria-hidden') !== 'true',
      targetBlank: a.target === '_blank', rel: a.rel || '', download: a.hasAttribute('download')
    }));
    const scriptBehavior = (source) => {
      const code = String(source || '').slice(0, DEVICE_PROFILE.maxInlineScriptChars || 2800);
      const flags = [];
      if (/\beval\s*\(|\bnew\s+Function\s*\(/i.test(code)) flags.push('dynamic-code-execution');
      if (/\batob\s*\(|\bunescape\s*\(|String\.fromCharCode|decodeURIComponent\s*\(/i.test(code)) flags.push('runtime-decoding');
      if (/createElement\s*\(\s*['"]script['"]|appendChild\s*\(\s*\w+\s*\)/i.test(code)) flags.push('dynamic-script-insertion');
      if (/document\.write|insertAdjacentHTML|\.innerHTML\s*=/i.test(code)) flags.push('dynamic-html-write');
      if (/location\.(?:href|assign|replace)|window\.open\s*\(/i.test(code)) flags.push('scripted-navigation');
      if (/\bfetch\s*\(|XMLHttpRequest/i.test(code)) flags.push('scripted-network-request');
      if (/navigator\.clipboard|clipboard\.writeText/i.test(code)) flags.push('clipboard-access');
      return flags;
    };
    const scriptDetails = allScriptNodes.slice(0, DEVICE_PROFILE.maxScripts || 48).map((script, index) => {
      const src = script.getAttribute('src') || '';
      const scriptType = String(script.getAttribute('type') || '').toLowerCase();
      const executable = !scriptType || /(?:java|ecma)script|module/i.test(scriptType);
      const source = !src && executable ? String(script.textContent || '').slice(0, DEVICE_PROFILE.maxInlineScriptChars || 2800) : '';
      return { scriptIndex: index, host: src ? hostOf(src, location.href) : location.hostname,
        srcHost: src ? hostOf(src, location.href) : '', inline: !src, executable,
        type: scriptType.slice(0, 60), async: !!script.async, defer: !!script.defer,
        integrity: !!script.integrity, codeLength: source.length,
        codePreview: source.slice(0, DEVICE_PROFILE.maxScriptPreviewChars || 360), behaviorSignals: scriptBehavior(source) };
    });
    const scripts = allScriptNodes.filter((script) => !!script.getAttribute('src')).slice(0, 160).map((script) => ({
      host: hostOf(script.getAttribute('src'), location.href), async: !!script.async, defer: !!script.defer, integrity: !!script.integrity
    }));
    const frames = allFrames.slice(0, 50).map((frame) => ({
      host: hostOf(frame.getAttribute('src') || '', location.href),
      hidden: (() => { try { const cs = getComputedStyle(frame); return cs.display === 'none' || cs.visibility === 'hidden' || frame.offsetWidth <= 1 || frame.offsetHeight <= 1; } catch (_) { return false; } })(),
      sandbox: frame.getAttribute('sandbox') || '', allow: frame.getAttribute('allow') || ''
    }));
    const resourceHosts = new Set();
    try { for (const entry of performance.getEntriesByType('resource').slice(-500)) { const h = hostOf(entry.name, location.href); if (h) resourceHosts.add(h); } } catch (_) {}
    return {
      url: location.href, title: document.title || '', capturedAt: Date.now(), elementCount: elements.length,
      elementDetails, elementDetailsTruncated: elements.length > elementDetails.length,
      inventoryTruncated: domIndexTruncated || elements.length >= MAX_INSPECTED_ELEMENTS, elementsByTag: counts,
      interactiveCount, interactive, forms, formCount: allForms.length,
      linkCount: allLinks.length, links, scriptCount: allScriptNodes.length, scripts,
      iframeCount: allFrames.length, frames, scriptDetails,
      openShadowRootCount: elements.filter((el) => !!el.shadowRoot).length,
      securityAttributeFindings: securityAttributes,
      inlineHandlerCount: elements.reduce((count, el) => count + (Array.from(el.attributes || []).some((attribute) => /^on/i.test(attribute.name)) ? 1 : 0), 0),
      resourceHosts: Array.from(resourceHosts).slice(0, 100),
      activityCounts: Object.assign({}, liveActivity.counts),
      recentActivity: liveActivity.recent.slice(-20),
      mutationCount: liveActivity.mutationCount, lastMutationAt: liveActivity.lastMutationAt,
      coverage: { openShadowRoots: true, closedShadowRoots: false,
        crossOriginFrames: 'Each frame is inspected independently only when browser host permissions allow content-script injection.' }
    };
  }

  function buildAiSnapshot(pageText, inventory, signals, reputation, options) {
    const opts = options || {};
    const cleanUrl = (value, keepSafeQuery) => {
      try {
        const u = new URL(value || location.href, location.href);
        if (!/^https?:$/.test(u.protocol)) return '';
        u.username = ''; u.password = ''; u.hash = '';
        if (!keepSafeQuery) u.search = '';
        else for (const key of Array.from(u.searchParams.keys())) {
          if (/(?:token|auth|session|secret|password|passwd|api.?key|access.?key|signature|(^|_)sig$|csrf|oauth|code|state|email|phone|user(?:name)?)/i.test(key)) u.searchParams.delete(key);
        }
        return u.href.slice(0, 2048);
      } catch (_) { return ''; }
    };
    const rawLinks = (inventory.links || []).filter((item) => item.url).slice(0, DEVICE_PROFILE.maxAiLinks || 28);
    const selectedUrl = cleanUrl(opts.selectedUrl, true);
    if (selectedUrl) {
      const selectedKey = cleanUrl(selectedUrl, false);
      const selectedIndex = rawLinks.findIndex((link) => link.url === selectedKey);
      const selected = selectedIndex >= 0 ? rawLinks.splice(selectedIndex, 1)[0] : {
        url: selectedKey, host: hostOf(selectedUrl, location.href), label: 'Link explicitly selected by the user', visible: true
      };
      rawLinks.unshift(Object.assign({}, selected, { remoteUrl: selectedUrl, selectedByUser: true }));
    }
    const links = rawLinks.slice(0, DEVICE_PROFILE.maxAiLinks || 28).map((link, index) => Object.assign({ id: 'L' + index }, link));
    const forms = (inventory.forms || []).slice(0, DEVICE_PROFILE.maxAiForms || 20).map((form, index) => Object.assign({ id: 'F' + index }, form, {
      crossSite: !!form.actionHost && registrable(form.actionHost) !== registrable(location.hostname)
    }));
    const downloads = [];
    for (const candidate of (signals.downloadCandidates || [])) {
      if (!candidate || !candidate.href) continue;
      const classified = SS.classifyDownloadCandidate ? SS.classifyDownloadCandidate(candidate) : null;
      if (!classified) continue;
      if (!classified.executable && !classified.script && !classified.disguised && !candidate.download) continue;
      downloads.push(Object.assign({ id: 'D' + downloads.length }, classified, { downloadAttribute: !!candidate.download,
        label: String(candidate.label || '').slice(0, 140) }));
      if (downloads.length >= (DEVICE_PROFILE.maxAiLinks || 28)) break;
    }
    // The monitor inspects the whole bounded DOM. The model receives a
    // high-information slice of controls/security-relevant nodes plus counts.
    const prioritizedScripts = (inventory.scriptDetails || []).slice().sort((a, b) =>
      (b.behaviorSignals || []).length - (a.behaviorSignals || []).length || Number(b.inline) - Number(a.inline));
    const scriptElements = prioritizedScripts.slice(0, DEVICE_PROFILE.maxAiScripts || 10).map((item) => Object.assign({ kind: 'script' }, item, {
      evidenceFlags: item.inline && item.executable && item.behaviorSignals && item.behaviorSignals.length >= 2
        ? ['multi-behavior-inline-script'] : []
    }));
    const prioritizedControls = (inventory.interactive || []).slice().sort((a, b) =>
      Number(/^(javascript|data):$/i.test(String(b.hrefProtocol || ''))) - Number(/^(javascript|data):$/i.test(String(a.hrefProtocol || ''))) ||
      Number(b.visible) - Number(a.visible));
    const controls = prioritizedControls.slice(0, DEVICE_PROFILE.maxInteractive || 550).map((item) => Object.assign({ kind: 'interactive-control' }, item, {
      evidenceFlags: /^(javascript|data):$/i.test(String(item.hrefProtocol || '')) ? ['active-link-scheme'] : []
    }));
    const details = (inventory.elementDetails || []).filter((item) => item.hrefHost || item.srcHost || item.actionHost ||
      item.hasInlineHandler || item.hidden || item.download || item.contentEditable || item.tag === 'meta' || item.tag === 'iframe')
      .sort((a, b) => Number(b.externalMetaRefresh || b.scriptableSrcdoc || b.hasInlineHandler) -
        Number(a.externalMetaRefresh || a.scriptableSrcdoc || a.hasInlineHandler)).slice(0, DEVICE_PROFILE.maxAiElements || 160)
      .map((item) => Object.assign({ kind: 'dom-element' }, item, {
        evidenceFlags: item.externalMetaRefresh ? ['external-meta-refresh'] : item.scriptableSrcdoc ? ['scriptable-srcdoc-frame'] : []
      }));
    const seenElements = new Set();
    const elements = scriptElements.concat(controls, details).filter((item) => {
      const key = [item.tag, item.id, item.hrefHost, item.srcHost, item.label, item.scriptIndex].join('|');
      if (seenElements.has(key)) return false;
      seenElements.add(key); return true;
    }).slice(0, DEVICE_PROFILE.maxAiElements || 160).map((item, index) => Object.assign({}, item, { id: 'E' + index }));
    return {
      routeKey: location.href, url: cleanUrl(location.href, false), host: location.hostname, isTopFrame: IS_TOP, title: String(document.title || '').slice(0, 300),
      visibleText: String(pageText || '').slice(0, DEVICE_PROFILE.maxVisibleTextChars || 5600),
      selectedText: String(opts.selectedText || '').slice(0, 8000),
      selectedLink: selectedUrl || '',
      selectionRequested: !!(opts.selectedText || selectedUrl),
      deviceHints: DEVICE_HINTS,
      deviceProfile: DEVICE_PROFILE,
      pageContext: signals.pageContext ? {
        pageKind: signals.pageContext.pageKind, isSearchResultsPage: !!signals.pageContext.isSearchResultsPage,
        hasEducationalCue: !!signals.pageContext.hasEducationalCue, articleLike: !!signals.pageContext.articleLike
      } : null,
      forms, links, downloads, elements,
      scripts: (inventory.scripts || []).slice(0, DEVICE_PROFILE.maxScripts || 48), frames: (inventory.frames || []).slice(0, 30),
      resourceHosts: (inventory.resourceHosts || []).slice(0, 40),
      securityAttributes: (inventory.securityAttributeFindings || []).slice(0, 80),
      counts: { elements: inventory.elementCount || 0, interactive: inventory.interactiveCount || 0,
        forms: inventory.formCount || 0, links: inventory.linkCount || 0, scripts: inventory.scriptCount || 0,
        frames: inventory.iframeCount || 0, openShadowRoots: inventory.openShadowRootCount || 0,
        inlineHandlers: inventory.inlineHandlerCount || 0, truncated: !!inventory.inventoryTruncated },
      activity: { counts: Object.assign({}, inventory.activityCounts || {}), recent: (inventory.recentActivity || []).slice(-10) },
      pageBehavior: { id: 'B0', dialogFloodCount: Number(techSignal.dialogFloodCount) || 0,
        fullscreenOnLoad: techSignal.fullscreenOnLoad === true,
        beforeUnloadCount: Number(techSignal.beforeUnloadCount) || 0,
        alarmAudio: techSignal.alarmAudio === true,
        notificationPermissionRequested },
      reputationSignals: reputation || {}, coverage: inventory.coverage || {}
    };
  }


  function aiSnapshotFingerprint(snapshot) {
    return SS.assessmentFingerprint(snapshot);
  }

  function scheduleLiveRescan(urgent) {
    clearTimeout(liveMutationTimer);
    clearTimeout(liveRescanTimer);
    const debounce = urgent ? Math.min(1500, DEVICE_PROFILE.mutationDebounceMs) : DEVICE_PROFILE.mutationDebounceMs;
    liveMutationTimer = setTimeout(() => {
      const minimum = urgent ? Math.min(5000, DEVICE_PROFILE.minFullRescanIntervalMs) : DEVICE_PROFILE.minFullRescanIntervalMs;
      const elapsed = Date.now() - lastLiveScanAt;
      const delay = Math.max(0, minimum - elapsed);
      liveRescanTimer = setTimeout(() => {
        if (document.visibilityState === 'hidden' && !urgent) return;
        lastLiveScanAt = Date.now();
        run({ automatic: true, urgent: !!urgent });
      }, delay);
    }, debounce);
  }

  function ensureLiveMonitor() {
    if (liveMonitorStarted) return;
    liveMonitorStarted = true;
    const eventTypes = [
      ['click', 'click'], ['dblclick', 'double-click'], ['auxclick', 'aux-click'],
      ['submit', 'form-submit'], ['reset', 'form-reset'], ['focusin', 'field-focus'],
      ['change', 'field-change'], ['input', 'field-input'], ['pointerdown', 'pointer-interaction'],
      ['keydown', 'keyboard-interaction'], ['copy', 'copy'], ['paste', 'paste'],
      ['drop', 'drop'], ['dragstart', 'drag-start'], ['contextmenu', 'context-menu'], ['scroll', 'scroll']
    ];
    const handleActivity = (type) => (event) => {
      if (!event.isTrusted || handledActivityEvents.has(event)) return;
      handledActivityEvents.add(event);
      if (type === 'pointer-interaction' && event.target && event.target.nodeType === 1 &&
          !event.target.closest('a,button,input,textarea,select,[role="button"],[role="link"]')) return;
      if (type === 'scroll') {
        liveActivity.counts.scroll = (liveActivity.counts.scroll || 0) + 1;
        return;
      }
      recordActivity(type, event.target);
    };
    const listeners = eventTypes.map(([name, type]) => [name, handleActivity(type)]);
    function observeRoot(domRoot) {
      if (!domRoot || observedRoots.has(domRoot)) return;
      observedRoots.add(domRoot);
      for (const [name, listener] of listeners) {
        try { domRoot.addEventListener(name, listener, { capture: true, passive: name === 'scroll' }); } catch (_) {}
      }
      if ('MutationObserver' in root) {
        try {
          const observer = new MutationObserver((records) => {
            let relevant = false;
            let indexStructureChanged = false;
            for (const record of records) {
              if (isPhishGuardNode(record.target)) continue;
              if (record.type === 'childList') {
                const changedNodes = [...record.addedNodes, ...record.removedNodes].filter((node) => !isPhishGuardNode(node));
                if (changedNodes.length) {
                  relevant = true;
                  indexStructureChanged = true;
                  for (const node of changedNodes) if (node.nodeType === 1) observeOpenRoots(node);
                  guardForeignCredentialFormsNow();
                }
              } else if (record.type === 'attributes' || record.type === 'characterData') {
                relevant = true;
              }
            }
            if (!relevant) return;
            if (indexStructureChanged) domIndexDirty = true;
            liveActivity.mutationCount += records.length;
            liveActivity.lastMutationAt = Date.now();
            scheduleLiveRescan(false);
          });
          observer.observe(domRoot, { childList: true, subtree: true, attributes: true,
            attributeFilter: ['href','action','formaction','formmethod','formenctype','formtarget','src','srcset','srcdoc','type','method','download','hidden','aria-hidden','aria-label','role','target','rel','name','id','autocomplete','required','disabled','contenteditable','sandbox','allow','allowfullscreen','integrity','crossorigin','referrerpolicy','nonce','poster','data-href','data-url','data-destination','data-action','data-link','data-download-url'], characterData: true });
          if (domRoot === document) window.__phishGuardMutationObserver = observer;
        } catch (_) {}
      }
      observeOpenRoots(domRoot);
    }
    function observeOpenRoots(scope) {
      if (!scope) return;
      const doc = scope.ownerDocument || document;
      let walker;
      try { walker = doc.createTreeWalker(scope, (root.NodeFilter && root.NodeFilter.SHOW_ELEMENT) || 1); } catch (_) { return; }
      let host = scope.nodeType === 1 ? scope : null;
      if (host && host.shadowRoot) observeRoot(host.shadowRoot);
      let node;
      let visited = 0;
      while ((node = walker.nextNode()) && visited++ < Math.min(1200, DEVICE_PROFILE.maxDomElements)) {
        if (node.shadowRoot) observeRoot(node.shadowRoot);
      }
    }
    observeRoot(document);
    guardForeignCredentialFormsNow();
    window.addEventListener('phishguard:shadow-root-created', (event) => {
      const host = event.target;
      if (host && host.shadowRoot) observeRoot(host.shadowRoot);
    }, true);
    if (document && typeof document.addEventListener === 'function') {
      document.addEventListener('visibilitychange', () => {
        liveActivity.counts.visibilityChange = (liveActivity.counts.visibilityChange || 0) + 1;
        if (document.visibilityState === 'visible') scheduleLiveRescan(false);
      });
    }
    window.addEventListener('pagehide', () => { liveActivity.counts.pageHide = (liveActivity.counts.pageHide || 0) + 1; });
    window.addEventListener('pageshow', () => { liveActivity.counts.pageShow = (liveActivity.counts.pageShow || 0) + 1; scheduleLiveRescan(false); });
    window.addEventListener('online', () => { liveActivity.counts.online = (liveActivity.counts.online || 0) + 1; });
    window.addEventListener('offline', () => { liveActivity.counts.offline = (liveActivity.counts.offline || 0) + 1; });
    window.addEventListener('hashchange', () => { liveActivity.counts.navigation = (liveActivity.counts.navigation || 0) + 1; scheduleLiveRescan(); });
    window.addEventListener('popstate', () => { liveActivity.counts.navigation = (liveActivity.counts.navigation || 0) + 1; scheduleLiveRescan(); });
    window.__phishGuardCapturePageInventory = capturePageInventory;
    window.__phishGuardLiveActivity = liveActivity;
  }

  function guardForeignCredentialFormsNow() {
    try {
      if (!SS || !SS.actions || typeof SS.actions.guardForms !== 'function') return;
      const auth = SS.KNOWN_AUTH_PROVIDERS || [];
      const fields = deepQueryAll('input[type="password"]');
      const forms = deepQueryAll('form').filter((form) => {
        const hasPassword = fields.some((field) => field.form === form || form.contains(field));
        if (!hasPassword) return false;
        try {
          const targetHost = new URL(form.getAttribute('action') || location.href, location.href).hostname;
          const targetDomain = SS.registrableDomain ? SS.registrableDomain(targetHost) : targetHost;
          const pageDomain = SS.registrableDomain ? SS.registrableDomain(location.hostname) : location.hostname;
          return targetDomain !== pageDomain && !auth.includes(targetDomain);
        } catch (_) { return false; }
      });
      if (forms.length) SS.actions.guardForms(forms, formGuardReasons || [], () => send('userReport', { label: 'false_positive' }));
    } catch (_) {}
  }

  function needsPageAnalysis(signals, urlRules, domRules) {
    if (signals.hasPasswordField) return true;
    if (Math.max(urlRules.score, domRules.score) >= 0.3) return true;
    return deepQueryAll('form').some((f) =>
      deepQueryAll('input:not([type]),input[type="text"],input[type="email"],input[type="tel"],input[type="number"],input[type="password"]')
        .filter((field) => field.form === f || f.contains(field)).length >= 2);
  }
  function iconCandidates() {
    const out = [];
    const add = (h) => { try { const u = new URL(h, location.href); if (/^https?:$/.test(u.protocol)) out.push(u.href); } catch (_) {} };
    document.querySelectorAll('link[rel~="icon"],link[rel="apple-touch-icon"]').forEach((l) => add(l.getAttribute('href') || ''));
    add('/favicon.ico');
    [...document.querySelectorAll('img')].filter((i) => /logo/i.test((i.getAttribute('src') || '') + ' ' + (i.getAttribute('alt') || '') + ' ' + i.className + ' ' + i.id) && (i.naturalWidth >= 40 || i.width >= 40)).slice(0, 2).forEach((i) => add(i.getAttribute('src') || ''));
    return [...new Set(out)].slice(0, 6);
  }
                                                                         
                                                                              
  const withTimeout = (p, ms) => {
    let t;
    const timeout = new Promise((r) => { t = setTimeout(() => r(null), ms); });
    return Promise.race([p, timeout]).finally(() => clearTimeout(t));
  };

                                                                              
                                                                             
                                                                             
                                                                             
                                                                           
                                        
  const CARD_INPUT_SEL = 'input[autocomplete="cc-number"], input[name*="card" i], input[id*="card" i], input[placeholder*="card" i]';

  function registrable(host) {
    if (SS && typeof SS.registrableDomain === 'function') return SS.registrableDomain(host);
    return String(host || '').toLowerCase().split('.').filter(Boolean).slice(-2).join('.');
  }

                                                                               
                                                                        
  function scopeOf(host) {
    if (SS && typeof SS.scopeDomain === 'function') return SS.scopeDomain(host);
    return registrable(host);
  }
                                                                         
                                                                           
                                                                     
  function scopeKeysOf(host) {
    if (SS && typeof SS.scopeKeys === 'function') return SS.scopeKeys(host);
    return [registrable(host)];
  }
  function isMutedHere(muted, kind) {
    return !!(SS.isMuted && scopeKeysOf(location.hostname).some((k) => SS.isMuted(muted, k, kind)));
  }

                                                                            
                                                                              
                                                
  function isUserExemptHost(host, settings) {
    const keys = scopeKeysOf(host);
    if (SS && SS.isPaused && keys.some((k) => SS.isPaused(settings && settings.pausedSites, k, Date.now()))) return true;
    return keys.some((k) => ((settings && settings.allowlist) || []).includes(k));
  }
  function isTrustedHost(host, settings) {
    return !!(SS && typeof SS.isSafeHost === 'function' && SS.isSafeHost(host)) || isUserExemptHost(host, settings);
  }

                                                                                    
  function muteHandler(kind) {
    return async () => {
      const domain = scopeOf(location.hostname);
      await send('muteWarning', { domain, kind, via: kind + '-toast' });
      if (SS.actions && SS.actions.ackSurface) SS.actions.ackSurface({ text: t('ackMuted', [bidi(domain)], "PhishGuard won't show this warning on " + domain + ' again.'), onUndo: () => send('unmuteWarning', { domain, kind }) });
    };
  }

                                                                                    
                                                                               
                                                                             
                                                                             
                                                                               
  const pageDetail = (o) => (typeof cloneInto === 'function' ? cloneInto(o, window) : o);
  function reply(id, allow) {
    try { window.dispatchEvent(new CustomEvent('phishguard:wallet-decision', { detail: pageDetail({ id, allow }) })); } catch (_) {}
  }
  window.addEventListener('phishguard:wallet-confirm', async (e) => {
    const detail = (e && e.detail) || {};
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || settings.walletGuard === false) { reply(detail.id, true); return; }
    if (isTrustedHost(location.hostname, settings)) { reply(detail.id, true); return; }
    if (!SS || !SS.actions) { reply(detail.id, true); return; }
    SS.actions.walletConfirmOverlay(detail, (allow, meta) => {
      reply(detail.id, allow);
      if (!allow && !(meta && meta.collision)) send('bumpThreats', { kind: 'wallet' });
    });
  });
  const clipboardSeen = new Set();                                                                      
  window.addEventListener('phishguard:clipboard-alert', async (e) => {
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || !SS || !SS.actions) return;
    if (settings.clipboardGuard === false && settings.clickFixGuard === false) return;
    if (isTrustedHost(location.hostname, settings)) return;
    const detail = (e && e.detail) || {};
    let cf = { level: 'none', reasons: [], flags: [] };
                                                                      
                                                                             
                                                                            
    if (detail.level === 'dangerous' && settings.clickFixGuard !== false && SS.scoreClickFix) {
      cf = SS.scoreClickFix({ text: (document.body ? document.body.innerText : '').slice(0, 20000), clipboardLevel: 'dangerous' });
    }
                                                                               
                                                                              
                                                                                
                                                                         
                                                                            
                                                                              
    const userGesture = !!(navigator.userActivation && navigator.userActivation.isActive);
    const tier = SS.clipboardTier({ level: detail.level, clickfixLevel: cf.level, userGesture });
    if (tier === 'none') return;
    if (tier === 'block' && SS.actions.dangerInterstitial) {
      try { await navigator.clipboard.writeText(t('guardClipboardBlockedPayload', null, 'Blocked by PhishGuard — this site put a dangerous command on your clipboard. Do not paste it anywhere.')); } catch (_) {                                }
      SS.actions.dangerInterstitial({ level: 'dangerous', reasons: cf.reasons, flags: cf.flags }, { onLeave: () => send('leaveTab'), onReport: () => send('userReport', { label: 'false_positive' }) });
      send('reportVerdict', { verdict: { level: 'dangerous', score: 0.95, reasons: cf.reasons, reasonCodes: cf.reasons.map((x) => x.code), flags: cf.flags, modelUsed: false }, subframe: !IS_TOP });
      send('bumpThreats', { kind: 'clipboard' });
      return;
    }
    if (settings.clipboardGuard === false) return;
    if (isMutedHere(settings.mutedWarnings, 'clipboard')) return;
    const key = detail.level + '|' + (detail.sample || '');
    if (clipboardSeen.has(key)) return; clipboardSeen.add(key);
                                                                            
    SS.actions.clipboardToast({ tier, level: detail.level, reasons: detail.reasons, host: location.hostname, onMute: muteHandler('clipboard') });
  });
  // Page wording is never allowed to turn the legacy scareware classifier
  // directly into a threat verdict. Observe concrete browser behaviors and
  // pass them to the generative page assessor for contextual interpretation.
  let techSignal = { dialogFloodCount: 0, fullscreenOnLoad: false, beforeUnloadCount: 0, alarmAudio: false };
  let notificationPermissionRequested = false;
  let lastTechSignalFingerprint = '';
  window.addEventListener('phishguard:techscam-signal', async (e) => {
    techSignal = Object.assign(techSignal, (e && e.detail) || {});
    const fingerprint = JSON.stringify(techSignal);
    if (fingerprint === lastTechSignalFingerprint) return;
    lastTechSignalFingerprint = fingerprint;
    const hasBehavior = Number(techSignal.dialogFloodCount) > 0 || techSignal.fullscreenOnLoad === true ||
      Number(techSignal.beforeUnloadCount) > 0 || techSignal.alarmAudio === true;
    if (!hasBehavior) return;
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || settings.techScamGuard === false || isTrustedHost(location.hostname, settings)) return;
    liveActivity.counts['browser-behavior-observed'] = (liveActivity.counts['browser-behavior-observed'] || 0) + 1;
    scheduleInventoryReport();
    scheduleLiveRescan();
  });

  const privacySeen = new Set();
  window.addEventListener('phishguard:leaky-form', async (e) => {
    const d = (e && e.detail) || {};
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || settings.leakyFormGuard === false) return;
    if (isTrustedHost(location.hostname, settings)) return;
    if (isMutedHere(settings.mutedWarnings, 'leak')) return;
    const key = 'leak|' + d.destHost + '|' + d.kind;
    if (privacySeen.has(key)) return; privacySeen.add(key);
    const text = d.kind === 'plain'
      ? t('guardLeakyFormPlain', [bidi(d.destHost)], 'This site sent your email/phone to ' + d.destHost + ' in plain text — before you pressed submit.')
      : t('guardLeakyFormHashed', [bidi(d.destHost), bidi(d.kind.toUpperCase())], 'This site sent your email/phone to ' + d.destHost + ' as a hashed (' + d.kind.toUpperCase() + ') identifier — before you pressed submit.');
    if (SS.actions && SS.actions.privacyToast) {
      SS.actions.privacyToast({ title: t('leakTitle', null, 'Form data may have been sent before submission'), text, muteKind: 'leak', onMute: muteHandler('leak') });
    }
    send('privacyFinding', { finding: { kind: 'leaky-form', host: d.destHost, detail: d.kind } });
  });
  window.addEventListener('phishguard:fingerprint', async (e) => {
    const d = (e && e.detail) || {};
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || settings.fingerprintDetect === false) return;
    if (isTrustedHost(location.hostname, settings)) return;
    let host = d.origin; try { host = new URL(d.origin).hostname; } catch (_) {}
    const key = 'fp|' + host;
    if (privacySeen.has(key)) return; privacySeen.add(key);
    send('privacyFinding', { finding: { kind: 'fingerprint', host, detail: (d.surfaces || []).join(',') } });
  });
  window.addEventListener('phishguard:notify-request', async () => {
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled || settings.notificationGuard === false || isTrustedHost(location.hostname, settings)) return;
    // Permission prompts are common and are not malicious by themselves.
    // Record the actual API request for model context; wording is not proof.
    notificationPermissionRequested = true;
    liveActivity.counts['notification-permission-request'] = (liveActivity.counts['notification-permission-request'] || 0) + 1;
    scheduleInventoryReport();
    scheduleLiveRescan();
  });

  function collectSignals(settings) {
    settings = settings || {};
    const pageHost = location.hostname;
    const allForms = deepQueryAll('form');
    const passwordFields = deepQueryAll('input[type="password"]');
    const passwordForms = allForms.filter((form) => passwordFields.some((field) => field.form === form || form.contains(field)));
    const passwordFormActions = passwordForms.map((f) => f.getAttribute('action') || location.href);
    const AUTH = (SS && SS.KNOWN_AUTH_PROVIDERS) || [];
    const foreignForms = passwordForms.filter((f) => {
      try {
        const h = new URL(f.getAttribute('action') || location.href, location.href).hostname;
        const actionDomain = registrable(h);
                                                                              
                                                                      
        return actionDomain !== registrable(pageHost) && !AUTH.includes(actionDomain);
      } catch (_) { return false; }
    });
                                                                           
                                                                           
                                                                          
                                                                        
                                                                         
                                                                         
                                                                       
    const exfilForms = deepQueryAll('form')
      .filter((f) => !foreignForms.includes(f))
      .filter((f) => {
        const fields = deepQueryAll('input,textarea,select').filter((field) => field.form === f || f.contains(field));
        const hasPassword = fields.some((field) => field.type === 'password');
        const hasCard = fields.some((field) => /cc-number|card/i.test((field.autocomplete || '') + ' ' + (field.name || '') + ' ' + (field.id || '')));
        if (!hasPassword && !hasCard) return false;
                                                                             
                                                                             
                                                                       
                                                                            
                                          
        if (hasPassword) {
          try {
            const actionDomain = registrable(new URL(f.getAttribute('action') || location.href, location.href).hostname);
            if (AUTH.includes(actionDomain)) return false;
          } catch (_) {}
        }
        return !!(SS && SS.crossOriginCredPostHost && SS.crossOriginCredPostHost(location.href, f.getAttribute('action')));
      });

    const hiddenIframeCount = deepQueryAll('iframe').filter((fr) => {
      const cs = getComputedStyle(fr);
      return cs.display === 'none' || cs.visibility === 'hidden' ||
        (fr.offsetWidth <= 1 && fr.offsetHeight <= 1);
    }).length;

    const bodyText = pageTextSnapshot(100000).toLowerCase();
    // Separate operative page instructions from material explicitly presented
    // as examples, quotations, code, or training snippets. This is a context
    // feature only; the original page remains untouched.
    let activeText = bodyText;
    try {
      if (document.body && document.body.cloneNode) {
        const activeCopy = document.body.cloneNode(true);
        for (const node of activeCopy.querySelectorAll('blockquote,q,pre,code,figure,[role="note"],[class*="example" i],[class*="sample" i],[class*="quote" i],[data-example]')) node.remove();
        activeText = String(activeCopy.innerText || activeCopy.textContent || '').slice(0, 40000).toLowerCase();
      }
    } catch (_) {}
    const hasCardInput = deepQueryAll(CARD_INPUT_SEL).length > 0;
    const formCount = allForms.length;
    const linkCount = deepQueryAll('a[href]').length;
    const actionNodes = deepQueryAll('a,button,[role="button"]').slice(0, 500);
    const ctaCount = actionNodes.filter((node) => /\b(?:verify|confirm|update|continue|sign in|log in|unlock|restore|review|pay now|submit|claim|secure account|complete)\b/i.test(
      ((node.innerText || node.textContent || '') + ' ' + (node.getAttribute('aria-label') || '') + ' ' + (node.getAttribute('title') || '')).slice(0, 240)
    )).length;
    const mentionsSeed = (SS.SEED_PHRASE_HINTS || []).some((p) => bodyText.includes(p));
    const manyWordInputs = deepQueryAll('input[type="text"],input:not([type]),textarea').length >= 12;
    const seedPhraseForm = mentionsSeed && manyWordInputs;
    const pageContext = SS.classifyPageContext ? SS.classifyPageContext(bodyText, {
      host: pageHost, pageHost, url: location.href, title: document.title || '', activeText,
      articleCount: deepQueryAll('article').length,
      mainCount: deepQueryAll('main,[role=main]').length,
      blockquoteCount: deepQueryAll('blockquote,q').length,
      codeBlockCount: deepQueryAll('pre,code').length,
      formCount, linkCount, ctaCount,
      hasPasswordField: passwordForms.length > 0, hasCardInput,
      hasForeignCredentialForm: foreignForms.length > 0,
      hasCrossOriginCredentialPost: exfilForms.length > 0,
      seedPhraseForm
    }) : null;
    const passiveInformational = !!(pageContext && pageContext.passiveInformational);
    const text = pageTextSnapshot(50000).toLowerCase().slice(0, 20000);

    const downloadNodes = deepQueryAll('a[href],a[download],button,[role=button]').slice(0, 500);
    const downloadCandidates = [];
    const filePattern = /\b[^\s<>\"']{1,150}\.(?:exe|msi|msp|dll|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|wsf|wsh|jar|apk|dmg|pkg|appx|msix|reg|lnk|iso|img|zip|rar|7z|tar|gz|docm|xlsm|pptm)\b/ig;
    let downloadCount = 0;
    for (const node of downloadNodes) {
      if (downloadCandidates.length >= 120) break;
      const label = ((node.innerText || node.textContent || '') + ' ' + (node.getAttribute('aria-label') || '') + ' ' + (node.getAttribute('title') || '') + ' ' + (node.getAttribute('data-tooltip') || '')).trim().slice(0, 300);
      const href = node.getAttribute('href') || '';
      const filename = node.getAttribute('download') || '';
      const isDownload = node.hasAttribute('download') || /\b(download|install|open file|view file|run file)\b/i.test(label);
      if (!isDownload && !/\.(?:exe|msi|msp|dll|scr|com|bat|cmd|ps1|vbs|js|hta|jar|apk|dmg|pkg|iso|img|zip|rar|7z)(?:$|[?#])/i.test(href)) continue;
      downloadCandidates.push({ href, label, filename, download: filename, isDownload, pageHost });
      downloadCount++;
    }
    const visibleNames = (document.body ? document.body.innerText : '').slice(0, 50000).match(filePattern) || [];
    for (const name of visibleNames.slice(0, 20)) downloadCandidates.push({ filename: name, label: name, isDownload: downloadCount > 0, pageHost });
    for (const node of [...document.querySelectorAll('h1,h2,[aria-label],[title]')].slice(0, 100)) {
      const name = ((node.textContent || '') + ' ' + (node.getAttribute('aria-label') || '') + ' ' + (node.getAttribute('title') || '')).trim().slice(0, 180);
      if (/\.(?:exe|msi|scr|bat|cmd|ps1|vbs|js|hta|jar|apk|dmg|pkg|iso|img|zip|rar|7z|docm|xlsm|pptm)\b/i.test(name)) downloadCandidates.push({ filename: name, label: name, isDownload: downloadCount > 0, pageHost });
    }

                                                   
    const titleBrand = (document.title || '').toLowerCase();
    const ogEl = document.querySelector('meta[property="og:site_name"]');
    const ogSiteName = ogEl ? (ogEl.getAttribute('content') || '') : '';
    const iconEl = document.querySelector('link[rel~="icon"]');
    let faviconHost = '';
    try { faviconHost = iconEl ? new URL(iconEl.getAttribute('href'), location.href).hostname : ''; } catch (_) {}
                                                                          
                                                                        
                                                                       
                                                                       
                                                                            
                                       
                                                                            
                                                                         
                                                                            
                                                                       
                                                                        
                                                                              
    const SSO_CTA_RE = /\b(?:sign in|sign-in|log in|log-in|login|continue) with\b/i;
    const insideSsoButton = (n) => {
      const btn = n.closest && n.closest('button,a,[role="button"]');
      if (!btn) return false;
      const clone = btn.cloneNode(true);
      clone.querySelectorAll('[hidden],[aria-hidden="true"]').forEach((el) => el.remove());
      return SSO_CTA_RE.test(clone.textContent || '');
    };
    const altImgs = [...document.querySelectorAll('img[alt]')]
      .filter((n) => {
        const bigEnough = (n.naturalWidth || 0) >= 24 || (n.width || 0) >= 24;
        const looksLikeLogo = /logo/i.test((n.getAttribute('src') || '') + ' ' + n.className + ' ' + n.id);
        return (bigEnough || looksLikeLogo) && !insideSsoButton(n);
      })
      .map((n) => n.getAttribute('alt') || '');
    const ariaEls = [...document.querySelectorAll('[aria-label]')]
      .filter((n) => !insideSsoButton(n))
      .map((n) => n.getAttribute('aria-label') || '');
    const logoAltBrands = altImgs.concat(ariaEls).slice(0, 40).map((t) => t.toLowerCase());

                                                                                       
    const rawClickfix = (SS.scoreClickFix && settings.clickFixGuard !== false) ? SS.scoreClickFix({ text: bodyText }) : null;
    const clickfix = passiveInformational && !seedPhraseForm ? null : rawClickfix;

                                                                             
                                          
    let fakeUpdate = null;
    if (SS.scoreFakeUpdate && settings.fakeUpdateGuard !== false && /update|out.of.date|outdated/i.test(bodyText)) {
      const updateAnchorHosts = [];
      let hasBlobDownload = false;
      let walked = 0;
      for (const a of document.querySelectorAll('a[href], a[download], button')) {
        if (++walked > 300) break;
        const t = ((a.textContent || '') + ' ' + (a.getAttribute('aria-label') || '')).toLowerCase();
        if (!/update|download|install/.test(t)) continue;
        if (a.hasAttribute('download')) hasBlobDownload = true;
        const href = a.getAttribute('href');
        if (!href) continue;
        if (/^(blob|data):/i.test(href)) { hasBlobDownload = true; continue; }
        try {
          const u = new URL(href, location.href);
          if (/^https?:$/.test(u.protocol)) updateAnchorHosts.push(registrable(u.hostname));
        } catch (_) {}
      }
      fakeUpdate = SS.scoreFakeUpdate({ text: bodyText, updateAnchorHosts, hasBlobDownload });
      if (passiveInformational && !hasBlobDownload && downloadCount === 0) fakeUpdate = null;
    }

                                                                                 
    const deliveryFeeText = /(redeliver|redelivery|customs|clearance|delivery|shipping|postage)\s+fee|unpaid\s+(postage|customs|fee)|pay\s+(a\s+)?(small\s+)?fee|schedule.{0,24}redelivery/i.test(bodyText);

    return {
      signals: {
        pageHost, hasPasswordField: passwordForms.length > 0, passwordFormActions, hiddenIframeCount,
        titleBrand, ogSiteName, faviconHost, logoAltBrands, seedPhraseForm,
        clickfix, fakeUpdate, hasCardInput, deliveryFeeText, formCount, linkCount, ctaCount,
        downloadCandidates, downloadCount, pageContext
      },
      foreignForms, exfilForms
    };
  }

                                                                       
  function parseCountdownSeconds() {
                                                                                
    let best = 0, scanned = 0;
    for (const el of document.querySelectorAll('[class*="countdown" i],[class*="timer" i],[id*="countdown" i],time,span,div,b')) {
      if (++scanned > 400) break;
      const t = (el.textContent || '').trim();
      const m = t.match(/\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b/);
      if (!m) continue;
      const secs = m[3] ? (+m[1]) * 3600 + (+m[2]) * 60 + (+m[3]) : (+m[1]) * 60 + (+m[2]);
      if (secs > best && secs <= 48 * 3600) best = secs;
    }
    return best;
  }
  async function collectShop(bodyText, pageHost) {
    const looksLikeShop = /add to (cart|bag|basket)|proceed to checkout|checkout|shopping cart|order summary|free shipping|buy now/i.test(bodyText) ||
      !!document.querySelector('[class*="add-to-cart" i],[id*="add-to-cart" i],[class*="addtocart" i],[name*="checkout" i]');
    if (!looksLikeShop) return { isStorefront: false };
    const fakeScarcity = (bodyText.match(/only\s+\d+\s+left|selling fast|\d+\s+(people|others)\s+(are\s+)?(viewing|watching|looking)|in\s+\d+\s+carts/gi) || []).length;
    const offPlatformPay = /\b(zelle|venmo|cash\s?app|western union|moneygram|wire transfer|bank transfer|pay(?:ing)? (?:by|with) (?:crypto|bitcoin|usdt))\b/i.test(bodyText);
    const badgeHotlink = [...document.querySelectorAll('img')].some((im) => {
      const s = ((im.getAttribute('src') || '') + ' ' + (im.getAttribute('alt') || '')).toLowerCase();
      if (!/secure|verified|trust|guarante|ssl|norton|mcafee/.test(s)) return false;
      let host = ''; try { host = new URL(im.src, location.href).hostname; } catch (_) { return false; }
      const crossOrigin = registrable(host) !== registrable(pageHost);
      const linked = !!im.closest('a[href]');
      return crossOrigin && !linked;
    });
    const hasContact = !!document.querySelector('a[href*="contact" i],a[href*="about" i],a[href*="imprint" i],a[href^="tel:"],a[href^="mailto:"]') ||
      /\b(contact us|customer service|our address|registered office|company (number|registration))\b/i.test(bodyText);
    const missingContact = !hasContact;
    let countdownReset = false;
    const secs = parseCountdownSeconds();
    if (secs > 0) { try { const r = await send('shopCountdown', { domain: registrable(pageHost), seconds: secs }); countdownReset = !!(r && r.reset); } catch (_) {} }
    return { isStorefront: true, fakeScarcity, offPlatformPay, badgeHotlink, missingContact, countdownReset };
  }

                                                                           
                                                                               
                                                                              
                                                                                
                                                                           
                                       
  const SEARCH_HOSTS = /^(?:(?:www\.)?google\.(?:com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})|(?:www\.)?bing\.com|(?:www\.)?duckduckgo\.com|html\.duckduckgo\.com|search\.brave\.com|(?:www\.)?ecosia\.org|search\.yahoo\.com|(?:www\.)?startpage\.com|search\.qwant\.com)$/i;
  function checkSerp() {
    let flagged = 0;
    const anchors = document.querySelectorAll('a[href^="http"]');
    let scanned = 0;
    for (const a of anchors) {
      if (++scanned > 600 || flagged >= 8) break;
      if (a.__ssSerp) continue;
                                                             
      let n = a, sponsored = false, hops = 0;
      while (n && hops++ < 6) {
        const lbl = ((n.getAttribute && (n.getAttribute('aria-label') || n.getAttribute('data-text-ad') || '')) || '') + ' ' + (n.className || '');
        if (/sponsored|\bads?\b|data-text-ad/i.test(String(lbl))) { sponsored = true; break; }
        n = n.parentElement;
      }
      if (!sponsored) {
                                                                     
        const cite = a.closest('div,li,article');
        if (cite && /\bsponsored\b|\bad\b·|·\s*ad\b/i.test((cite.innerText || '').slice(0, 60))) sponsored = true;
      }
      if (!sponsored) continue;
      let destHost = ''; try { destHost = new URL(a.href).hostname; } catch (_) { continue; }
      const destReg = registrable(destHost);
                                                                         
      const cite = a.querySelector('cite') || a.closest('div,li,article') && (a.closest('div,li,article').querySelector('cite'));
      let shownReg = '';
      if (cite) { const m = (cite.textContent || '').match(/([a-z0-9-]+\.)+[a-z]{2,}/i); if (m) shownReg = registrable(m[0].replace(/^https?:\/\//, '')); }
      if (!shownReg || shownReg === destReg) continue;
                                                  
      a.__ssSerp = true;
      const chip = document.createElement('span');
      chip.className = 'phishguard-serp';
      setDir(chip);
      chip.textContent = t('serpAdMismatch', [bidi(destReg), bidi(shownReg)], '⚠ PhishGuard: this ad goes to ' + destReg + ', not ' + shownReg);
      (a.closest('div,li,article') || a).appendChild(chip);
      flagged++;
    }
    return flagged;
  }

                                                                            
                                                                             
                                                                             
                                                                              
                                                                       
                                                                       
                                                                                 
                                                                            
                                                                           
                                                                
  const SERP_BADGE_CAP = 50;
  const SERP_BADGE_SCAN_CAP = DEVICE_PROFILE.maxSerpAnchorScan || 420;
  let serpBadgeBudget = SERP_BADGE_CAP;
  let serpBadgeRunning = false;
  let serpBadgePending = false;
  let serpObserverStarted = false;
  let serpObserverTimer = null;

                                                                              
                                                                              
                                                                               
                                                            
  function serpResultHost(a) {
    const href = a && a.getAttribute && a.getAttribute('href');
    if (!href || !SS || typeof SS.unwrapSerpRedirect !== 'function') return null;
    const real = SS.unwrapSerpRedirect(href, location.href);
    if (!real) return null;
    try { const u = new URL(real); return /^https?:$/.test(u.protocol) ? u.hostname : null; } catch (_) { return null; }
  }

  function badgeGlyph() {
    return '<svg viewBox="0 0 8 8" width="8" height="8" aria-hidden="true" focusable="false"><circle cx="4" cy="4" r="4" fill="currentColor"/></svg>';
  }
  function paintSerpBadge(a, level) {
    const dot = document.createElement('span');
    dot.className = 'phishguard-serp-badge phishguard-serp-badge-' + level;
    setDir(dot);
    dot.setAttribute('role', 'img');
    const label = level === 'danger'
      ? t('serpBadgeDanger', null, 'PhishGuard: this result is on our threat block list')
      : t('serpBadgeCaution', null, 'PhishGuard: this result shows scam warning signs');
    dot.setAttribute('aria-label', label);
    dot.setAttribute('title', label);
    dot.innerHTML = badgeGlyph();
                                                                              
                                                                             
    a.insertAdjacentElement('afterend', dot);
  }

                                                                          
                                                                       
                                                                          
                                                                          
  function collectSerpBadgeTargets() {
    if (serpBadgeBudget <= 0) return [];
    const anchors = document.querySelectorAll('a[href]');
    const targets = [];
    let scanned = 0;
    for (const a of anchors) {
      if (serpBadgeBudget <= 0 || ++scanned > SERP_BADGE_SCAN_CAP) break;
      if (a.__ssSerpBadge) continue;
      a.__ssSerpBadge = true;
      const host = serpResultHost(a);
      if (!host || SEARCH_HOSTS.test(host)) continue;
      targets.push({ a, host });
      serpBadgeBudget--;
    }
    return targets;
  }

  async function annotateSerpResults() {
    if (serpBadgeRunning) { serpBadgePending = true; return; }
    serpBadgeRunning = true;
    try {
      do {
        serpBadgePending = false;
        const targets = collectSerpBadgeTargets();
        if (!targets.length) break;
        const hosts = SS.dedupeCapped(targets.map((tg) => tg.host), SERP_BADGE_CAP);
        let feedResults = {};
        try {
          const res = await send('checkFeedBatch', { hosts });
          feedResults = (res && res.results) || {};
        } catch (_) {                                                     }
        for (const { a, host } of targets) {
          if (!a.isConnected) continue;                                          
          const feedHit = feedResults[host];
          let level = null;
          if (feedHit === 'block') level = 'danger';
          else if (feedHit === 'warn') level = 'caution';
          else if (SS.fuzzyBrandMatch && SS.allowlistBrandMatch && !SS.allowlistBrandMatch(host)) {
            const fuzzy = SS.fuzzyBrandMatch(host);
            if (fuzzy && (fuzzy.grade === 'strongest' || fuzzy.grade === 'strong')) level = 'caution';
          }
          if (level) paintSerpBadge(a, level);
        }
      } while (serpBadgePending);
    } catch (_) {                                                             }
    finally { serpBadgeRunning = false; }
  }

                                                                           
                                                                              
                                                       
  function ensureSerpBadgeObserver() {
    if (serpObserverStarted || !('MutationObserver' in root)) return;
    serpObserverStarted = true;
    try {
      const mo = new MutationObserver(() => {
        clearTimeout(serpObserverTimer);
        serpObserverTimer = setTimeout(() => { annotateSerpResults(); }, DEVICE_PROFILE.serpObserverDebounceMs || 1400);
      });
      mo.observe(document.body, { childList: true, subtree: true });
    } catch (_) {}
  }

                                                                             
                                                                              
                                                                              
                                                                               
                                                                             
                                                                               
                                                                              
                                                                             
                                                                              
                                                                          
                                                       
  function guardExfilForms(forms, settings) {
    forms.forEach((form) => {
      if (form.__phishguardExfilGuarded) return;
      form.__phishguardExfilGuarded = true;
      const onSubmit = (ev) => {
        const hasPassword = !!form.querySelector('input[type="password"]');
        let kind = null;
        if (hasPassword) {
          kind = 'password';
        } else {
          const panInput = [...form.querySelectorAll(CARD_INPUT_SEL)]
            .find((inp) => SS.isPanShaped && SS.isPanShaped(inp.value));
          if (panInput) kind = 'card';
        }
        if (!kind) return;                                                          
        const destHost = SS.crossOriginCredPostHost && SS.crossOriginCredPostHost(location.href, form.getAttribute('action'));
        if (!destHost) return;                                                                       
                                                                        
                                                                         
                                                       
        if (isMutedHere(settings && settings.mutedWarnings, 'credpost')) return;
        ev.preventDefault(); ev.stopPropagation();
        const reason = { code: 'crossOriginCredPost', kind: 'page', params: [destHost] };
        if (SS.actions && SS.actions.crossOriginCredToast) {
                                                                               
                                                                                 
                                                                        
          SS.actions.crossOriginCredToast(reason, () => form.submit(), muteHandler('credpost'));
        } else {
          form.submit();                                                       
        }
        send('privacyFinding', { finding: { kind: 'cross-origin-cred-post', host: destHost, detail: kind } });
      };
                                                                             
                                                                               
                                                                              
                                                                
                                                                            
                                                                      
                                                                           
                                                                    
      form.addEventListener('submit', onSubmit, true);
      form.addEventListener('phishguard:formsubmit', onSubmit, true);
    });
  }

                                                                                
                                                                           
                                                                       
                                                                       
                                                                                     
                                                                            
                                                                          
                                                                         
  const QR_POPUP_MIN_SIZE = 48, QR_POPUP_CAP = 30;
  const QR_AUTOSCAN_MIN_SIZE = 120, QR_AUTOSCAN_CAP = 10;
  let qrAutoScanBudget = 30;                                                               

                                                                           
                                                                           
                                                                     
                                                                           
                                                                           
                                                                
  async function scoreDecodedUrl(url, settings) {
    let host = '';
    try { host = new URL(url).hostname; } catch (_) { return null; }
    if (isTrustedHost(host, settings)) return { url, host, level: 'safe', score: 0, reasons: [] };
    const urlRules = SS.scoreUrl(url, settings.riskTlds);
    let modelProb = null;
    if (urlRules.score >= 0.3 && SS.isAvailable && SS.isAvailable()) {
      try { modelProb = await SS.predict(SS.extractUrlFeatures(url)); } catch (_) {}
    }
    let verdict = SS.fuse({ modelProb, urlRules, domRules: { score: 0, reasons: [], flags: [] }, contentProb: null, iconMatch: false });
    try {
      const feedHit = await withTimeout(send('checkFeed', { host }), 5000);
      if (feedHit && feedHit.hit === 'block') {
        const reason = { code: 'feedBlock', kind: 'link', params: [String((feedHit.sources || []).length)] };
        verdict = Object.assign({}, verdict, {
          level: 'dangerous', score: Math.max(verdict.score, 0.97),
          reasons: [reason].concat(verdict.reasons || []), reasonCodes: [reason.code].concat(verdict.reasonCodes || []),
          flags: ['feed-block'].concat(verdict.flags || [])
        });
      } else if (feedHit && feedHit.hit === 'warn' && verdict.level !== 'dangerous') {
        const reason = { code: 'feedWarn', kind: 'link', params: [String(Math.max(1, (feedHit.sources || []).length))] };
        verdict = Object.assign({}, verdict, {
          level: 'suspicious', score: Math.max(verdict.score, 0.6),
          reasons: [reason].concat(verdict.reasons || []), reasonCodes: [reason.code].concat(verdict.reasonCodes || []),
          flags: ['feed-warn'].concat(verdict.flags || [])
        });
      }
    } catch (_) {                                 }
    try {
      const riskHit = await withTimeout(send('checkRisk', { host }), 3000);
      if (riskHit && riskHit.hit) verdict = SS.foldRiskEvidence(verdict, 0.30, { code: 'riskDynamicHost', kind: 'link' }, 'risk-hosting');
    } catch (_) {                   }
    try {
      const nrdHit = await withTimeout(send('checkNrd', { host }), 3000);
      if (nrdHit && nrdHit.hit) {
        const nrdCode = nrdHit.strengthen ? 'newDomainUnvisited' : 'newDomain';                                                     
                                                                             
                                                                         
                                                                            
                                                                          
                                                                         
                                          
        const nrdCorroborated = !!(urlRules && urlRules.score >= 0.15);
        verdict = SS.foldRiskEvidence(verdict, 0.20, { code: nrdCode, kind: 'link' }, 'new-domain', nrdCorroborated ? { minLevel: 'suspicious' } : undefined);
      }
    } catch (_) {                   }
    return { url, host, valid: true, kind: 'website', level: verdict.level, score: verdict.score, reasons: verdict.reasons || [], flags: verdict.flags || [] };
  }

                                                                             
                                                                        
                                                                            
                                                                
                                                                        
                                                                         
                                                                        
                                                                  
  function decodeImageToQr(img) {
    try {
      const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
      if (!w || !h) return null;
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return null;
      ctx.drawImage(img, 0, 0, w, h);
      let data;
      try { data = ctx.getImageData(0, 0, w, h); }
      catch (e) { if (SS.isTaintedCanvasError && SS.isTaintedCanvasError(e)) return null; throw e; }
      if (typeof SS.jsQR !== 'function') return null;
      const code = SS.jsQR(data.data, w, h);
      return code && code.data ? code.data : null;
    } catch (_) { return null; }                                  
  }

                                                                          
                                                                          
                                                                    
                                                                             
                                                                        
                                                                         
                                                                          
                                    
  function collectQrCandidates(minSize, cap, markProp) {
    const out = [];
    const imgs = document.images || document.querySelectorAll('img');
    for (const img of imgs) {
      if (!SS.withinScanBudget(out.length, cap)) break;
      if (markProp && img[markProp]) continue;
                                                                               
                                                                           
                                                                          
                                                                            
      if (!img.complete) continue;
      const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
      if (!SS.shouldScanImage(w, h, minSize)) continue;
      out.push(img);
    }
    return out;
  }

                                                                           
                                                                            
                                                          
  async function scanPageForQr(minSize, cap, settings, markProp) {
    const candidates = collectQrCandidates(minSize, cap, markProp);
    const results = [];
    const seenPayloads = new Set();
    for (const img of candidates) {
      if (markProp) img[markProp] = true;
      const payload = decodeImageToQr(img);
      if (!payload) continue;
      const key = String(payload).trim();
      if (!key || seenPayloads.has(key)) continue;
      seenPayloads.add(key);
      const classified = SS.classifyQrPayload ? SS.classifyQrPayload(key) : { valid: true, kind: 'website', url: SS.extractQrUrl(key), level: 'unknown', label: 'Decoded QR payload', reasons: [] };
      if (classified.kind === 'website' && classified.url) {
        try {
          const scored = await scoreDecodedUrl(classified.url, settings);
          if (scored) results.push(scored);
        } catch (_) { results.push({ valid: true, kind: 'malformed-url', level: 'suspicious', label: 'Website destination could not be checked', url: classified.url, reasons: classified.reasons || [] }); }
      } else {
        results.push({ valid: !!classified.valid, kind: classified.kind, level: classified.level || 'unknown',
          label: classified.label || 'Decoded QR payload', url: classified.url || '', host: classified.host || '',
          score: classified.level === 'dangerous' ? 1 : classified.level === 'suspicious' ? 0.6 : 0,
          reasons: classified.reasons || [], flags: [] });
      }
    }
    const websiteCount = results.filter((item) => item.kind === 'website').length;
    return { found: results.length, decoded: results.length, scanned: candidates.length, websiteCount, nonWebsiteCount: results.length - websiteCount, results };
  }

                                                                             
                                                                         
                                                                         
                                                                            
                                                                        
                                                                              
                                                                             
                                                                     
                                                             
  function surfaceQrVerdict(item) {
    if (!item || item.level === 'safe' || !SS.actions || !SS.actions.showBanner) return;
    const verdict = {
      level: item.level, score: item.score,
      reasons: [{ code: 'qrCodeDestination', kind: 'link', params: [item.url] }].concat(item.reasons || [])
    };
    SS.actions.showBanner(verdict, {
      onLeave: () => { SS.actions.clearAll(); },
      onReport: () => send('userReport', { label: 'false_positive' }),
      noTrust: true
    });
  }

                                                                                  
                                                                    
                                                                                    
                                                                           
                                                         
  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg) return undefined;
    if (msg.type === 'aiAssessmentReady') {
      const pending = pendingAiRequest;
      if (!pending || msg.requestId !== pending.id || msg.url !== location.href || pending.url !== location.href) return false;
      completedAiResponse = { fingerprint:pending.fingerprint, response:msg.result, at:Date.now() };
      pendingAiRequest = null;
      run({ automatic:true, source:'ai-result', ...activeSelection }).catch(()=>{});
      sendResponse({ok:true}); return false;
    }
    if (msg.type === 'reanalyzePage') {
      if (msg.source === 'ai-ready') { completedAiResponse = null; lastAiAssessment = null; pendingAiRequest = null; cachedAiStatus = null; }
      ensureLiveMonitor();
      if (!IS_TOP) {
        run({ force: true, manual: true }).catch(() => {});
        return false;
      }
      (async () => {
        const selectedText = typeof msg.selectedText === 'string' ? msg.selectedText.slice(0, 8000) : '';
        const selectedUrl = typeof msg.selectedUrl === 'string' ? msg.selectedUrl.slice(0, 2048) : '';
        activeSelection = {selectedText,selectedUrl};
        const verdict = await run({ force: true, manual: true, source:msg.source, selectedText, selectedUrl });
        const inventory = capturePageInventory();
        await send('reportPageInventory', { inventory });
        // Child frames scan independently; collect their most recent bounded inventories.
        await new Promise((resolve) => setTimeout(resolve, 350));
        const frameSnapshot = await send('getPageInventories');
        const frames = frameSnapshot && Array.isArray(frameSnapshot.frames) ? frameSnapshot.frames : [];
        const elementTotal = frames.length ? frames.reduce((sum, frame) => sum + Number(frame.inventory && frame.inventory.elementCount || 0), 0) : inventory.elementCount;
        const interactiveTotal = frames.length ? frames.reduce((sum, frame) => sum + Number(frame.inventory && frame.inventory.interactiveCount || 0), 0) : inventory.interactiveCount;
        const pageLevel = (verdict || window.__ssLastVerdict || {}).level || 'unknown';
        const pageDescription = SS.describePageAssessment(verdict || window.__ssLastVerdict);
        if (selectedText || selectedUrl) {
          const evidence = window.__phishGuardLastEvidence || {};
          const ai = evidence.ai || {};
          const aiSummary = ai.summary || (evidence.aiAvailable ? 'The model did not return a detailed explanation.' : 'The on-device model could not provide a generative assessment.');
          const selection = ai.selection || null;
          const selectionSummary = selection && selection.verdict !== 'not_requested' ? selection.summary :
            (selectedUrl ? 'The selected link was included in the page reassessment.' : 'Selected text was treated as context, not as proof of a threat.');
          const title = selectedUrl && selectedText ? 'Page, selected text, and link rechecked with PhishGuard AI' :
            selectedUrl ? 'Link rechecked with PhishGuard AI' : 'Selected content rechecked with PhishGuard AI';
          if (SS.actions && SS.actions.showContextAnalysis) {
            SS.actions.showContextAnalysis({ level: pageLevel === 'dangerous' ? 'dangerous' : pageLevel === 'suspicious' ? 'suspicious' : pageLevel === 'safe' ? 'safe' : 'info',
              title, body: `PAGE: ${pageDescription} ${aiSummary} SELECTION: ${selectionSummary} Rechecked ${elementTotal.toLocaleString()} DOM elements across ${Math.max(1, frames.length)} permitted frames. The highlighted content was assessed in a separate verdict and treated as context, not as proof of a threat. ${selectedUrl ? 'The selected destination was included in a one-off remote link scan when that optional service is configured; page-wide remote scanning remains optional.' : ''}` });
          }
          sendResponse({ ok: true, url: location.href, verdict: verdict || window.__ssLastVerdict || null,
            ai: ai || null, selectedUrl: selectedUrl || '', inventory, frames });
          return;
        }
        if (SS.actions && SS.actions.showScanNotice) {
          SS.actions.showScanNotice({ title: 'Page rechecked', body: `${pageDescription} Rechecked ${elementTotal.toLocaleString()} DOM elements across ${Math.max(1, frames.length)} permitted frames, including ${interactiveTotal.toLocaleString()} interactive controls. Form, link, script, download, and interaction metadata were refreshed locally.` });
        }
        sendResponse({ ok: true, url: location.href, verdict: verdict || window.__ssLastVerdict || null, inventory, frames });
      })().catch((error) => sendResponse({ ok: false, error: String(error && error.message || error).slice(0, 200) }));
      return true;
    }
    if (!IS_TOP) return undefined;
    if (msg.type === 'getPageAnalysis') {
      (async () => {
        const monitor = capturePageInventory();
        const stored = await send('getPageInventories');
        monitor.frames = stored && Array.isArray(stored.frames) ? stored.frames : [];
        monitor.frameCountObserved = monitor.frames.length;
        monitor.totalFrameElements = monitor.frames.length ? monitor.frames.reduce((sum, item) => sum + Number(item.inventory && item.inventory.elementCount || 0), 0) : monitor.elementCount;
        monitor.totalFrameInteractive = monitor.frames.length ? monitor.frames.reduce((sum, item) => sum + Number(item.inventory && item.inventory.interactiveCount || 0), 0) : monitor.interactiveCount;
        sendResponse({ url: location.href, title: document.title || '', verdict: window.__ssLastVerdict || null,
          evidence: window.__phishGuardLastEvidence || null, monitor });
      })().catch(() => sendResponse({ url: location.href, title: document.title || '', verdict: window.__ssLastVerdict || null,
        evidence: window.__phishGuardLastEvidence || null, monitor: capturePageInventory() }));
      return true;
    }
    if (msg.type !== 'scanQrCodes') return undefined;
    (async () => {
      const settings = await send('getSettings');
      if (!settings || !settings.enabled || isUserExemptHost(location.hostname, settings)) { sendResponse({ found: 0, results: [] }); return; }
      let result;
      try { result = await scanPageForQr(QR_POPUP_MIN_SIZE, QR_POPUP_CAP, settings); }
      catch (_) { result = { found: 0, results: [] }; }
      for (const item of result.results) surfaceQrVerdict(item);
      sendResponse(result);
    })();
    return true;                      
  });

                                                                             
                                                                           
                                                                           
                                                                            
                                                                    
  let qrAutoScanRunning = false, qrAutoScanObserverStarted = false, qrAutoScanTimer = null;
  function scheduleIdle(fn) {
    try { if (typeof root.requestIdleCallback === 'function') { root.requestIdleCallback(fn, { timeout: 3000 }); return; } } catch (_) {}
    setTimeout(fn, 200);
  }
  async function autoScanQr(settings) {
    if (qrAutoScanRunning || qrAutoScanBudget <= 0) return;
    qrAutoScanRunning = true;
    try {
      const cap = Math.min(QR_AUTOSCAN_CAP, qrAutoScanBudget);
      const result = await scanPageForQr(QR_AUTOSCAN_MIN_SIZE, cap, settings, '__ssQrAutoScanned');
      qrAutoScanBudget -= cap;
      for (const item of result.results) {
        if (item.level === 'dangerous' || item.level === 'suspicious') {
          surfaceQrVerdict(item);
          send('bumpThreats', { kind: 'qr' });
        }
      }
    } catch (_) {                                                        }
    finally { qrAutoScanRunning = false; }
  }
  function ensureQrAutoScanObserver(settings) {
    if (qrAutoScanObserverStarted || !('MutationObserver' in root)) return;
    qrAutoScanObserverStarted = true;
    try {
      const mo = new MutationObserver(() => {
        clearTimeout(qrAutoScanTimer);
        qrAutoScanTimer = setTimeout(() => scheduleIdle(() => autoScanQr(settings)), 1500);
      });
      mo.observe(document.body, { childList: true, subtree: true });
    } catch (_) {}
  }

                                                                                
                                                                       
  const formGuardReasons = [];

  async function performRun(options) {
    options = options || {};
    lastLiveScanAt = Date.now();
    const force = options.force === true;
    if (!SS || typeof SS.scoreUrl !== 'function') return null;
    if (!document.documentElement) return null;
    const scanUrl = location.href;
    const settings = await send('getSettings');
    if (!settings || !settings.enabled) return { level: 'unknown', score: 0, reasons: [], flags: ['protection-disabled'] };
    const pageDomain = scopeOf(location.hostname);                                                  
                                                                         
    if (IS_TOP && settings.serpCheck !== false && SEARCH_HOSTS.test(location.hostname)) {
      try { checkSerp(); } catch (_) {}
      try { annotateSerpResults(); ensureSerpBadgeObserver(); } catch (_) {}
    }
                                                                                    
    if (!force && isUserExemptHost(location.hostname, settings)) {
      if (IS_TOP) await send('reportVerdict', { verdict: { level: 'safe', score: 0, reasons: [], modelUsed: false, flags: ['user-exempt'] } });
      return { level: 'safe', score: 0, reasons: [], flags: ['user-exempt'] };
    }
                                                                            
                                                                            
                                                                         
                                                          
    if (IS_TOP && settings.qrAutoScan !== false && typeof SS.jsQR === 'function') {
      scheduleIdle(() => autoScanQr(settings));
      try { ensureQrAutoScanObserver(settings); } catch (_) {}
    }

    const { signals, foreignForms, exfilForms } = collectSignals(settings);
    const inventory = capturePageInventory();
    send('reportPageInventory', { inventory });
    signals.inventory = { elementCount: inventory.elementCount, interactiveCount: inventory.interactiveCount,
      scriptCount: inventory.scriptCount, iframeCount: inventory.iframeCount, externalResourceHosts: inventory.resourceHosts.length };
                                                                               
                                                                               
                                                                           
    const pageAnalysisEnabled = force || settings.pageAnalysis !== false;
    let iconMatch = false;
    let pageText = '';
    let urlRules = SS.scoreUrl(location.href, settings.riskTlds);
    let domRules = SS.scoreDom(signals);
    let downloadRules = null;
    if (pageAnalysisEnabled) {
      try {
        pageText = pageTextSnapshot(DEVICE_PROFILE.maxVisibleTextChars || 5600);
        // Download inspection receives actual DOM download targets only. Page
        // prose and quoted filenames are not converted into a risk score.
        const actualDownloadTargets = (signals.downloadCandidates || []).filter((item) => item && item.href && /^https?:/i.test(item.href));
        if (typeof SS.scoreDownloadSurface === 'function') {
          downloadRules = SS.scoreDownloadSurface({ host: location.hostname, pageText: '', candidates: actualDownloadTargets });
        }
      } catch (error) {
        console.warn('[PhishGuard] structural page inspection failed:', error);
      }
    }


                                                                               
                                                                               
                                                                             
                                                                             
                                                                            
                                                                            
                                                                        
                                                                               
                                                                  
    try {
      const prov = SS.fuse({ modelProb: null, urlRules, domRules, contentProb: null, iconMatch: false });
      formGuardReasons.splice(0, formGuardReasons.length, ...(prov.reasons || []));
    } catch (_) { formGuardReasons.length = 0; }
    if (foreignForms.length) SS.actions.guardForms(foreignForms, formGuardReasons, () => send('userReport', { label: 'false_positive' }));
                                                                              
                                                                             
                             
    if (settings.leakyFormGuard !== false && exfilForms.length) guardExfilForms(exfilForms, settings);
                                                                             
                                                                              
                                                                               
                                                                             
                                                                         
                                                                           
                                                                           
                                                                         
                                                                             
                                                                      
                                                                            
                                                         
    const wantIcons = pageAnalysisEnabled && needsPageAnalysis(signals, urlRules, domRules);
    const iconsP = wantIcons ? send('hashIcons', { urls: iconCandidates() }).catch(() => null) : null;
    const feedP = send('checkFeed', { host: location.hostname }).catch(() => null);
    const riskP = send('checkRisk', { host: location.hostname }).catch(() => null);
    const nrdP = send('checkNrd', { host: location.hostname }).catch(() => null);
    // Legacy URL/page classifiers are deliberately not verdict authorities.
    if (wantIcons) {
      try {
        const icons = await withTimeout(iconsP, 1200);
        if (icons && icons.matches && icons.matches.length) {
          signals.iconMatches = icons.matches; domRules = SS.scoreDom(signals);
          iconMatch = (domRules.flags || []).includes('brand-impersonation-visual');
        }
      } catch (_) {                                    }
    }
    // Icon matches enrich the AI snapshot; passive text scores never enter the verdict.
                                                                        
                                                                           
                                                                             
                                                                         
                                                                 
                                                                     
                                                                        
                                                                           
                                           
                                                                              
                                                                          
                                                                          
                                                                          
                                                                      
                                                                             
                                                                     
                         
    if (IS_TOP) {
      const navEntry = performance.getEntriesByType('navigation')[0];
      if (navEntry && navEntry.redirectCount > 0) {
        const ln = await withTimeout(send('getLastNavigation'), 500);
        const g = SS.gatewaySignal({ redirectCount: navEntry.redirectCount, originalUrl: ln && ln.url, landingHost: location.hostname });
        if (g.score) {
          urlRules = Object.assign({}, urlRules, { score: Math.min(1, urlRules.score + g.score), reasons: urlRules.reasons.concat(g.reasons) });
        }
      }
    }
    let verdict = SS.fuse({ modelProb: null, urlRules, domRules, contentProb: null, iconMatch });

                                                                           
                                                                   
                                                                            
                                                                          
                                                                              
                                                                              
                                                                          
                                                                              
                                                                             
                                                                               
    let feedHit = null, riskHit = null, nrdHit = null;
    try { feedHit = await withTimeout(feedP, 1200); } catch (_) {}
    try { riskHit = await withTimeout(riskP, 250); } catch (_) {}
    try { nrdHit = await withTimeout(nrdP, 250); } catch (_) {}
    // Warning-tier domain age/reputation and keyword rules are context only.
    // A verified block-list hit and structurally verified foreign credential
    // exfiltration remain independent hard signals below.

    if (IS_TOP && settings.shopGuard !== false && SS.scoreShop) {
      try {
        const shop = await collectShop(pageText, location.hostname);
        const sr = SS.scoreShop(shop);
        if (sr.flags.length) {
          send('shopFindings', { flags: sr.flags, level: sr.level });
          // Store commerce observations as context only; they do not independently raise a threat.
        }
      } catch (_) {                                 }
    }
                                                                             
                                                                               
                                                                        
                                                   
    let aiSnapshot = null, aiResponse = null;
    if (pageAnalysisEnabled) {
      try {
        aiSnapshot = buildAiSnapshot(pageText, inventory, signals, {
          feed: feedHit && feedHit.hit || 'none', riskHosting: !!(riskHit && riskHit.hit),
          newDomain: !!(nrdHit && nrdHit.hit), iconBrandMatches: (signals.iconMatches || []).slice(0, 8),
          executableDownloadCandidates: (downloadRules && downloadRules.signals && downloadRules.signals.executableCount) || 0
        }, options);
        aiSnapshot.remoteLinkChecks = settings.remoteLinkChecks === true;
        await attachLocalMlScores(aiSnapshot, inventory, pageText, options.manual === true || options.source === 'ai-ready');
        const fingerprint = aiSnapshotFingerprint(aiSnapshot);
        const completed = completedAiResponse && completedAiResponse.fingerprint === fingerprint && Date.now()-completedAiResponse.at < 120000;
        const cached = lastAiAssessment && fingerprint === lastAiSnapshotFingerprint && Date.now()-lastAiSnapshotAt < 120000;
        if (completed) {
          aiResponse = completedAiResponse.response;
          if (aiResponse && aiResponse.available && aiResponse.assessment) {
            lastAiAssessment = aiResponse.assessment; lastAiSnapshotFingerprint = fingerprint;
            lastAiSnapshotAt = completedAiResponse.at; lastAiSnapshot = aiResponse.snapshot || aiSnapshot;
          }
        } else if (cached) {
          aiResponse = {available:true,assessment:lastAiAssessment,snapshot:lastAiSnapshot,reused:true};
        } else if (pendingAiRequest && pendingAiRequest.fingerprint === fingerprint && Date.now()-pendingAiRequest.at < 90000) {
          aiResponse = pendingAiRequest.initial;
        } else {
          const request = {id:String(Date.now())+':'+(++aiRequestSequence),fingerprint,url:location.href,at:Date.now(),initial:null};
          pendingAiRequest = request;
          aiResponse = await withTimeout(send('aiAnalyzePage', { snapshot:aiSnapshot, requestId:request.id }), 2500);
          request.initial = aiResponse;
          if (aiResponse && !aiResponse.pending && aiResponse.assessment) {
            if (!aiResponse.deferred) completedAiResponse = {fingerprint,response:aiResponse,at:Date.now()};
            pendingAiRequest = null;
          }
        }
      } catch (error) {
        aiResponse = { available: false, error: String(error && error.message || error) };
      }
    }
    const hardSignals = {
      confirmedFeedBlock: !!(feedHit && feedHit.hit === 'block')
    };
    if (typeof SS.resolveAiVerdict === 'function') {
      verdict = SS.resolveAiVerdict(aiResponse && aiResponse.available ? aiResponse.assessment : null,
        (aiResponse && aiResponse.snapshot) || aiSnapshot || {}, hardSignals);
      verdict.analysisPending = !!(aiResponse && aiResponse.pending);
      if (verdict.analysisPending) verdict.summary = 'Local checks are complete. Deeper analysis is running in the background.';
      if (aiResponse && aiResponse.error) verdict.aiError = String(aiResponse.error).slice(0, 240);
      if (aiResponse && aiResponse.remoteScanCount) verdict.remoteScanCount = aiResponse.remoteScanCount;
    } else {
      verdict = { level: hardSignals.confirmedFeedBlock || hardSignals.foreignCredentialForm ? 'dangerous' : 'unknown',
        score: 0, reasons: [], reasonCodes: [], aiAvailable: false };
    }
    if (location.href !== scanUrl) return null;
    try {
      window.__ssLastVerdict = verdict;
      window.__phishGuardLastEvidence = {
        url: location.href, title: document.title || '', checkedAt: Date.now(),
        downloads: downloadRules || null, ai: aiResponse && aiResponse.assessment || null,
        aiAvailable: !!(aiResponse && aiResponse.available), aiError: aiResponse && aiResponse.error || '',
        remoteLinkScans: aiResponse && aiResponse.snapshot && aiResponse.snapshot.remoteLinkScans || [],
        pageContext: signals.pageContext || null,
        urlEvidence: urlRules && urlRules.reasons || [], domEvidence: domRules && domRules.reasons || [],
        signals: { hasPasswordField: !!signals.hasPasswordField, hasCardInput: !!signals.hasCardInput,
          forms: signals.formCount || 0, links: signals.linkCount || 0, downloads: signals.downloadCount || 0,
          elements: inventory.elementCount, interactive: inventory.interactiveCount },
        monitor: inventory
      };
    } catch (_) {}
    let report = null;
    try {
      report = {
        url: location.href, urlFeatures: Array.from(SS.extractUrlFeatures(location.href)),
        iconMatches: signals.iconMatches || [], detectors: ['page']
      };
    } catch (_) { report = null; }
    await send('reportVerdict', { verdict, report, subframe: !IS_TOP, manualRescan: options.manual === true || options.source === 'ai-result', selection: aiResponse && aiResponse.assessment && aiResponse.assessment.selection });
    if (IS_TOP) {
      const verdictKey = [location.href, verdict.analysisPending, verdict.level, (verdict.reasonCodes || []).join(','), verdict.aiEngine || ''].join('|');
      if (verdictKey !== lastPresentedVerdictKey) {
        lastPresentedVerdictKey = verdictKey;
        if (verdict.level === 'safe' || verdict.level === 'informational') {
          if ((lastRenderedRiskLevel === 'dangerous' || lastRenderedRiskLevel === 'suspicious') && SS.actions && SS.actions.clearAll) {
            try { SS.actions.clearAll(); } catch (_) {}
          }
          const fallback = verdict.aiEngine === 'local-ml';
          if (SS.actions && SS.actions.showVerdictStatus) SS.actions.showVerdictStatus({
            level: verdict.level, title: verdict.analysisPending ? 'Local checks complete' : verdict.level === 'safe' ? 'PhishGuard checked this page' : 'Page checks complete',
            body: verdict.analysisPending ? verdict.summary : fallback
              ? 'The lightweight on-device models found no corroborated threat. Generative reasoning is not active on this device.'
              : (verdict.summary || 'No meaningful malicious behavior was established from the inspected evidence.')
          });
        } else if (verdict.level === 'unknown' && !verdict.analysisPending && SS.actions && SS.actions.showVerdictStatus) {
          SS.actions.showVerdictStatus({ level: 'unknown', title: 'PhishGuard assessment is limited',
            body: verdict.summary || 'Some page evidence could not be assessed. No keyword-only warning was raised.' });
        }
      }
      lastRenderedRiskLevel = verdict.level;
    }

    if ((verdict.level === 'suspicious' || verdict.level === 'dangerous') && IS_TOP) {
                                                                           
      if (verdict.brand && SS.BRAND_DOMAINS && SS.BRAND_DOMAINS[verdict.brand]) {
        verdict.brandUrl = 'https://' + SS.BRAND_DOMAINS[verdict.brand][0] + '/';
        verdict.brandLabel = SS.brandDisplayName ? SS.brandDisplayName(verdict.brand) : verdict.brand;
      }
                                                                          
                                                                    
                                                                             
                                                                            
      const DECISIVE_INTERSTITIAL = ['seed-phrase-harvest', 'clickfix', 'fake-browser-update', 'delivery-fee-scam', 'feed-block'];
      const handlers = { onLeave: () => send('leaveTab'), onReport: () => send('userReport', { label: 'false_positive' }), onHide: (choice) => send('pauseSite', { domain: pageDomain, choice }) };
                                                                             
                                                                 
      const decisive = verdict.level === 'dangerous' && (verdict.flags || []).some((f) => DECISIVE_INTERSTITIAL.includes(f));
      if ((decisive || settings.strictMode === true) && SS.actions.dangerInterstitial) {
        SS.actions.dangerInterstitial(verdict, handlers);
      } else {
        SS.actions.showBanner(verdict, handlers);
      }
                                                                            
      if (verdict.level === 'dangerous' && !settings.supportAskShown && SS.actions.supportToast) {
        send('setSettings', { patch: { supportAskShown: true } });
        setTimeout(() => SS.actions.supportToast(), 1500);
      }
    }
                                                                      
                                                                            
                                                                          
                                                                             
                                              
    formGuardReasons.splice(0, formGuardReasons.length, ...(verdict.reasons || []));
    return verdict;
  }


  function mergeManualScanOptions(current, incoming) {
    const merged = Object.assign({}, current || {}, incoming || {}, { manual: true, force: true });
    const snippets = [];
    for (const value of [current && current.selectedText, incoming && incoming.selectedText]) {
      const text = String(value || '').trim();
      if (text && !snippets.includes(text)) snippets.push(text);
    }
    merged.selectedText = snippets.join('\n\n[Additional selected content]\n\n').slice(0, 8000);
    merged.selectedUrl = String((incoming && incoming.selectedUrl) || (current && current.selectedUrl) || '').slice(0, 2048);
    return merged;
  }

  async function run(options) {
    options = options || {};
    if (activeScanPromise) {
      if (options.manual || options.force) {
        pendingManualOptions = mergeManualScanOptions(pendingManualOptions, options);
        return new Promise((resolve, reject) => pendingManualWaiters.push({ resolve, reject }));
      }
      pendingAutomaticScan = true;
      if (options.source === 'ai-result') pendingAutomaticOptions = options;
      return activeScanPromise;
    }
    activeScanPromise = performRun(options);
    try { return await activeScanPromise; }
    finally {
      activeScanPromise = null;
      if (pendingManualOptions) {
        const queuedOptions = pendingManualOptions;
        const waiters = pendingManualWaiters.splice(0);
        pendingManualOptions = null;
        Promise.resolve().then(() => run(queuedOptions)).then((result) => {
          for (const waiter of waiters) waiter.resolve(result);
        }, (error) => {
          for (const waiter of waiters) waiter.reject(error);
        });
      } else if (pendingAutomaticScan) {
        pendingAutomaticScan = false;
        const queued = pendingAutomaticOptions || {automatic:true};
        pendingAutomaticOptions = null;
        setTimeout(() => run(queued).catch(()=>{}),0);
      }
    }
  }

  let lastUrl = location.href;
  let navTimer = null;
  window.addEventListener('phishguard:navigate', () => {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    pendingAiRequest = null; completedAiResponse = null; lastAiAssessment = null; lastAiSnapshot = null;
    activeSelection = {selectedText:'',selectedUrl:''};
    clearTimeout(navTimer);
                                                                         
                                                                             
                                                                             
                                                                         
    serpBadgeBudget = SERP_BADGE_CAP;
    clipboardSeen.clear();
    navTimer = setTimeout(() => { if (SS && SS.actions) SS.actions.clearAll(); run({ automatic: true, force: true }); }, 250);
  });

  ensureLiveMonitor();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => run());
  else run();
})(typeof globalThis !== 'undefined' ? globalThis : self);
