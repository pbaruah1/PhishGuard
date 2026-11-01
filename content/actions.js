(function (root) {
  'use strict';
  const NS = 'phishguard';
  const api = root.browser || root.chrome;
                                                                 
                                                                             
                                                                            
                                                                          
                                                              
  const send = (type, data) => new Promise((resolve) => {
    try { api.runtime.sendMessage(Object.assign({ type }, data || {}), (r) => resolve(r || null)); }
    catch (_) { resolve(null); }
  });
                                                                     
                                                                            
                                                                            
  function t(key, subs, fallback) {
    try { const R = root.SSReasons; if (R && R.tOverride) { const o = R.tOverride(key, subs); if (o) return o; } } catch (_) {}
    try { const m = api && api.i18n && api.i18n.getMessage(key, subs); if (m) return m; } catch (_) {}
    return fallback != null ? fallback : key;
  }
                                                                              
                                                                               
                                                                            
                                                                               
                                                                              
                                                                           
                                                                                
                                                        
    
                                                                               
                                                                               
                                                                              
                                                                       
                                                                    
    
                                                                         
                                                                              
                                                               
                                                                            
                                                      
  if (!root.__phishguardLangAsked) {
    root.__phishguardLangAsked = true;
    try {
      api.storage.local.get('settings').then((cur) => {
        const lang = cur && cur.settings && cur.settings.uiLang;
        if (!lang || lang === 'auto') return;                                           
        return api.runtime.sendMessage({ type: 'getLangDict' }).then((r) => {
          if (r && r.lang && r.dict && root.SSReasons) root.SSReasons.setOverride(r.lang, r.dict);
        });
      }).catch(() => {                                                                  });
    } catch (_) {                                   }
  }
                                                                                
                                                                              
                                                                           
  function reasonText(r) {
    const R = root.SSReasons;
    if (r == null) return '';
    return R ? R.resolveReason(r) : (typeof r === 'string' ? r : '');
  }
                                                                          
                                                                          
                                                                   
  function bidi(s) {
    const R = root.SSReasons;
    return R && R.bidiWrap ? R.bidiWrap(s) : (s == null ? '' : String(s));
  }
                                                                           
                                                                              
  function setDir(node) {
    try { node.setAttribute('dir', root.SSReasons && root.SSReasons.isRTL() ? 'rtl' : 'ltr'); } catch (_) {}
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
                                                                        
                                                                         
                                                                            
                                                                         
                                                                         
                                                    
                                                                         
                                                                             
                                                                          
                                                                         
                                                                         
                                                                           
  function onTrustedClick(node, fn) {
    node.addEventListener('click', (e) => { if (!e.isTrusted) return; fn(e); });
  }

                                                                               
                                                                              
                                                                              
                                                                             
                
  const TILE = { danger: '<path d="M12 2l8 3v6c0 5.2-3.4 9.6-8 11-4.6-1.4-8-5.8-8-11V5l8-3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>', warn: '<path d="M12 2l8 3v6c0 5.2-3.4 9.6-8 11-4.6-1.4-8-5.8-8-11V5l8-3z"/><path d="M12 8v5"/><path d="M12 16h.01"/>', info: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 10l3 2-3 2M13 14h3"/>', ok: '<path d="M20 6L9 17l-5-5"/>' };
  function tile(kind) { const s = el('span', 'ss-tile ' + (TILE[kind] ? kind : 'info')); s.setAttribute('aria-hidden', 'true'); s.innerHTML = '<svg viewBox="0 0 24 24">' + (TILE[kind] || TILE.info) + '</svg>'; return s; }
  function button(cls, label, opts) { const b = el('button', 'ss-btn ' + cls + (opts && opts.primary ? ' primary' : '') + (opts && opts.quiet ? ' quiet' : ''), label); b.type = 'button'; return b; }
                                                                                        
  function timer(node, ms, onDone) {
    let left = ms, started = Date.now(), handle = null, done = false;
    const bar = node.querySelector('.ss-prog i');
    const paint = () => { if (bar) { bar.style.transition = 'none'; bar.style.transform = 'scaleX(' + (left / ms) + ')'; requestAnimationFrame(() => { bar.style.transition = 'transform ' + left + 'ms linear'; bar.style.transform = 'scaleX(0)'; }); } };
                                                                                
                                                                              
                                                                              
                                                                      
    const start = () => { if (done || handle != null) return; started = Date.now(); handle = setTimeout(() => { done = true; onDone(); }, left); paint(); };
    const pause = () => { if (done || handle == null) return; clearTimeout(handle); handle = null; left = Math.max(0, left - (Date.now() - started)); if (bar) { bar.style.transition = 'none'; bar.style.transform = 'scaleX(' + (left / ms) + ')'; } };
    node.addEventListener('mouseenter', pause); node.addEventListener('focusin', pause);
                                                                         
                                                                          
                                                                      
                                          
    node.addEventListener('mouseleave', () => { if (!node.contains(document.activeElement)) start(); });
    node.addEventListener('focusout', () => { if (!node.contains(document.activeElement)) start(); });
    start();
    return { cancel: () => { done = true; clearTimeout(handle); } };
  }
                                                                           
                                                                            
                                                                             
                                                                               
                                                                   
  function toast(opts) {
    const o = opts || {};
                                                                            
                                                                           
                                                                              
                                                                            
                                                                        
    document.querySelectorAll('.' + NS + '-toast:not(.' + NS + '-ack)').forEach((n) => n.remove());                             
    const box = el('div', NS + '-toast ' + (o.kind || 'info'));
    box.setAttribute('role', o.role || 'status'); setDir(box);
    box.append(tile(o.kind === 'notice' ? 'info' : (o.kind || 'info')), el('div', 'ss-title', o.title || ''));
    if (o.body) box.append(el('div', 'ss-body', o.body));
    const acts = el('div', 'ss-acts');
    for (const a of (o.actions || [])) { const b = button(a.cls || '', a.label, { primary: !!a.primary }); onTrustedClick(b, () => { a.onClick && a.onClick(); if (a.closes !== false) close(); }); acts.appendChild(b); }
    if (o.muteKind && o.onMute && canStore()) { const m = button('ss-mute', t('dontWarnHere', null, "Don't warn me on this site"), { quiet: true }); onTrustedClick(m, () => { close(); o.onMute(); }); acts.appendChild(m); }
    const x = button('ss-x', '✕'); x.setAttribute('aria-label', t('ariaDismiss', null, 'Dismiss')); onTrustedClick(x, close); acts.appendChild(x);
    box.appendChild(acts);
    let tm = null;
    if (!o.persist) { const p = el('div', 'ss-prog'); p.setAttribute('aria-hidden', 'true'); p.appendChild(el('i')); box.appendChild(p); }
                                                                           
                                                                         
                                                                             
                      
    function close() { if (tm) tm.cancel(); box.remove(); o.onClose && o.onClose(); }
    (document.body || document.documentElement).appendChild(box);
                                                                               
                                                                             
    if (!o.persist) tm = timer(box, o.timeoutMs || 10000, close);
    return box;
  }

                                                                           
                                                                          
                                                                       
                                                                         
                                                                         
                                                                           
                                                                           
                                   
  function buildReportText(verdict) {
    const R = root.SSReasons;
    const dangerous = verdict.level === 'dangerous';
    const levelLabel = dangerous ? t('popupDangerous', null, 'High-risk activity detected') : t('popupSuspicious', null, 'Review before proceeding');
    const hostText = bidi(R && R.defangHost ? R.defangHost(location.hostname) : location.hostname);
    const headerLine = t('copyReportHeader', [hostText], '⚠ PhishGuard flagged this site: ' + location.hostname);
    const verdictLine = t('copyReportVerdict', [levelLabel], 'Verdict: ' + levelLabel);
    const signalsLabel = t('copyReportSignals', null, 'Signals:');
    const footerLine = t('copyReportFooter', null, 'Checked locally by PhishGuard. Review the evidence before acting.');
    const reasons = (verdict.reasons || []).slice(0, 4).map(reasonText).filter(Boolean);
    return (R && R.buildCopyReportText)
      ? R.buildCopyReportText({ headerLine, verdictLine, signalsLabel, reasons, footerLine })
      : [headerLine, verdictLine, signalsLabel].concat(reasons.map((r) => '- ' + r), [footerLine]).join('\n');
  }
  function copiedToast() {
    return toast({ kind: 'ok', title: t('toastCopied', null, 'Copied'), timeoutMs: 2500 });
  }
  function copyReportButton(verdict) {
                                                                             
                                                                               
                                                         
    const btn = button('ss-copy', t('copyReportBtn', null, 'Copy report'));
                                                                           
                                                                             
                                 
    onTrustedClick(btn, () => {
      const text = buildReportText(verdict);
                                                                                    
                                                                          
                                                            
      try { window.__ssLastCopyReport = text; } catch (_) {}
      const R = root.SSReasons;
      const copy = R && R.copyToClipboard ? R.copyToClipboard(text) : Promise.resolve(false);
      copy.then((ok) => { if (ok) copiedToast(); });
    });
    return btn;
  }

  function clearAll() {
                                                                     
                                                                              
                                                                            
                                                                            
                                                                        
                                    
    document.querySelectorAll('.' + NS + '-banner').forEach((n) => { if (n.__ssTeardown) n.__ssTeardown(); n.remove(); });
                                                                              
                                                                              
    document.querySelectorAll('.' + NS + '-overlay:not(.' + NS + '-wallet)').forEach((n) => n.remove());
    document.querySelectorAll('.' + NS + '-hidden-block').forEach((n) => {
      n.classList.remove(NS + '-hidden-block');
      const t = n.querySelector('.' + NS + '-hidden-tag'); if (t) t.remove();
    });
  }

                                                                              
                                                                            
                                         
  function armDelayed(btn, seconds) {
    const label = btn.textContent;
    let left = seconds == null ? 3 : seconds;
    btn.disabled = true;
    const countdown = () => t('guardCountdown', [label, bidi(left)], label + ' (' + left + ')');
    btn.textContent = countdown();
    const tick = setInterval(() => {
      left -= 1;
      if (left <= 0) { clearInterval(tick); btn.disabled = false; btn.textContent = label; }
      else btn.textContent = countdown();
    }, 1000);
    return () => clearInterval(tick);
  }

                                                                              
                                                                         
  function compareRow(brandLabel, brandUrl) {
    let realHost = '';
    try { realHost = new URL(brandUrl).hostname.replace(/^www\./, ''); } catch (_) {}
    if (!realHost) return null;
    const row = el('div', 'ss-compare');
    const fake = el('span', 'ss-cmp-fake'); fake.append(el('small', null, t('compareThisSite', null, 'This site')), el('b', null, location.hostname));
    const real = el('span', 'ss-cmp-real'); real.append(el('small', null, t('compareRealSite', [bidi(brandLabel)], 'Real ' + brandLabel)), el('b', null, realHost));
    row.append(fake, el('span', 'ss-cmp-vs', '≠'), real);
    return row;
  }
                                                                              
                                                                         
                                                                         
                                                                     
                                                                         
                                              
                                                                                
                                                                            
                                           
  function canStore() {
    try { const SS = root.PhishGuard; return !(SS && SS.isTenantApex && SS.isTenantApex(regDomain())); } catch (_) { return true; }
  }
  function regDomain() {
    try {
      const SS = root.PhishGuard;
                                                                             
                                                
      if (SS && typeof SS.scopeDomain === 'function') return SS.scopeDomain(location.hostname);
      return (SS && typeof SS.registrableDomain === 'function') ? SS.registrableDomain(location.hostname) : location.hostname;
    } catch (_) { return location.hostname; }
  }
                                                                            
                                                                              
                                                                              
                                                                            
                                                                                 
                                                                               
                                                               
                                                                             
                                                          
  function ackSurface(arg, restoreArg) {
    let text, onUndo, restore;
    if (arg && typeof arg === 'object') {
      text = arg.text; onUndo = arg.onUndo; restore = arg.restore;
    } else {
      const domain = arg;
      text = t('ackTrusted', [bidi(domain)], "PhishGuard won't flag " + domain + ' again.');
      onUndo = () => send('untrustSite', { domain });
      restore = restoreArg;
    }
    const old = document.querySelector('.' + NS + '-ack'); if (old) old.remove();
                                                                             
                                                                          
                                                                              
                                                                 
                                                                              
                                                                            
                                                                   
                                                                  
                                                                                
                                                                               
                                                                           
                                                                            
                                                                         
    const bar = toast({
      kind: 'ok', timeoutMs: 10000, title: text,
      actions: [{ cls: 'ss-undo', label: t('undo', null, 'Undo'), onClick: async () => { await onUndo(); restore && restore(); } }]
    });
    bar.classList.add(NS + '-ack');
    return bar;
  }
                                                                             
                                                                            
                                                              
                                                                         
                                                                    
                                                      
    
                                                                      
                                                                         
                                                                        
                                                                             
                                                                             
                                                                           
  const TRUST_ARM_MS = 300;
  function trustButton(onAllow) {
    const btn = button('ss-trust', t('trustThisSite', null, 'Trust this site'));
    if (onAllow) {
      let armedAt = performance.now();
                                                                              
                                                                               
                                                                             
                                                              
      btn.__ssRearm = () => { armedAt = performance.now(); };
      onTrustedClick(btn, (e) => { if (performance.now() < armedAt + TRUST_ARM_MS) return; onAllow(e); });
    }
    return btn;
  }
  function showBanner(verdict, extra) {
    if (document.querySelector('.' + NS + '-banner')) return;
    const x = extra || {}; const danger = verdict.level === 'dangerous';
    const bar = el('div', NS + '-banner ' + (danger ? 'danger' : 'suspicious'));
    bar.setAttribute('role', danger ? 'alert' : 'status'); setDir(bar);
    const text = el('div', 'ss-text');
    const head = verdict.brandLabel ? (danger ? t('bannerDangerBrand', [bidi(verdict.brandLabel)], 'Dangerous page — looks like ' + verdict.brandLabel + ", but isn't") : t('bannerTakeCare', null, 'Take care on this site')) : (danger ? t('bannerDanger', null, 'High-risk activity detected') : t('bannerTakeCare', null, 'Take care on this site'));
    const reason = el('span', 'ss-reason', reasonText(verdict.reasons[0]) || (danger ? t('popupDangerSummary', null, "Strong risk indicators were found. Avoid entering credentials, payment details, or downloading files here.") : t('popupSuspiciousSummary', null, 'Some signals deserve a closer look. Check the address and evidence before sharing information.')));
    text.append(el('b', null, head), reason);
    const more = (verdict.reasons || []).slice(1, 4);
    if (more.length) { const why = el('button', 'ss-why', t('whyShort', null, 'Why?')); why.type = 'button'; why.setAttribute('aria-expanded', 'false'); onTrustedClick(why, () => { const ul = el('ul', 'ss-why-list'); for (const r of more) ul.appendChild(el('li', null, reasonText(r))); reason.after(ul); why.remove(); }); reason.appendChild(why); }
    bar.append(tile(danger ? 'danger' : 'warn'), text);
    const acts = el('div', 'ss-acts'); const menu = el('div', 'ss-menu'); menu.setAttribute('role', 'menu'); menu.hidden = true;
    const leave = button('ss-leave', t('leaveThisPage', null, 'Leave this page')); onTrustedClick(leave, () => { bar.__ssTeardown && bar.__ssTeardown(); x.onLeave ? x.onLeave() : history.back(); });
    const rescue = verdict.brandUrl ? button('ss-rescue', t('takeMeToReal', [bidi(verdict.brandLabel || 'site')], 'Take me to the real ' + (verdict.brandLabel || 'site')), { primary: true }) : null;
    if (rescue) onTrustedClick(rescue, () => { bar.__ssTeardown && bar.__ssTeardown(); location.href = verdict.brandUrl; });
                                                                           
                                                                         
                                                                        
                                   
                                                                            
                                                                          
                                                                            
                                                                           
    const trust = (x.noTrust || !canStore()) ? null : trustButton(async () => { bar.__ssTeardown && bar.__ssTeardown(); bar.remove(); const domain = regDomain(); await send('trustSite', { domain, via: x.trustVia || 'banner' }); ackSurface({ text: t('ackTrusted', [bidi(domain)], "PhishGuard won't flag " + domain + ' again.'), onUndo: () => send('untrustSite', { domain }), restore: () => showBanner(verdict, extra) }); });
    const report = button('ss-report', t('reportMistake', null, 'Report a mistake')); onTrustedClick(report, () => { report.textContent = t('thanks', null, 'Thanks'); report.disabled = true; x.onReport && x.onReport(); closeMenu(); });
    const copyBtn = copyReportButton(verdict); onTrustedClick(copyBtn, () => closeMenu());
                                                                                                                          
                                                                                                                                
    if (danger) { if (rescue) { acts.append(rescue, leave); } else { leave.classList.add('primary'); acts.appendChild(leave); } if (trust) menu.appendChild(trust); }
    else if (trust) acts.appendChild(trust);
    menu.append(report, copyBtn);
                                                                                                           
    if (verdict.brandLabel && verdict.brandUrl) { const cmp = compareRow(verdict.brandLabel, verdict.brandUrl); if (cmp) text.appendChild(cmp); }
    const moreBtn = button('ss-more', '⋯'); moreBtn.setAttribute('aria-label', t('moreActions', null, 'More actions')); moreBtn.setAttribute('aria-haspopup', 'menu'); moreBtn.setAttribute('aria-expanded', 'false');
    const closeMenu = () => { menu.hidden = true; moreBtn.setAttribute('aria-expanded', 'false'); document.removeEventListener('click', onDoc, true); document.removeEventListener('keydown', onKey, true); };
                                                                           
                                                                             
                                                                              
                                                                             
                                                                           
                                                                            
                                                                              
                             
    bar.__ssTeardown = closeMenu;
                                                                                                                                                        
    const onDoc = (e) => { if (!acts.contains(e.target)) closeMenu(); }; const onKey = (e) => { if (!e.isTrusted) return; if (e.key === 'Escape') closeMenu(); };
                                                                        
                                                                      
                                                                            
                                                              
    onTrustedClick(moreBtn, () => { if (menu.hidden) { menu.hidden = false; moreBtn.setAttribute('aria-expanded', 'true'); trust && trust.__ssRearm && trust.__ssRearm(); document.addEventListener('keydown', onKey, true); setTimeout(() => { document.addEventListener('click', onDoc, true); }, 0); } else closeMenu(); });
                                                                                                       
                                                                                                         
    const choice = danger ? '1h' : '1d';
    const closeLabel = !canStore() ? t('ariaDismiss', null, 'Dismiss') : danger ? t('bannerHideHour', null, 'Hide for an hour') : t('bannerHideDay', null, 'Hide for a day');
    const close = button('ss-x', ''); const glyph = el('span', 'ss-x-glyph', '✕'); glyph.setAttribute('aria-hidden', 'true'); close.append(glyph, el('span', 'ss-x-label', closeLabel));
    close.setAttribute('aria-label', closeLabel); close.title = closeLabel;
    onTrustedClick(close, () => { closeMenu(); bar.remove(); if (!x.noTrust && x.onHide && canStore()) x.onHide(choice); });
    acts.append(moreBtn, close, menu); bar.appendChild(acts);
    (document.body || document.documentElement).appendChild(bar);
  }

                                                                             
                                                                          
                                                                            
                                                                              
                                                                           
                                                                              
                                           
  function dangerInterstitial(verdict, x) {
    if (document.querySelector('.' + NS + '-interstitial')) return;
    x = x || {};
    const HEADS = [
      t('interstitialHead1', null, 'Do not continue to this destination'),
      t('interstitialHead2', null, 'Pause and review this page first'),
      t('interstitialHead3', null, "Don't go further — scam warning")
    ];
    const ov = el('div', NS + '-overlay ' + NS + '-interstitial'); ov.setAttribute('role', 'alertdialog'); ov.setAttribute('aria-modal', 'true'); ov.setAttribute('aria-label', t('ariaScamWarning', null, 'Scam warning')); setDir(ov);
    const card = el('div', 'ss-card'); const head = el('div', 'ss-head'); const h3 = el('h3', null, HEADS[Math.floor(Math.random() * HEADS.length)]); head.append(tile('danger'), h3); card.append(head);
    card.append(el('p', 'ss-lead', reasonText(verdict.reasons[0]) || t('interstitialFallback', null, 'Multiple signals indicate that this destination may be part of a scam.')));
                                                                             
    const addr = el('div', 'ss-addr'); addr.append(el('small', null, t('thisPage', null, 'This page')), el('code', null, location.href.slice(0, 200))); card.append(addr);
    if (verdict.brandLabel && verdict.brandUrl) { const cmp = compareRow(verdict.brandLabel, verdict.brandUrl); if (cmp) card.appendChild(cmp); }
    const ul = el('ul', 'ss-evidence'); for (const r of (verdict.reasons || []).slice(1, 4)) { const li = el('li'); li.append(el('span', 'ss-chip', t('chipWhy', null, 'Why')), el('span', null, reasonText(r))); ul.appendChild(li); } if (ul.children.length) card.appendChild(ul);
    card.append(el('p', 'ss-sub', t('interstitialReassure', null, "If you entered a password or payment information here, change it through the service’s official app or website.")));
    const actions = el('div', 'ss-actions'); const leave = button('ss-primary', t('leaveThisPage', null, 'Leave this page')); onTrustedClick(leave, () => { x.onLeave ? x.onLeave() : history.back(); }); actions.append(leave);
    const copyBtn = copyReportButton(verdict); actions.append(copyBtn);
                                                                           
                                                                    
    if (verdict.brandUrl) { const rescue = button('ss-rescue-ghost', t('takeMeToReal', [bidi(verdict.brandLabel || 'site')], 'Go to the real ' + (verdict.brandLabel || 'site'))); onTrustedClick(rescue, () => { location.href = verdict.brandUrl; }); actions.append(rescue); }
    card.append(actions);
    const details = el('details', 'ss-details'); const sum = el('summary', null, t('detailsAndOptions', null, 'Details and other options')); details.append(sum);
    const row1 = el('div', 'ss-dt'); const stay = button('ss-danger-ghost', t('continueAnyway', null, 'Continue anyway')); armDelayed(stay, 3);
                                                                                                             
    onTrustedClick(stay, async () => {
      if (canStore()) await send('pauseSite', { domain: regDomain(), choice: '1h' });
      ov.remove();
      if (x.onDismiss) x.onDismiss();
    });
                                                                                                               
    const consequence = canStore() ? t('continuePausesHour', null, 'Pauses PhishGuard on this site for 1 hour.') : t('continueOnce', null, 'Continues to this page once. PhishGuard stays on.');
    row1.append(stay, el('span', 'ss-consequence', consequence)); details.append(row1);
    const row2 = el('div', 'ss-dt');
    const trust = (x.noTrust || !canStore()) ? null : trustButton(async () => { ov.remove(); const domain = regDomain(); await send('trustSite', { domain, via: x.trustVia || 'interstitial' }); ackSurface({ text: t('ackTrusted', [bidi(domain)], "PhishGuard won't flag " + domain + ' again.'), onUndo: () => send('untrustSite', { domain }), restore: () => dangerInterstitial(verdict, x) }); });
    if (trust) { trust.className = 'ss-trust ss-trust-link'; trust.textContent = t('blockedTrustSite', null, 'Not a scam? Trust this site'); row2.append(trust); }
    const rep = el('button', 'ss-report', t('reportMistake', null, 'Report a mistake')); rep.type = 'button'; onTrustedClick(rep, () => { rep.textContent = t('thanks', null, 'Thanks'); rep.disabled = true; x.onReport && x.onReport(); });
    row2.append(rep); details.append(row2); card.append(details);
                                                                                                       
    card.append(el('p', 'ss-foot', t('interstitialFooter', null, "PhishGuard checked this page on your device.")));
    ov.append(card); document.documentElement.appendChild(ov); leave.focus();
  }

                                                                             
                                                                              
                                                                          
                                                                               
                           
                                                                                                         
                  
                                                                                                                                     
                                                                                                                                                                             
                      
       
   

                                                             
                                                                               
                                                                             
                                                                             
                                                                              
                                                              
                                                                             
                                                                             
                                                                         
                                                    
  function guardForms(foreignForms, reasons, onReport) {
    foreignForms.forEach((form) => {
      if (form.__phishguardGuarded) return;
      form.__phishguardGuarded = true;
      const onSubmit = (ev) => {
        ev.preventDefault(); ev.stopPropagation();
        if (document.querySelector('.' + NS + '-overlay')) return;
        const ov = el('div', NS + '-overlay');
        ov.setAttribute('role', 'dialog');
        ov.setAttribute('aria-modal', 'true');
        ov.setAttribute('aria-label', t('ariaPhishingWarning', null, 'Possible phishing warning'));
        setDir(ov);
        const card = el('div', 'ss-card');
        let dest = '';
        try { dest = new URL(form.getAttribute('action') || location.href, location.href).hostname; } catch (_) {}
        card.append(
          el('h3', null, t('phishingStop', null, 'Stop — possible phishing')),
          el('p', null, dest
            ? t('guardFormDestKnown', [bidi(dest), bidi(location.hostname)], 'This form sends your password to ' + dest + ', not to ' + location.hostname + '. Sending a password to a different website is how scammers steal logins.')
            : t('guardFormDestUnknown', null, 'This form sends a password to a different site from the one displayed. That mismatch can expose your sign-in details.'))
        );
        const ul = el('ul', 'ss-evidence');
        for (const r of (reasons || []).slice(0, 3)) { const li = el('li'); li.append(el('span', 'ss-chip', t('chipPage', null, 'Page')), el('span', null, reasonText(r))); ul.appendChild(li); }
        card.appendChild(ul);
        const actions = el('div', 'ss-actions');
        const back = button('ss-primary', t('cancelRecommended', null, 'Cancel (recommended)'));
        const close = () => { document.removeEventListener('keydown', onKey, true); ov.remove(); };
        const onKey = (e) => { if (!e.isTrusted) return; if (e.key === 'Escape') { e.preventDefault(); close(); } };
                                                                               
                                                                          
                                                                     
                                                                       
                                                           
        onTrustedClick(back, close);
        const go = button('ss-danger-ghost', t('submitAnyway', null, 'Submit anyway'));
        armDelayed(go, 3);
                                                                                 
                                                                 
        onTrustedClick(go, () => { document.removeEventListener('keydown', onKey, true); ov.remove(); form.submit(); });
        actions.append(back, go);
        const rep = button('ss-report', t('reportMistake', null, 'Report a mistake')); onTrustedClick(rep, () => { rep.textContent = t('thanks', null, 'Thanks'); rep.disabled = true; onReport && onReport(); }); actions.prepend(rep);
        card.append(actions); ov.append(card);
        document.documentElement.appendChild(ov);
        document.addEventListener('keydown', onKey, true);
        back.focus();
      };
      form.addEventListener('submit', onSubmit, true);
      form.addEventListener('phishguard:formsubmit', onSubmit, true);
    });
  }

  function hideScamBlocks(blocks) {
    blocks.forEach((node) => {
      if (node.classList.contains(NS + '-hidden-block')) return;
      node.classList.add(NS + '-hidden-block');
      const tag = el('div', NS + '-hidden-tag', t('guardHiddenTag', null, 'Hidden by PhishGuard'));
      setDir(tag);
      node.appendChild(tag);
    });
  }

  function walletConfirmOverlay(detail, onDecision) {
    if (document.querySelector('.' + NS + '-overlay')) {
                                                                             
                                                                         
                                                                               
                                                                           
                                                               
      toast({ kind: 'warn', role: 'alert', title: t('guardWalletCollision', null, 'PhishGuard blocked a wallet request while another warning was open. Close it and retry.'), timeoutMs: 12000 });
      onDecision(false, { collision: true });
      return;
    }
    const ov = el('div', NS + '-overlay ' + NS + '-wallet');
    ov.setAttribute('role', 'dialog'); ov.setAttribute('aria-modal', 'true');
    ov.setAttribute('aria-label', t('walletRiskyTitle', null, 'Risky wallet request'));
    setDir(ov);
    const card = el('div', 'ss-card');
    const head = el('div', 'ss-head'); const h3 = el('h3', null, t('walletRiskyTitle', null, 'Risky wallet request')); head.append(tile('warn'), h3);
    card.append(head,
      el('p', null, reasonText(detail.reasons && detail.reasons[0]) || t('guardWalletFallback', null, 'A wallet request needs review before you approve it.')),
      el('p', 'ss-sub', t('walletRiskyBody', null, 'Cancel if you did not expect this request. Some signatures grant ongoing token or account permissions that are difficult to reverse.')));
    const actions = el('div', 'ss-actions');
    const cancel = button('ss-primary', t('cancelRecommended', null, 'Cancel (recommended)'));
    const proceed = button('ss-danger-ghost', t('proceedAnyway', null, 'Proceed anyway'));
    armDelayed(proceed, 3);
    let decided = false;
    const watch = new MutationObserver(() => {
                                                                              
                                                                           
      if (!decided && !ov.isConnected) { decided = true; stop(); onDecision(false); }
    });
    const stop = () => { watch.disconnect(); document.removeEventListener('keydown', onKey, true); };
    const done = (allow) => { if (decided) return; decided = true; stop(); ov.remove(); onDecision(allow); };
    const onKey = (e) => { if (!e.isTrusted) return; if (e.key === 'Escape') { e.preventDefault(); done(false); } };
                                                                              
                                                                          
    onTrustedClick(cancel, () => done(false));
    onTrustedClick(proceed, () => done(true));
    actions.append(cancel, proceed); card.append(actions); ov.append(card);
    document.documentElement.appendChild(ov);
    watch.observe(document, { childList: true });
    watch.observe(document.documentElement, { childList: true });
    document.addEventListener('keydown', onKey, true); cancel.focus();
                                                                             
                                                      
                                                                              
                                                                                    
    try {
      const d = { id: detail.id };
      window.dispatchEvent(new CustomEvent('phishguard:wallet-ack', { detail: typeof cloneInto === 'function' ? cloneInto(d, window) : d }));
    } catch (_) {}
  }

                                                                           
                                                                       
                                                                           
                                                  
  function privacyToast(detail) {
    const d = detail || {};
    return toast({
      kind: 'warn', role: 'status', title: d.title || '',
      body: d.text || t('guardPrivacyFallback', null, 'PhishGuard observed a possible data-exposure or tracking pattern on this page.'),
      muteKind: d.muteKind, onMute: d.onMute
    });
  }

                                                                           
                                                                           
                                                                     
                                                                            
                                                                             
                                                                    
                                                                           
                                                                         
                                                                              
  function showScanNotice(opts) {
    const o = opts || {};
    return toast({ kind: 'info', role: 'status', title: o.title || 'Page analysis refreshed',
      body: o.body || 'PhishGuard rescanned this page and its permitted frames. Detailed evidence is available in the extension popup.' });
  }

  function showContextAnalysis(opts) {
    const o = opts || {};
    const kind = o.level === 'dangerous' ? 'danger' : o.level === 'suspicious' ? 'warn' : 'info';
    return toast({ kind, role: 'status', timeoutMs: 14000,
      title: o.title || 'Selected text analyzed on this page',
      body: o.body || 'The selected text was assessed separately from the page hosting it.' });
  }

  function showVerdictStatus(opts) {
    const o = opts || {};
    const level = String(o.level || 'unknown');
    const kind = level === 'dangerous' ? 'danger' : level === 'suspicious' ? 'warn' :
      level === 'safe' ? 'ok' : level === 'informational' ? 'info' : 'notice';
    return toast({ kind, role: 'status', timeoutMs: o.timeoutMs || 7500,
      title: o.title || 'PhishGuard page assessment updated',
      body: o.body || 'PhishGuard has updated its assessment of the current page.' });
  }

  function clearBanner() {
    document.querySelectorAll('.' + NS + '-banner').forEach((node) => {
      if (node.__ssTeardown) node.__ssTeardown();
      node.remove();
    });
    document.querySelectorAll('.' + NS + '-overlay:not(.' + NS + '-wallet)').forEach((node) => node.remove());
  }

  function crossOriginCredToast(reason, onProceed, onMute) {
    return toast({
      kind: 'danger', role: 'alert', persist: true,
      title: t('credPostTitle', null, 'This form sends entered data to another site'),
      body: reasonText(reason),
      actions: [
        { cls: 'ss-keep', label: t('keepMyDetails', null, 'Keep my details'), primary: true },
        { cls: 'ss-send', label: t('submitAnyway', null, 'Submit anyway'), onClick: onProceed }
      ],
      muteKind: 'credpost', onMute
    });
  }

                                                                            
                                                                         
                                                                          
                                                                          
                                                                             
                                                                  
  function clipboardToast(detail) {
    const d = detail || {};
    const reason = (d.reasons && d.reasons[0]) || {};
    const host = bidi(d.host);
    if (d.tier === 'notice') {
      const isAddr = reason.code === 'clipboardCryptoAddress';
      return toast({
        kind: 'notice', role: 'status',
        title: isAddr
          ? t('clipboardNoticeAddrTitle', [host], 'You copied a crypto address from ' + d.host)
          : t('clipboardNoticeCmdTitle', [host], 'You copied a terminal command from ' + d.host),
        body: isAddr
          ? t('clipboardNoticeAddrBody', null, 'Compare every character with the intended recipient before transferring funds.')
          : t('clipboardNoticeCmdBody', null, 'Do not run it unless you independently understand and trust the command. Fake verification pages use this trick to install malware.'),
        muteKind: 'clipboard', onMute: d.onMute
      });
    }
    return toast({
      kind: 'warn', role: 'status',
      title: t('clipboardWarnTitle', [host], d.host + ' changed your clipboard on its own'),
      body: reasonText(reason) || t('guardClipboardFallback', null, 'A site changed your clipboard.'),
      muteKind: 'clipboard', onMute: d.onMute
    });
  }

  function techScamEscapeOverlay(verdict, onLeave) {
    if (document.querySelector('.' + NS + '-overlay')) return;
    const ov = el('div', NS + '-overlay');
    ov.setAttribute('role', 'dialog'); ov.setAttribute('aria-modal', 'true');
    ov.setAttribute('aria-label', t('techScamTitle', null, 'Possible tech-support scam'));
    setDir(ov);
    const card = el('div', 'ss-card');
    const head = el('div', 'ss-head'); const h3 = el('h3', null, t('techScamTitle', null, 'Possible tech-support scam')); head.append(tile('danger'), h3);
    card.append(head,
      el('p', null, reasonText(verdict.reasons && verdict.reasons[0]) || t('guardTechScamFallback', null, 'This page is using scare tactics.')),
      el('p', 'ss-sub', t('techScamBody', null, 'A web page cannot diagnose a computer infection by itself. Close this page; do not call a number or install remote-support software offered by the warning.')));
    const actions = el('div', 'ss-actions');
    const leave = button('ss-primary', t('getMeOut', null, 'Get me out (close this page)'));
    const stay = button('', t('dismiss', null, 'Dismiss'));
    const close = () => { document.removeEventListener('keydown', onKey, true); ov.remove(); };
    const onKey = (e) => { if (!e.isTrusted) return; if (e.key === 'Escape') { e.preventDefault(); close(); } };
                                                                                
                                                                               
    onTrustedClick(leave, () => { close(); onLeave && onLeave(); });
    onTrustedClick(stay, close);
    actions.append(leave, stay); card.append(actions); ov.append(card);
    document.documentElement.appendChild(ov);
    document.addEventListener('keydown', onKey, true); leave.focus();
  }

  root.PhishGuard = root.PhishGuard || {};
  root.PhishGuard.actions = { showBanner, guardForms, hideScamBlocks, clearAll, walletConfirmOverlay, clipboardToast, techScamEscapeOverlay, showScanNotice, showContextAnalysis, showVerdictStatus, clearBanner, dangerInterstitial, armDelayed, privacyToast, crossOriginCredToast, ackSurface };
})(typeof globalThis !== 'undefined' ? globalThis : self);
