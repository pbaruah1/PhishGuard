'use strict';
const api = globalThis.browser || globalThis.chrome;
const $ = (id) => document.getElementById(id);
const SS = globalThis.PhishGuard, F = globalThis.SSFormat, I = globalThis.SSIcons, R = globalThis.SSReasons, SSTATS = globalThis.SSStats;
                                                                              
                                                                         
                                                         
let UI_LANG = (() => { try { return api.i18n.getUILanguage(); } catch (_) { return 'en'; } })();
                                                                          
                                                               
const T = (k, subs, fb) => { const v = globalThis.SSi18n && globalThis.SSi18n.t(k, subs); return v || fb || k; };
const bidi = (s) => (R && R.bidiWrap ? R.bidiWrap(s) : (s == null ? '' : String(s)));
const LEVELTXT = { safe: 'popupSafe', suspicious: 'popupSuspicious', dangerous: 'popupDangerous', unknown: 'popupUnknown' };
const levelLabel = (lvl) => T(LEVELTXT[lvl] || 'popupUnknown', null, F.levelText(lvl));
const send = (type, extra) => new Promise((res) => { try { api.runtime.sendMessage(Object.assign({ type }, extra || {}), (r) => res(r)); } catch (_) { res(null); } });
                                                                                            
const registrable = (h) => (SS && SS.scopeDomain) ? SS.scopeDomain(h) : (SS && SS.registrableDomain) ? SS.registrableDomain(h) : String(h || '').split('.').slice(-2).join('.');
const brandName = (key) => SS.brandDisplayName ? SS.brandDisplayName(key) : key;
function toast(t) { const el = $('toast'); el.textContent = t; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 1400); }
                                                                                
                                                                             
                                                                              
                                                                              
                                                    
function timeOfDay(ts) {
  const opts = { hour: '2-digit', minute: '2-digit' };
  const d = new Date(ts), now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (!sameDay) { opts.month = 'short'; opts.day = 'numeric'; }
  try { return d.toLocaleTimeString(UI_LANG, opts); } catch (_) { return d.toLocaleTimeString('en', opts); }
}

let tab = null, domain = null, settings = null, verdict = null, level = 'unknown';

function renderStatus(level, host, summary, levelTextOverride) {
  $('status').className = 'card status ' + level;
  $('statusicon').innerHTML = I.shield(level); $('level').textContent = levelTextOverride || levelLabel(level); $('host').textContent = host || '';
  $('summary').hidden = !summary; $('summary').textContent = summary || '';
}
                                                                                
                                                                             
const chipLabel = (kind) => T('chip' + kind.charAt(0).toUpperCase() + kind.slice(1), null, F.detectorLabel(kind));
                                                                               
                                                                       
                                                                          
                                                                               
                                                                             
                                                                          
                                                                              
function renderEvidence(reasons, level) {
  const ul = $('reasons'); ul.replaceChildren();
  const list = (level === 'safe' || level === 'unknown') ? [] : (reasons || []).slice(0, 5);
  for (const r of list) {
    const kind = R.reasonKind(r);
    const li = document.createElement('li'); const chip = document.createElement('span'); chip.className = 'chip' + (kind === 'brand' ? ' brand' : '');
    chip.textContent = chipLabel(kind);
    const span = document.createElement('span'); span.textContent = R.resolveReason(r); li.append(chip, span); ul.appendChild(li);
  }
  const n = list.length;
  $('whypanel').hidden = n === 0;
  $('whycount').textContent = n === 0 ? '' : n === 1 ? T('whyVerdictCountOne', null, '· 1 signal') : T('fmtWhyVerdictCount', [bidi(String(n))], `· ${n} signals`);
  $('whypanel').open = level === 'dangerous' || level === 'suspicious';
                                                                    
                                                                         
                                                                           
                                                     
  $('whyfoot').hidden = !(level === 'dangerous' || level === 'suspicious');
}
                                                                           
                                                                          
                                                                           
function copyReportText() {
  const host = tab && tab.url ? new URL(tab.url).hostname : '';
  const hostText = bidi(R && R.defangHost ? R.defangHost(host) : host);
  const lvlLabel = levelLabel(level);
  const headerLine = T('copyReportHeader', [hostText], '⚠ PhishGuard flagged this site: ' + host);
  const verdictLine = T('copyReportVerdict', [lvlLabel], 'Verdict: ' + lvlLabel);
  const signalsLabel = T('copyReportSignals', null, 'Signals:');
  const footerLine = T('copyReportFooter', null, 'Checked locally by PhishGuard. Review the evidence before acting.');
  const reasons = ((verdict && verdict.reasons) || []).slice(0, 4).map((r) => R.resolveReason(r)).filter(Boolean);
  return (R && R.buildCopyReportText)
    ? R.buildCopyReportText({ headerLine, verdictLine, signalsLabel, reasons, footerLine })
    : [headerLine, verdictLine, signalsLabel].concat(reasons.map((r) => '- ' + r), [footerLine]).join('\n');
}
                                                                             
                                                                     
                                                                            
                                                                         
function renderVerdictUI(host) {
  const checking = !!settings.enabled && verdict == null;
  level = !settings.enabled ? 'unknown' : (verdict ? (verdict.level || 'safe') : 'unknown');
  const brand = verdict && verdict.brand ? brandName(verdict.brand) : null;
  renderStatus(level, host,
    !settings.enabled ? T('popupPausedSummary', null, 'Checks are paused for now. Resume them to inspect this page.') :
    checking ? '' :
    level === 'dangerous' ? (brand ? T('popupBrandDangerSummary', [bidi(brand)], `Looks like ${brand}, but isn't. Don't enter your password here.`) : T('popupDangerSummary', null, "Strong risk indicators were found. Avoid entering credentials, payment details, or downloading files here.")) :
    level === 'suspicious' ? T('popupSuspiciousSummary', null, 'Some signals deserve a closer look. Check the address and evidence before sharing information.') : '',
    checking ? T('popupChecking', null, 'Checking…') : undefined);
  renderEvidence(verdict && verdict.reasons, level);
  $('leave').hidden = level !== 'dangerous';
  $('leave').textContent = T('leaveThisPage', null, 'Leave this page');
  const rescueUrl = verdict && verdict.brand && SS.BRAND_DOMAINS[verdict.brand] ? 'https://' + SS.BRAND_DOMAINS[verdict.brand][0] + '/' : null;
  $('rescue').hidden = !(level === 'dangerous' && rescueUrl); if (rescueUrl) $('rescue').textContent = T('takeMeToReal', [bidi(brand)], 'Take me to the real ' + brand);
  $('reportbtn').hidden = checking;
  if (!checking) $('reportbtn').querySelector('.lbl').textContent = level === 'safe' || level === 'unknown' ? T('reportScam', null, 'Report: this is a scam') : T('reportSafe', null, 'Report: this is safe');
  renderFooter(level);
}
let footerVariant = 'trust';
async function resolveFooterVariant() {
  try {
    const stored = (await api.storage.local.get('footerVariant')).footerVariant;
    footerVariant = stored === 'trust' ? 'support' : 'trust';
    await api.storage.local.set({ footerVariant });
  } catch (_) { footerVariant = 'trust'; }
}
function renderFooter() {
  $('askcard').hidden = true;
  $('foottrust').hidden = footerVariant !== 'trust';
  $('footsupport').hidden = footerVariant !== 'support';
}
async function pollVerdict(host) {
  for (let i = 0; i < 10; i++) {
    await new Promise((res) => setTimeout(res, 300));
    const v = await send('getVerdict', { tabId: tab.id });
    if (v != null) { verdict = v; renderVerdictUI(host); return; }
  }
}
function renderTrust() {
  const paused = settings.pausedSites && settings.pausedSites[domain];
  const always = (settings.allowlist || []).includes(domain);
  $('trust').hidden = !!paused || always || (SS.isTenantApex && SS.isTenantApex(domain)); $('trusted').hidden = !(paused || always);
  const until = paused ? timeOfDay(paused) : '';
  $('trustedtext').textContent = always ? T('paused', null, 'Paused') : paused ? T('pausedUntil', [bidi(until)], 'Paused until ' + until) : '';
}
                                                                      
                                                                      
                                                                           
                                                                       
function setTrustMenu(open) {
  if (open) setLangMenu(false);
  $('trustmenu').hidden = !open; $('trust').setAttribute('aria-expanded', String(open));
  if (open) { const first = $('trustmenu').querySelector('.dditem'); if (first) first.focus(); }
}
function setLangMenu(open) {
  if (open) setTrustMenu(false);
  $('langdd').hidden = !open; $('langbtn').setAttribute('aria-expanded', String(open));
  if (open) { const cur = $('langdd').querySelector('.cur') || $('langdd').querySelector('.langitem'); if (cur) cur.focus(); }
}
                                                                              
                                                                  
                                                                                  
                                                                            
                                                                          
                                                                            
                                                                            
                                                                           
                                                                                   
        
function buildLangMenu() {
  const dd = $('langdd'); dd.replaceChildren();
  const current = (settings && settings.uiLang) || 'auto';
  const mk = (value, label) => {
    const b = document.createElement('button');
    b.type = 'button'; b.setAttribute('role', 'menuitem');
    b.className = 'dditem langitem' + (value === current ? ' cur' : '');
    b.dataset.lang = value;
    const span = document.createElement('span'); span.textContent = label;
    const chk = document.createElement('span'); chk.className = 'chk'; chk.textContent = value === current ? '✓' : '';
    b.append(span, chk);
    b.addEventListener('click', async () => {
      setLangMenu(false);
      await send('setSettings', { patch: { uiLang: value } });
      location.reload();
    });
    return b;
  };
  dd.appendChild(mk('auto', T('optLangAuto', null, 'Browser default')));
  for (const code of (R ? R.LOCALES : [])) dd.appendChild(mk(code, (R && R.LANG_NAMES && R.LANG_NAMES[code]) || code));
}
                                                                        
                                                                       
                                                                            
                                                                           
                                                                            
                                                                          
                                                          
async function currentTab() {
  let self = null; try { self = await api.tabs.getCurrent(); } catch (_) {}
  if (!self) { const [t] = await api.tabs.query({ active: true, currentWindow: true }); return t || null; }
  const all = await api.tabs.query({ currentWindow: true });
                                                                        
                                                                           
                                                                  
                                                                           
                                                                             
                                                                         
                                                                           
                                                                        
                                                                         
  const others = all.filter((t) => t.id !== self.id);
  const web = others.filter((t) => t.url && /^https?:/.test(t.url));
  return others.find((t) => t.active) || web[web.length - 1] || others[others.length - 1] || null;
}
async function init() {
                                                                               
                                                                         
                                                         
  const settingsPromise = send('getSettings');
                                                                        
                                                                             
                                                                         
                                                                             
  const statsPromise = send('getStats');
                                                                              
                                                                              
                                                                         
                                                                              
                                                                       
                                                                             
                                                                         
                                                                         
                                                                        
  const footerVariantPromise = resolveFooterVariant();
                                                                               
                                                                             
                                                                           
                             
  try {
    const lang = await globalThis.SSi18n.ready;
    if (lang) UI_LANG = R.intlTag(lang);                                             
  } catch (_) {                                         }
  $('lockline').textContent = T('footerTrustLine', null, 'Most checks run locally. Threat-list and site-icon requests use the network; reports stay local unless you configure and enable a relay.');
  $('brandmark').insertAdjacentHTML('afterbegin', '<img class="ic" src="assets/icons/icon32.png" alt="" width="16" height="16">'); $('opts').innerHTML = I.gear(); $('langbtn').innerHTML = I.globe(); $('lockline').insertAdjacentHTML('afterbegin', I.lock());
  try { $('ver').textContent = api.runtime.getManifest().version; } catch (_) {}
  settings = await settingsPromise;
  if (!settings) { renderStatus('unknown', '', T('toastExtensionError', null, 'Extension error — try reopening.')); return; }
  $('enabled').checked = !!settings.enabled; $('enabledwrap').classList.toggle('on', !!settings.enabled); $('enabledlbl').textContent = settings.enabled ? T('on', null, 'On') : T('paused', null, 'Paused');
  $('enabled').addEventListener('change', async () => { settings = await send('setSettings', { patch: { enabled: $('enabled').checked } }); $('enabledwrap').classList.toggle('on', !!settings.enabled); $('enabledlbl').textContent = settings.enabled ? T('on', null, 'On') : T('paused', null, 'Paused'); });
  $('opts').addEventListener('click', (e) => { e.preventDefault(); api.runtime.openOptionsPage(); });
  const aiPanelButton = $('open-ai-panel');
  if (aiPanelButton) {
    aiPanelButton.hidden = !api.sidePanel || !tab || !Number.isInteger(tab.id);
    aiPanelButton.addEventListener('click', async () => {
      try { await api.sidePanel.open({ tabId: tab.id }); window.close(); }
      catch (error) { toast('Could not open the AI panel: ' + String(error.message || error)); }
    });
  }
                                                                            
                                                                       
                                                                   
  buildLangMenu();
  $('langbtn').addEventListener('click', (e) => { e.stopPropagation(); setLangMenu($('langdd').hidden); });
  document.addEventListener('click', (e) => { if (!$('langdd').hidden && !$('langdd').contains(e.target) && e.target !== $('langbtn')) setLangMenu(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('langdd').hidden) { setLangMenu(false); $('langbtn').focus(); } });
  $('support').addEventListener('click', (e) => { e.preventDefault(); api.tabs.create({ url: api.runtime.getURL('options.html#about') }); });
                                                                              
                                                                             
                                                                            
  $('viewall').addEventListener('click', (e) => { e.preventDefault(); api.tabs.create({ url: api.runtime.getURL('options.html#stats') }); window.close(); });
  if (settings.whatsNewSeen !== '1.0.0') { $('whatsnew').hidden = false; $('whatsnewlink').addEventListener('click', (e) => { e.preventDefault(); api.tabs.create({ url: api.runtime.getURL('options.html#about') }); }); $('whatsnewx').addEventListener('click', async () => { $('whatsnew').hidden = true; await send('setSettings', { patch: { whatsNewSeen: '1.0.0' } }); }); }

  tab = await currentTab();
                                                                              
                                                                        
                                                                       
                                                                               
                                                                               
                                                               
                                                                         
                                                                         
  const stats = await statsPromise;
  $('tile-since').querySelector('b').textContent = String((stats && Number(stats.threatsBlocked)) || settings.threatsBlocked || 0);
  const weekly = (stats && Array.isArray(stats.statsDaily) && SSTATS) ? SSTATS.summarize(stats.statsDaily, 7, Date.now()).threats : 0;
  $('tile-week').querySelector('b').textContent = String(weekly || 0);
  const http = tab && tab.url && /^https?:/.test(tab.url);
  if (!http) {
    const protocol = tab && tab.url ? new URL(tab.url).protocol.replace(':', '') : '';
    renderStatus('unknown', protocol ? T('fmtProtocolPage', [bidi(protocol)], protocol + ' page') : '', T('popupNotHttp', null, "Browser-internal pages and extension-store pages are outside PhishGuard’s scanning coverage."));
    await footerVariantPromise;
    renderFooter('unknown');
    renderHistory(); return;
  }
  const host = new URL(tab.url).hostname; domain = registrable(host);
  verdict = await send('getVerdict', { tabId: tab.id });
  await footerVariantPromise;
  renderVerdictUI(host);
  if (settings.enabled && verdict == null) pollVerdict(host);                                                        
  $('leave').addEventListener('click', async () => { await send('leaveTab', { tabId: tab.id }); window.close(); });
  wireQrScan();
  $('copyreport').addEventListener('click', () => {
    const text = copyReportText();
                                                                              
                                                                        
                                                          
    try { window.__ssLastCopyReport = text; } catch (_) {}
    const copy = R && R.copyToClipboard ? R.copyToClipboard(text) : Promise.resolve(false);
    copy.then((ok) => { if (ok) toast(T('toastCopied', null, 'Copied')); });
  });
  $('rescue').addEventListener('click', () => {
    const rescueUrl = verdict && verdict.brand && SS.BRAND_DOMAINS[verdict.brand] ? 'https://' + SS.BRAND_DOMAINS[verdict.brand][0] + '/' : null;
    if (rescueUrl) { api.tabs.update(tab.id, { url: rescueUrl }); window.close(); }
  });
  $('trust').textContent = T('popupPauseMenu', null, 'Site controls ▾');
  $('trust').hidden = false; renderTrust();
  $('trust').addEventListener('click', (e) => { e.stopPropagation(); setTrustMenu($('trustmenu').hidden); });
  document.addEventListener('click', (e) => { if (!$('trustmenu').hidden && !$('trustmenu').contains(e.target) && e.target !== $('trust')) setTrustMenu(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('trustmenu').hidden) { setTrustMenu(false); $('trust').focus(); } });
                                                                              
                                                                          
                                                                       
  for (const b of document.querySelectorAll('#trustmenu .dditem')) b.addEventListener('click', async () => {
    const r = await send('pauseSite', { domain, choice: b.dataset.choice }); setTrustMenu(false);
    settings = await send('getSettings'); renderTrust(); toast(r && r.until ? T('toastPausedForNow', null, 'Paused for now') : T('paused', null, 'Paused'));
  });
  $('untrust').addEventListener('click', async () => { await send('unpauseSite', { domain }); settings = await send('getSettings'); renderTrust(); toast(T('toastResumed', null, 'Protection resumed')); });

  $('reportbtn').addEventListener('click', async () => {
    const r = await send('userReport', { label: level === 'safe' || level === 'unknown' ? 'scam' : 'false_positive', tabId: tab.id });
    $('reportbtn').hidden = true; $('reportdone').hidden = false; $('reportdone').textContent = r && r.via === 'relay' ? T('toastThanksSent', null, 'Thanks — sent') : T('toastThanksNoted', null, 'Saved on this device; nothing was sent.');
  });

  const [h, pf, shop] = await Promise.all([send('getHistory'), send('getPrivacyFindings', { tabId: tab.id }), send('getShopFindings', { tabId: tab.id })]);
  renderHistoryList((h && h.history) || []);
  renderPrivacy((pf && pf.findings) || []);
  renderShop(shop || { flags: [] });
}
function renderShop(shop) {
  const flags = (shop && shop.flags) || [];
  if (!flags.length) return;
  $('shopcard').hidden = false;
  const ul = $('shoplist'); ul.replaceChildren();
  for (const f of flags.slice(0, 6)) {
    const li = document.createElement('li');
    const chip = document.createElement('span'); chip.className = 'chip' + (shop.level === 'suspicious' ? ' brand' : ''); chip.textContent = R.resolveReason({ code: 'shop_' + f.code }) || T('popupShopFlagFallback', null, 'Flag');
    const span = document.createElement('span'); span.textContent = R.resolveReason({ code: 'shop_' + f.code + '_detail' });
    li.append(chip, span); ul.appendChild(li);
  }
}
function renderPrivacy(findings) {
  if (!findings.length) return;
  $('privacycard').hidden = false;
  const ul = $('privacylist'); ul.replaceChildren();
  const label = { 'leaky-form': () => T('chipDataLeak', null, 'Data leak'), fingerprint: () => T('chipTracking', null, 'Tracking'), 'notify-lure': () => T('chipPopups', null, 'Pop-ups'), 'cross-origin-cred-post': () => T('chipDataLeak', null, 'Data leak') };
  const text = (f) =>
    f.kind === 'leaky-form' ? (f.detail && f.detail !== 'plain'
      ? T('popupPrivacyLeakHashed', [bidi(f.host)], 'Sent your email/phone to ' + f.host + ' (hashed) before you submitted.')
      : T('popupPrivacyLeakPlain', [bidi(f.host)], 'Sent your email/phone to ' + f.host + ' before you submitted.')) :
    f.kind === 'fingerprint' ? T('popupPrivacyFingerprint', [bidi(f.host)], f.host + ' is fingerprinting your device to track you.') :
    f.kind === 'notify-lure' ? T('popupPrivacyNotifyLure', null, 'This page used a misleading prompt to request notification permission.') :
    f.kind === 'cross-origin-cred-post' ? (f.detail === 'password'
      ? T('popupPrivacyCredExfilPassword', [bidi(f.host)], 'Sent your password to ' + f.host + ' — a different site than the one you were on.')
      : T('popupPrivacyCredExfilCard', [bidi(f.host)], 'Sent your card details to ' + f.host + ' — a different site than the one you were on.')) :
    T('popupPrivacyDefaultText', null, 'Privacy issue detected.');
  for (const f of findings.slice(0, 5)) {
    const li = document.createElement('li');
    const chip = document.createElement('span'); chip.className = 'chip brand'; chip.textContent = label[f.kind] ? label[f.kind]() : T('chipPrivacy', null, 'Data exposure and tracking');
    const span = document.createElement('span'); span.textContent = text(f);
    li.append(chip, span); ul.appendChild(li);
  }
}
function renderHistoryList(list) {
  if (!list.length) return; $('recent').hidden = false; const ul = $('hist'); ul.replaceChildren();
  for (const e of list.slice(0, 3)) {
    const li = document.createElement('li'); const chip = document.createElement('span'); chip.className = 'chip' + (e.kind === 'page' ? '' : ' brand'); chip.textContent = chipLabel(e.kind);
    const hs = document.createElement('span'); hs.className = 'h'; hs.textContent = e.host || T('unknownSite', null, 'unknown site'); const t = document.createElement('time'); t.textContent = F.relTime(e.ts, undefined, UI_LANG);
    li.append(chip, hs, t); ul.appendChild(li);
  }
}
async function renderHistory() {
  const h = await send('getHistory'); renderHistoryList((h && h.history) || []);
}
                                                                           
                                                                       
                                                                          
                                                                                      
                                                                         
                                                                           
                                          
function wireQrScan() {
  $('qrcheck').hidden = false;
  const btn = $('qrscanbtn');
  btn.addEventListener('click', async () => {
    if (!tab) return;
    btn.disabled = true;
    let res = null;
    try { res = await new Promise((resolve) => { api.tabs.sendMessage(tab.id, { type: 'scanQrCodes' }, (r) => resolve(r)); }); } catch (_) { res = null; }
    btn.disabled = false;
    const results = (res && Array.isArray(res.results)) ? res.results : [];
    $('qrresult').hidden = false;
    const ul = $('qrlist'); ul.replaceChildren();
    if (!res) {
      $('qrsummary').textContent = T('qrScanUnavailable', null, 'PhishGuard could not reach this page. Refresh the page and try again.');
      return;
    }
    if (!results.length) {
      const checked = Number(res.scanned) || 0;
      $('qrsummary').textContent = checked
        ? T('qrScanNoneCount', [String(checked)], `No QR code could be decoded in the ${checked} supported images checked.`)
        : T('qrScanNone', null, 'No supported images were available to check for QR codes.');
      return;
    }
    const websites = Number(res.websiteCount) || 0;
    const other = Number(res.nonWebsiteCount) || 0;
    $('qrsummary').textContent = T('qrScanSummary', [String(results.length), String(websites), String(other)],
      `${results.length} QR code${results.length === 1 ? '' : 's'} decoded. ${websites} website destination${websites === 1 ? '' : 's'} checked; ${other} non-website payload${other === 1 ? '' : 's'} identified but not safety-rated.`);
    for (const r of results.slice(0, 10)) {
      const li = document.createElement('li');
      const chip = document.createElement('span');
      chip.className = 'chip' + (r.level === 'dangerous' || r.level === 'suspicious' ? ' brand' : '');
      const statusText = r.valid === false ? T('qrInvalidCodeLabel', null, 'Invalid or unreadable QR code') :
        r.kind === 'website' ? (r.level === 'dangerous' ? T('qrValidDangerousLabel', null, 'Valid QR · Dangerous destination') :
          r.level === 'suspicious' ? T('qrValidSuspiciousLabel', null, 'Valid QR · Suspicious destination') :
          T('qrValidSafeLabel', null, 'Valid QR · No strong destination risk found')) :
        r.kind === 'malformed-url' ? T('qrDecodedMalformedLabel', null, 'Valid QR · Malformed website address') :
        r.kind === 'active-scheme' ? T('qrDecodedUnsafeLabel', null, 'Valid QR · Unsafe link type') :
        r.kind === 'external-action' || r.kind === 'unsupported-scheme' ? T('qrDecodedExternalLabel', null, 'Valid QR · External app action') :
        T('qrDecodedNonWebLabel', null, 'Valid QR · Non-website data (not safety-rated)');
      chip.textContent = statusText;
      const span = document.createElement('span');
      span.textContent = r.host || r.label || (() => { try { return new URL(r.url).hostname; } catch (_) { return 'QR payload'; } })();
      li.append(chip, span); ul.appendChild(li);
    }
  });
}
function wireMessageChecker() {
  if (!SS || typeof SS.scoreMessage !== 'function') { $('msgcheck').hidden = true; return; }
  $('msgbtn').addEventListener('click', async () => {
    const input = $('msgtext').value;
    $('msgresult').hidden = false;
    if (!input.trim()) {
      $('msgstatus').className = 'status mini unknown';
      $('msgicon').innerHTML = I.shield('unknown');
      $('msglevel').textContent = T('checkMessageTitle', null, 'Inspect a message or destination');
      $('msgwhy').textContent = T('checkMessagePlaceholder', null, 'Paste a message or link first.');
      $('msgmeta').textContent = '';
      return;
    }
    const button = $('msgbtn');
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
      const base = SS.scoreMessage(input);
      const r = typeof SS.enrichMessageReputation === 'function'
        ? await SS.enrichMessageReputation(base, (host) => send('checkFeed', { host }), 1600)
        : base;
      $('msgstatus').className = 'status mini ' + r.level; $('msgicon').innerHTML = I.shield(r.level);
      $('msglevel').textContent = r.level === 'safe' ? T('msgSafe', null, 'No strong scam indicators found in this sample. That does not prove it is genuine.') : r.level === 'suspicious' ? T('msgSuspicious', null, 'Several risk clues were found. Verify the sender and destination independently.') : T('msgDangerous', null, 'This sample contains high-risk scam signals. Do not follow its instructions.');
      $('msgwhy').textContent = r.reasons.slice(0, 3).map((x) => R.resolveReason(x)).filter(Boolean).join(' · ') || T('msgNoSignals', null, 'No clear scam signals were found. Stay cautious with unexpected requests.');
      const evidenceList = $('msgevidence');
      evidenceList.replaceChildren();
      const evidence = Array.isArray(r.evidence) ? r.evidence : [];
      if (!evidence.length) evidence.push({ title: 'No strong indicators found', detail: 'This sample did not contain enough evidence to classify it as suspicious. That is not proof that the sender or destination is genuine.', severity: 'info' });
      for (const item of evidence.slice(0, 8)) {
        const li = document.createElement('li'); li.className = 'evidence-item ' + (item.severity || 'info');
        const title = document.createElement('strong'); title.textContent = item.title || 'Analysis evidence';
        const detail = document.createElement('span'); detail.textContent = item.detail || '';
        li.append(title, detail); evidenceList.appendChild(li);
      }
      const score = Math.round((Number(r.score) || 0) * 100);
      $('msgmeta').textContent = T('msgScoreDetails', [String(score), String((r.links || []).length)], `Risk indicator score: ${score}/100 · Links checked: ${(r.links || []).length}`);
    } finally {
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  });
}
wireMessageChecker();
init().catch((err) => { renderStatus('unknown', '', T('toastExtensionError', null, 'Extension error — try reopening.')); console.error('[PhishGuard] popup init failed:', err); });
