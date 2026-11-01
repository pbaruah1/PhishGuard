'use strict';
const api = globalThis.browser || globalThis.chrome;
const $ = (id) => document.getElementById(id);
const F = globalThis.SSFormat, I = globalThis.SSIcons, REVIEW = globalThis.SSReview;
const SS = globalThis.PhishGuard;
                                                                              
                                                                             
                                                                          
                                                                     
let UI_LANG = (() => { try { return api.i18n.getUILanguage(); } catch (_) { return 'en'; } })();
                                                                          
                                                               
const T = (k, subs, fb) => { const v = globalThis.SSi18n && globalThis.SSi18n.t(k, subs); return v || fb || k; };
const R = globalThis.SSReasons;
const bidi = (s) => (R && R.bidiWrap ? R.bidiWrap(s) : (s == null ? '' : String(s)));
const send = (type, extra) => new Promise((res) => { try { api.runtime.sendMessage(Object.assign({ type }, extra || {}), (r) => res(r)); } catch (_) { res(null); } });
                                                                           
const SV = globalThis.SSStatsView, SSTATS = globalThis.SSStats;
let statsPeriod = '7', statsToken = 0;
                                                                                
let curTab = 'protection';
let currentReportUrl = '';
let defaultOtaUrl = '';
                                                                               
                                                                              
                                                                               
                                                             
function intlDate(opts) { try { return new Intl.DateTimeFormat(UI_LANG, opts); } catch (_) { return new Intl.DateTimeFormat('en', opts); } }
function num(n) { const v = Number(n) || 0; try { return v.toLocaleString(UI_LANG); } catch (_) { return String(v); } }
                                                                   
function stamp(ts) { try { return new Date(ts).toLocaleString(UI_LANG); } catch (_) { return new Date(ts).toLocaleString('en'); } }
function flash(t) { $('status').textContent = t; $('status').classList.add('show'); setTimeout(() => $('status').classList.remove('show'), 1200); }
function showTab(name, userInitiated) {
  curTab = name;
  for (const s of document.querySelectorAll('.tab')) s.hidden = s.id !== 'tab-' + name;
  for (const a of document.querySelectorAll('nav a')) {
    const cur = a.dataset.tab === name;
    a.classList.toggle('cur', cur); if (cur) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  try { history.replaceState(null, '', '#' + name); } catch (_) {}
  if (userInitiated) { const h = $('tab-' + name).querySelector('h2'); if (h) h.focus(); }
                                                                              
                                                                                
                                                                            
  if (name === 'stats') loadStats();
}
for (const a of document.querySelectorAll('nav a')) a.addEventListener('click', (e) => { e.preventDefault(); showTab(a.dataset.tab, true); });
$('brandmark').insertAdjacentHTML('afterbegin', '<img class="ic" src="assets/icons/icon32.png" alt="" width="16" height="16">');
                                                                            
                                                                      
function renderVersion() {
  try { const v = api.runtime.getManifest().version; $('ver').textContent = T('fmtVersion', [bidi(v)], 'Version ' + v); $('aboutver').textContent = v; } catch (_) {}
}
renderVersion();
                                                                         
                                                                           
                                                                            
                                                                    
                                                                              
                                                                      

const CHIPKEY = (k) => 'chip' + k.charAt(0).toUpperCase() + k.slice(1);
const KIND = (k) => T(CHIPKEY(k), null, F.detectorLabel(k));
const LEVELKEY = { safe: 'levelSafe', suspicious: 'levelSuspicious', dangerous: 'levelDangerous', unknown: 'levelUnknown' };
const LEVEL = (lvl) => T(LEVELKEY[lvl] || 'levelUnknown', null, F.levelText(lvl));
function bindSwitch(id, key) {
  const el = $(id); const wrap = el.closest('.switch');
  el.addEventListener('change', async () => {
                                                                          
                                                                             
                                                                          
                                                                           
                                                                            
                                                                          
                                                                         
                                             
    if (key === 'reportingOptIn') {
      const ok = await requestReportingConsent(el.checked);
      if (!ok) { el.checked = false; wrap.classList.remove('on'); return; }
    }
    await send('setSettings', { patch: { [key]: el.checked } }); wrap.classList.toggle('on', el.checked); flash(T('saved', null, 'Saved'));
  });
}
async function requestReportingConsent(turningOn) {
  if (turningOn && !currentReportUrl) { flash(T('reportRelayMissing', null, 'Set an HTTPS reporting URL in About before enabling reports.')); return false; }
  try {
    if (REVIEW && REVIEW.isChromeFromManifest(api.runtime.getManifest())) return true;
    if (!api.permissions || typeof api.permissions.getAll !== 'function') return true;
    const all = await api.permissions.getAll();
    if (!all || !Array.isArray(all.data_collection)) return true;                                    
    const dc = { data_collection: ['websiteActivity'] };
    if (!turningOn) { try { await api.permissions.remove(dc); } catch (_) {} return true; }
    if (all.data_collection.includes('websiteActivity')) return true;
    return (await api.permissions.request(dc)) === true;
  } catch (_) { return !turningOn; }
}
function setSwitch(id, on) { $(id).checked = !!on; $(id).closest('.switch').classList.toggle('on', !!on); }
                                                                           
                                                                               
                                                                               
                                                       
function syncHotSub() { $('hotsub').hidden = !$('block').checked; }
async function load() {
  const s = await send('getSettings');
  const feedDefaultResponse = await send('getDefaultFeedUrl');
  defaultOtaUrl = typeof feedDefaultResponse === 'string' ? feedDefaultResponse : (feedDefaultResponse && (feedDefaultResponse.url || feedDefaultResponse.value)) || '';
  if (!s) { flash(T('toastExtensionError', null, 'Extension error — try reopening.')); return; }
  setSwitch('enabled', s.enabled); setSwitch('block', s.blockKnownBad); setSwitch('hide', s.hideScamContent); setSwitch('pageanalysis', s.pageAnalysis !== false); setSwitch('report', s.reportingOptIn);
  setSwitch('clickfix', s.clickFixGuard !== false); setSwitch('fakeupdate', s.fakeUpdateGuard !== false);
  setSwitch('techscam', s.techScamGuard !== false); setSwitch('clipboard', s.clipboardGuard !== false);
  setSwitch('wallet', s.walletGuard !== false); setSwitch('strict', s.strictMode === true);
  setSwitch('leakyform', s.leakyFormGuard !== false); setSwitch('fingerprint', s.fingerprintDetect !== false); setSwitch('notifyguard', s.notificationGuard !== false);
  setSwitch('shop', s.shopGuard !== false); setSwitch('serp', s.serpCheck !== false);
  setSwitch('qrscan', s.qrAutoScan !== false);
  setSwitch('sync', s.syncEnabled === true);
  syncHotSub();
  $('net-feed').textContent = s.otaUrl ? (s.lastOtaAt ? F.relTime(s.lastOtaAt, undefined, UI_LANG) : T('receiptOnInstall12h', null, 'on install + every 12h')) : T('receiptDisabled', null, 'disabled');
  currentReportUrl = String(s.reportUrl || '');
  $('reporturl').value = currentReportUrl;
  let reportHost = ''; try { reportHost = new URL(currentReportUrl).hostname; } catch (_) {}
  $('net-report').textContent = !currentReportUrl ? T('receiptRelayNotConfigured', null, 'not configured; reports stay local') : (s.reportingOptIn ? `${T('receiptWhenFlagged', null, 'when flagged')} · ${reportHost}` : T('receiptOffDefault', null, 'off (default)'));
  $('otaurl').value = s.otaUrl && s.otaUrl !== defaultOtaUrl ? s.otaUrl : ''; $('theme').value = s.theme || 'auto';
                                                                            
                                                                            
  const lang = s.uiLang || 'auto';
  $('lang').value = R && R.LOCALES.includes(lang) ? lang : 'auto';
  if (s.lastOtaAt) {
    const relStr = F.relTime(s.lastOtaAt, undefined, UI_LANG);
    const countStr = num(s.lastOtaCount);
    $('feedstatus').textContent = T('fmtUpdatedRules', [bidi(relStr), bidi(countStr)], `Updated ${relStr} · ${countStr} rules`);
  } else {
    $('feedstatus').textContent = T('feedNeverUpdated', null, 'Never updated');
  }
  $('feeddot').classList.toggle('ok', !!s.lastOtaAt);
  renderAllow(s.allowlist || [], s.pausedSites || {}, s.allowlistMeta || {}, s.mutedWarnings || {});
                                                                            
                                                                            
                                                                         
                                                                             
                                                                              
                                                                         
                                                                            
  const hot = await send('getHotStatus');
  if (hot && !hot.enabled) {
    $('hotstatus').textContent = T('hotListOff', null, 'Hot list: off');
    $('hotdot').classList.remove('ok');
  } else if (!hot || !hot.updatedAt) {
                                                                             
                                                                             
                                                                             
                                                                      
    $('hotstatus').textContent = T('hotListPending', null, 'Hot list: not downloaded yet');
    $('hotdot').classList.remove('ok');
  } else {
    const hotAgo = F.relTime(hot.updatedAt, undefined, UI_LANG);
    const hotCount = num(hot.count);
    $('hotstatus').textContent = T('hotListStatus', [bidi(hotCount), bidi(hotAgo)], `Hot list: ${hotCount} sites, updated ${hotAgo}`);
    $('hotdot').classList.add('ok');
  }
                                                                             
                                                               
  const hotRej = $('hotrejected');
  if (hotRej) {
    hotRej.textContent = hot && hot.rejectReason ? T('optHotRejected', null, 'PhishGuard rejected the latest recent-risk list because its validation failed; the last accepted list remains active.') : '';
    hotRej.hidden = !(hot && hot.rejectReason);
  }
  const h = await send('getHistory'); renderHistory((h && h.history) || []);
}
function li(text, meta, btnText, onClick) {
  const el = document.createElement('li'); const t = document.createElement('span'); t.textContent = text; el.appendChild(t);
  if (meta) { const m = document.createElement('span'); m.className = 'meta'; m.textContent = meta; el.appendChild(m); }
  if (btnText) { const b = document.createElement('button'); b.className = 'btn'; b.textContent = btnText; b.addEventListener('click', onClick); el.appendChild(b); }
  return el;
}
                                                                           
                                                                            
                                                                       
                                                                          
function tenantApexBadge(el, d) {
  if (!(SS.isTenantApex && SS.isTenantApex(d))) return el;
  const tag = document.createElement('span'); tag.className = 'tag warn'; tag.dataset.tenantApex = '1';
  tag.textContent = T('optTenantApexBadge', [bidi(d)], 'Covers every site on ' + d + ' — remove it and trust the specific site instead');
  const btn = el.querySelector('button');
  if (btn) el.insertBefore(tag, btn); else el.appendChild(tag);
  return el;
}
                                                                        
                                                                        
                                                                            
                                                                      
                                                                 
                                                                 
function allowLi(d, meta) {
  const el = document.createElement('li');
  el.dataset.domain = d;
  const t = document.createElement('span'); t.textContent = d; el.appendChild(t);
  if (meta && meta.via) {
    const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = T('trustedViaWarning', null, 'Trusted via warning');
    el.appendChild(tag);
  }
  const b = document.createElement('button'); b.className = 'btn remove'; b.textContent = T('remove', null, 'Remove');
  b.addEventListener('click', async () => { await send('removeAllow', { domain: d }); load(); });
  el.appendChild(b);
  return tenantApexBadge(el, d);
}
function renderAllow(list, paused, meta, muted) {
  $('allowlist').replaceChildren(); $('pausedlist').replaceChildren();
  if (!list.length) $('allowlist').appendChild(li(T('optNoneYet', null, 'None yet')));
  for (const d of list) $('allowlist').appendChild(allowLi(d, (meta || {})[d]));
  const entries = Object.entries(paused);
  if (!entries.length) $('pausedlist').appendChild(li(T('optNoneRightNow', null, 'None right now')));
  for (const [d, until] of entries) {
    const whenStr = intlDate({ hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' }).format(new Date(until));
    $('pausedlist').appendChild(tenantApexBadge(li(d, T('fmtUntilTime', [bidi(whenStr)], 'until ' + whenStr), T('resumeNow', null, 'Resume now'), async () => { await send('unpauseSite', { domain: d }); load(); }), d));
  }
  renderMuted(muted || {});
}
                                                                         
                                                                          
                                                                             
const MUTE_KIND = (k) => T('muteKind_' + k, null, { clipboard: 'Clipboard notices', leak: 'Form-leak warnings', notify: 'Notification-lure warnings', credpost: 'Card and password form warnings' }[k] || k);
function renderMuted(muted) {
  $('mutedlist').replaceChildren(); const rows = SS.listMuted(muted);
  if (!rows.length) { $('mutedlist').appendChild(li(T('optNoneYet', null, 'None yet'))); return; }
  for (const r of rows) $('mutedlist').appendChild(tenantApexBadge(li(r.domain, `${MUTE_KIND(r.kind)} · ${stamp(r.at)}`, T('warnAgain', null, 'Warn again'), async () => { await send('unmuteWarning', { domain: r.domain, kind: r.kind }); load(); }), r.domain));
}
function renderHistory(list) {
  $('history').replaceChildren();
  if (!list.length) { $('history').appendChild(li(T('optNothingYetGood', null, 'No recent events.'))); return; }
  for (const e of list.slice(0, 200)) $('history').appendChild(li(`${KIND(e.kind)} · ${e.host || T('unknownSite', null, 'unknown site')}`, `${LEVEL(e.level)} · ${stamp(e.ts)}`, T('markMistake', null, 'Mark as mistake'), async () => { const r = await send('userReport', { host: e.host, level: e.level }); flash(r && r.via === 'relay' ? T('toastThanksSent', null, 'Thanks — sent') : T('toastThanksNoted', null, 'Saved on this device; nothing was sent.')); }));
}
$('block').addEventListener('change', syncHotSub);
bindSwitch('enabled', 'enabled'); bindSwitch('block', 'blockKnownBad'); bindSwitch('hide', 'hideScamContent'); bindSwitch('pageanalysis', 'pageAnalysis'); bindSwitch('report', 'reportingOptIn');
bindSwitch('clickfix', 'clickFixGuard'); bindSwitch('fakeupdate', 'fakeUpdateGuard'); bindSwitch('techscam', 'techScamGuard'); bindSwitch('clipboard', 'clipboardGuard'); bindSwitch('wallet', 'walletGuard'); bindSwitch('strict', 'strictMode');
bindSwitch('leakyform', 'leakyFormGuard'); bindSwitch('fingerprint', 'fingerprintDetect'); bindSwitch('notifyguard', 'notificationGuard');
bindSwitch('shop', 'shopGuard'); bindSwitch('serp', 'serpCheck');
bindSwitch('qrscan', 'qrAutoScan');
$('sync').addEventListener('change', async () => { const r = await send('setSync', { on: $('sync').checked }); $('sync').closest('.switch').classList.toggle('on', $('sync').checked); flash($('sync').checked ? (r && r.ok ? T('toastSyncOn', null, 'Sync on') : T('toastSyncUnavailable', null, 'Sync unavailable')) : T('toastSyncOff', null, 'Sync off')); });
$('exportbtn').addEventListener('click', async () => {
  const data = await send('exportSettings');
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'phishguard-settings.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000); flash(T('toastExported', null, 'Exported'));
});
$('importbtn').addEventListener('click', () => $('importfile').click());
$('importfile').addEventListener('change', async () => {
  const f = $('importfile').files[0]; if (!f) return;
  try { const obj = JSON.parse(await f.text()); const r = await send('importSettings', { data: obj }); flash(r && r.ok ? T('toastImported', null, 'Imported') : T('toastInvalidFile', null, 'Invalid file')); load(); }
  catch (_) { flash(T('toastInvalidFile', null, 'Invalid file')); }
  $('importfile').value = '';
});
$('save-report-url').addEventListener('click', async () => {
  const raw = $('reporturl').value.trim();
  let normalized = '';
  if (raw) {
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('Invalid relay URL');
      normalized = parsed.href;
    } catch (_) { flash(T('reportRelayInvalid', null, 'Enter a valid HTTPS URL without credentials, query or fragment.')); return; }
  }
  const changed = normalized !== currentReportUrl;
  const patch = { reportUrl: normalized };
  if (changed || !normalized) patch.reportingOptIn = false;
  const saved = await send('setSettings', { patch });
  if (!saved) { flash(T('toastExtensionError', null, 'Could not update browser settings.')); return; }
  currentReportUrl = normalized;
  $('reporturl').value = normalized;
  if (changed || !normalized) setSwitch('report', false);
  flash(T('reportRelaySaved', null, 'Relay saved. Reports remain off until you enable them.'));
  load();
});

$('whatsent').addEventListener('click', () => { $('whatsentbody').hidden = !$('whatsentbody').hidden; });
$('theme').addEventListener('change', async () => { await send('setSettings', { patch: { theme: $('theme').value } }); globalThis.SSTheme.applyTheme($('theme').value); flash(T('saved', null, 'Saved')); });

                                                                              
                                                                             
                                                                           
                                                                         
                                                                          
                                                               
                                                                              
function buildLangOptions() {
  const sel = $('lang');
                                                                               
                                                                               
                                                                   
  const prev = sel.value;
  const opts = [];
                                                                              
                                                              
  const auto = document.createElement('option');
  auto.value = 'auto';
                                                                                
                                                      
  const tag = String(UI_LANG).replace('-', '_');
  const names = (R && R.LANG_NAMES) || {};
  const own = names[tag] || names[tag.split('_')[0]];
  const autoLabel = T('optLangAuto', null, 'Browser default');
  auto.textContent = own ? `${autoLabel} (${own})` : autoLabel;
  opts.push(auto);
  for (const code of (R ? R.LOCALES : [])) {
    const o = document.createElement('option');
    o.value = code; o.textContent = R.LANG_NAMES[code] || code;
    opts.push(o);
  }
  sel.replaceChildren(...opts);
  if (prev) sel.value = prev;
}
buildLangOptions();
                                                                              
                                                                               
                                                                  
$('lang').addEventListener('change', async () => {
  await send('setSettings', { patch: { uiLang: $('lang').value } });
  location.reload();
});

$('otaurl').addEventListener('change', async () => { await send('setSettings', { patch: { otaUrl: $('otaurl').value.trim() } }); flash(T('saved', null, 'Saved')); });
$('checkupd').addEventListener('click', async () => { flash(T('toastCheckingUpdates', null, 'Checking…')); const r = await send('checkForUpdates'); flash(r && r.ok ? (r.updated ? T('fmtUpdatedToVersion', [bidi(r.version)], 'Updated to v' + r.version) : T('toastAlreadyUpToDate', null, 'Already up to date')) : T('toastUpdateFailed', null, 'Update failed')); load(); });
$('clearhist').addEventListener('click', async () => { await send('clearHistory'); renderHistory([]); flash(T('toastHistoryCleared', null, 'History cleared')); });
$('resetfeed').addEventListener('click', async () => { const d = await send('getDefaultFeedUrl'); if (!d || !d.url) return; await send('setSettings', { patch: { otaUrl: d.url } }); $('otaurl').value = ''; flash(T('saved', null, 'Saved')); });

                                                                              
                                                                           
                                                                            
                                                  
                                                                              
const CAT_EN = { phishing: 'Phishing', fakeShop: 'Fake shop', wallet: 'Wallet drainer', techSupport: 'Tech-support', clipboard: 'Clipboard', clickfix: 'Fake CAPTCHA', fakeUpdate: 'Fake update', other: 'Other' };
const CAT = (k) => T('statsCat' + k.charAt(0).toUpperCase() + k.slice(1), null, CAT_EN[k] || k);
const CHART_TITLE_EN = { statsChartTitle7d: 'Pages checked · last 7 days', statsChartTitle30d: 'Pages checked · last 30 days', statsChartTitleAll: 'Pages checked · since install', statsChartTitle90d: 'Pages checked · last 90 days' };
                                                                                
                                                                             
function dayMs(key) { const t = Date.parse(key + 'T00:00:00Z'); return Number.isFinite(t) ? t : null; }
function dayText(key) { const t = dayMs(key); return t == null ? key : intlDate({ day: 'numeric', month: 'short', timeZone: 'UTC' }).format(t); }
function barRangeText(bar) {
  if (!bar || bar.days <= 1) return dayText(bar && bar.to);
  const a = dayMs(bar.from), b = dayMs(bar.to);
  if (a == null || b == null) return dayText(bar.to);
  const f = intlDate({ day: 'numeric', month: 'short', timeZone: 'UTC' });
  try { return f.formatRange(a, b); } catch (_) { return f.format(a) + ' – ' + f.format(b); }
}
function barTip(bar) {
  const d = bidi(barRangeText(bar)), c = bidi(num(bar.checked));
  if (bar.threats === 1) return T('fmtStatsBarTipThreat', [d, c], `${d} · ${c} pages checked · 1 threat stopped`);
  if (bar.threats > 1) { const t = bidi(num(bar.threats)); return T('fmtStatsBarTipThreats', [d, c, t], `${d} · ${c} pages checked · ${t} threats stopped`); }
  return T('fmtStatsBarTip', [d, c], `${d} · ${c} pages checked`);
}
function renderBars(ser) {
  const wrap = $('st-bars'); wrap.replaceChildren();
  const hs = SV.heights(ser.bars);
  ser.bars.forEach((bar, i) => {
    const b = document.createElement('div'); b.className = 'b' + (bar.threats > 0 ? ' hit' : '');
    const tip = document.createElement('span'); tip.className = 'tip'; tip.textContent = barTip(bar);
    const fill = document.createElement('i'); fill.style.height = hs[i] + '%';
    b.append(tip, fill); wrap.appendChild(b);
  });
}
function renderCats(byType) {
  const wrap = $('st-cats'); wrap.replaceChildren();
  for (const row of SV.catRows(byType)) {
    const el = document.createElement('div'); el.className = 'cat';
    const label = document.createElement('span'); label.textContent = CAT(row.key);
    const track = document.createElement('div'); track.className = 'track';
    const fill = document.createElement('div'); fill.className = 'fill'; fill.style.width = row.pct + '%';
    track.appendChild(fill);
    const n = document.createElement('b'); n.textContent = num(row.count);
    el.append(label, track, n); wrap.appendChild(el);
  }
}
                                                                        
                                                                           
                                                                          
                                          
function pillFor(level) {
  if (level === 'dangerous') return { cls: 'danger', text: T('statsPillBlocked', null, 'Blocked') };
  if (level === 'suspicious') return { cls: 'warn', text: T('statsPillWarned', null, 'Warned') };
  return { cls: 'info', text: T('chipPrivacy', null, 'Data exposure and tracking') };
}
function renderStatsRecent(list) {
  const ul = $('st-recent'); ul.replaceChildren();
  if (!list.length) {
    const li = document.createElement('li'); const s = document.createElement('span'); s.className = 'host';
    s.textContent = T('optNothingYetGood', null, 'No recent events.'); li.appendChild(s); ul.appendChild(li); return;
  }
  for (const e of list.slice(0, 3)) {
    const li = document.createElement('li');
    const p = pillFor(e.level); const pill = document.createElement('span'); pill.className = 'pill ' + p.cls; pill.textContent = p.text;
    const host = document.createElement('span'); host.className = 'host'; host.textContent = e.host || T('unknownSite', null, 'unknown site');
    const time = document.createElement('time'); time.textContent = F.relTime(e.ts, undefined, UI_LANG);
    li.append(pill, host, time); ul.appendChild(li);
  }
}
function renderStats(st, hist) {
  const daily = st.statsDaily || [];
  const now = Date.now();
  const ser = SV.series(daily, statsPeriod, now, Number(st.installedAt) || now);
  const sums = SSTATS.summarize(daily, ser.days, now);
                                                                               
                                                                              
                                                        
  const all = statsPeriod === 'all';
  const checked = all ? Number(st.pagesCheckedTotal) || 0 : sums.checked;
  const threats = all ? Number(st.threatsBlocked) || 0 : sums.threats;
  const privacy = all ? Number(st.privacyFindingsTotal) || 0 : sums.privacy;

                                                                               
                                                                
  const installedAt = Number(st.installedAt) > 0 ? Number(st.installedAt) : now;
  const sinceStr = intlDate({ day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(installedAt));
  $('statssince').textContent = T('fmtStatsSince', [bidi(sinceStr)], 'Protecting this browser since ' + sinceStr);
  $('st-checked').textContent = num(checked);
  $('st-threats').textContent = num(threats);
  $('st-privacy').textContent = num(privacy);
  $('st-rules').textContent = num(st.feedRuleCount);
  $('st-threats-tile').classList.toggle('zero', threats === 0);
  $('st-threats-sub').textContent = threats === 0
    ? T('statsThreatsNone', null, 'No threats recorded in this period.')
    : threats === 1
      ? T('statsScamsBlockedOne', null, '1 high-risk event blocked in this period')
      : T('fmtStatsScamsBlocked', [bidi(num(threats))], num(threats) + ' high-risk events blocked in this period');

  const titleKey = statsPeriod === '7' ? 'statsChartTitle7d'
    : statsPeriod === '30' ? 'statsChartTitle30d'
      : ser.clamped ? 'statsChartTitle90d' : 'statsChartTitleAll';
  const title = T(titleKey, null, CHART_TITLE_EN[titleKey]);
  $('st-charttitle').textContent = title;
  $('st-axstart').textContent = dayText(ser.from);
  renderBars(ser);
                                                                             
                                                                          
  $('st-bars').setAttribute('aria-label', title);
  renderCats(st.threatsByType);
  renderStatsRecent(hist);
}
async function renderLocalFeedback() {
  const list = $('localfeedback');
  if (!list) return;
  list.replaceChildren();
  let rows = [];
  try {
    const saved = await api.storage.local.get('localFeedback');
    rows = Array.isArray(saved.localFeedback) ? saved.localFeedback : [];
  } catch (_) {}
  if (!rows.length) {
    const li = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = T('localFeedbackEmpty', null, 'No locally saved feedback.');
    li.appendChild(label);
    list.appendChild(li);
    return;
  }
  for (const item of rows.slice(-10).reverse()) {
    const li = document.createElement('li');
    const label = document.createElement('span');
    const verdict = item.label === 'scam' ? T('reportScam', null, 'Reported as scam') : T('reportSafe', null, 'Marked as safe');
    let when = '';
    if (Number.isFinite(Number(item.at))) {
      try { when = new Date(Number(item.at)).toLocaleString(UI_LANG); } catch (_) {}
    }
    label.textContent = `${String(item.host || T('unknownSite', null, 'unknown site'))} — ${verdict}${when ? ' · ' + when : ''}`;
    li.appendChild(label);
    list.appendChild(li);
  }
}
$('clearlocalfeedback')?.addEventListener('click', async () => {
  try {
    await api.storage.local.set({ localFeedback: [] });
    await renderLocalFeedback();
    flash(T('localFeedbackCleared', null, 'Local feedback cleared.'));
  } catch (_) { flash(T('toastExtensionError', null, 'Could not update browser storage.')); }
});

async function loadStats() {
  const token = ++statsToken;
  const [st, h] = await Promise.all([send('getStats'), send('getHistory')]);
  if (token !== statsToken) return;                                         
  if (!st) { flash(T('toastExtensionError', null, 'Extension error — try reopening.')); return; }
  renderStats(st, (h && h.history) || []);
}
for (const b of document.querySelectorAll('#statsseg button')) {
  b.addEventListener('click', () => {
    statsPeriod = b.dataset.p;
    for (const x of document.querySelectorAll('#statsseg button')) {
      const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-pressed', String(on));
    }
    loadStats();
  });
}

renderLocalFeedback();
showTab((location.hash || '#protection').slice(1).replace(/[^a-z]/g, '') || 'protection');
load();
                                                                             
                                                                         
                                                                          
                                                                              
                                                                          
try {
  globalThis.SSi18n.ready.then((lang) => {
    if (!lang) return;
                                                                            
                                                                              
                                                                            
    UI_LANG = R.intlTag(lang);
    renderVersion();
    buildLangOptions();
    load();
    if (curTab === 'stats') loadStats();
  });
} catch (_) {                                                                    }
