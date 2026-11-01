                                                         
  
                                                                                   
                                                                              
                                                                         
                                                                                
                                                 
  
                                                                             
                                                                       
                                                                        
                                                                 
'use strict';
const api = globalThis.browser || globalThis.chrome;
const SS = globalThis.PhishGuard, I = globalThis.SSIcons, R = globalThis.SSReasons, i18n = globalThis.SSi18n;
const $ = (id) => document.getElementById(id);
const T = (key, subs, fallback) => { try { const v = i18n && i18n.t ? i18n.t(key, subs) : ''; return v || fallback; } catch (_) { return fallback; } };
const bidi = (s) => '⁨' + s + '⁩';
                                                                                                 
const registrable = (h) => (SS && SS.scopeDomain) ? SS.scopeDomain(h) : (SS && SS.registrableDomain) ? SS.registrableDomain(h) : String(h || '').split('.').slice(-2).join('.');
const send = (type, data) => new Promise((resolve) => { try { api.runtime.sendMessage(Object.assign({ type }, data || {}), (r) => resolve(r || null)); } catch (_) { resolve(null); } });

function blockedUrl() {
  let raw = location.hash.slice(1);
  try { raw = decodeURIComponent(raw); } catch (_) {}
  try { const u = new URL(raw); if (/^https?:$/.test(u.protocol)) return u; } catch (_) {}
  return null;
}
const target = blockedUrl();
const host = target ? target.hostname : '';
const domain = host ? registrable(host) : '';

function render(info) {
  try { $('hico').innerHTML = I && I.shield ? I.shield('dangerous') : ''; } catch (_) {}
  $('url').textContent = target ? target.href : '';
  if (host) {
                                                                           
                                                                            
                                                                           
                                                                             
                                                   
    $('lead').textContent = (info && info.kind === 'hot')
      ? T('blockedLeadHot', [bidi(host)], host + ' was reported for phishing in the last two days, so the page was stopped before it could load. Nothing ran and nothing you typed was sent.')
      : T('blockedLead', [bidi(host)], host + " is on PhishGuard's list of known scam and malicious sites, so the page was stopped before it could load. Nothing ran and nothing you typed was sent.");
  }
  const sources = info && Array.isArray(info.sources) ? info.sources.filter((s) => typeof s === 'string' && s) : [];
  if (sources.length) { $('src').removeAttribute('data-i18n'); $('src').textContent = T('blockedListedBy', [bidi(sources.slice(0, 4).join(', '))], 'Listed by ' + sources.slice(0, 4).join(', ')); }
}

$('back').addEventListener('click', async () => {
  if (history.length > 1) { history.back(); return; }
  try { const t = await api.tabs.getCurrent(); if (t && t.id != null) { await api.tabs.remove(t.id); return; } } catch (_) {}
  location.href = api.runtime.getURL('onboarding.html');
});
$('copy').addEventListener('click', async () => {
  const hostText = bidi(R && R.defangHost ? R.defangHost(host) : host);
  const lvl = T('levelDangerous', null, 'High-risk activity detected');
  const text = [
    T('copyReportHeader', [hostText], '⚠ PhishGuard flagged this site: ' + host),
    T('copyReportVerdict', [lvl], 'Verdict: ' + lvl),
    T('blockedListedGeneric', null, "Listed in PhishGuard's block list of confirmed scam domains."),
    T('copyReportFooter', null, 'Checked locally by PhishGuard. Review the evidence before acting.')
  ].join('\n');
  try { await navigator.clipboard.writeText(text); $('copy').textContent = T('toastCopied', null, 'Copied'); } catch (_) {}
});
                                                                             
                                                                  
if (domain && SS && SS.isTenantApex && SS.isTenantApex(domain)) { for (const id of ['visit', 'trust']) { const b = $(id); if (b) b.hidden = true; } }
$('visit').addEventListener('click', async (e) => {
  e.preventDefault();
  if (!target || !domain) return;
                                                                             
                                                                         
  await send('pauseSite', { domain, choice: '1h' });
  location.replace(target.href);
});
                                                                          
                                                                            
                                                                        
                                                                         
                                                                          
                                                                            
                                                     
$('trust').addEventListener('click', async (e) => {
  e.preventDefault();
  if (!target || !domain) return;
  await send('trustSite', { domain, via: 'blocked' });
  location.replace(target.href);
});

(async () => {
  if (i18n && i18n.ready) { try { await i18n.ready; } catch (_) {} }
  render(null);
  if (!target) return;
  const info = await send('dnrBlocked', { url: target.href });
  render(info);
})();
