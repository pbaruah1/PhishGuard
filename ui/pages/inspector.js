'use strict';
const api = globalThis.browser || globalThis.chrome;
const SS = globalThis.PhishGuard;
const R = globalThis.SSReasons;
const $ = (id) => document.getElementById(id);
const query = new URLSearchParams(location.search);
const tabId = Number(query.get('tabId'));
const state = { pageUrl: query.get('pageUrl') || query.get('url') || '', latest: null };

async function extensionCall(method, args, fallback) {
  try {
    const result = method.apply(null, args);
    if (result && typeof result.then === 'function') return await result;
    if (result !== undefined) return result;
  } catch (_) {}
  if (typeof fallback !== 'function') return null;
  return new Promise((resolve) => {
    try { method.apply(null, [...args, (value) => resolve(value)]); }
    catch (_) { resolve(null); }
  });
}
function send(type, extra) {
  return extensionCall(api.runtime.sendMessage.bind(api.runtime), [Object.assign({ type }, extra || {})], null);
}
async function storageGet(key) {
  const value = await extensionCall(api.storage.local.get.bind(api.storage.local), [key]);
  return value && value[key] || '';
}
async function storageSet(key, value) {
  try {
    const result = await extensionCall(api.storage.local.set.bind(api.storage.local), [{ [key]: value }]);
    return result !== null;
  } catch (_) { return false; }
}
function evidenceItem(item) {
  const li = document.createElement('li'); li.className = item.severity || 'info';
  const title = document.createElement('strong'); title.textContent = item.title || 'Analysis evidence';
  const detail = document.createElement('span'); detail.textContent = item.detail || '';
  li.append(title, detail); return li;
}
function render(level, score, summary, items, technical) {
  $('result').hidden = false;
  $('result').dataset.level = level || 'unknown';
  $('level').textContent = ({ dangerous: 'High risk', suspicious: 'Needs caution', safe: 'No strong risk evidence found', unknown: 'Unable to assess' })[level] || 'Unable to assess';
  $('summary').textContent = summary || '';
  const value = Math.round(Math.max(0, Math.min(1, Number(score) || 0)) * 100);
  $('score').textContent = value + '/100';
  $('meter-fill').style.width = value + '%';
  $('evidence').replaceChildren();
  (items && items.length ? items : [{ title: 'No decisive indicators found', detail: 'The supplied sample did not provide enough evidence for a strong classification. This is not proof of authenticity or safety.', severity: 'info' }]).slice(0, 12).forEach((item) => $('evidence').appendChild(evidenceItem(item)));
  $('technical').textContent = technical ? JSON.stringify(technical, null, 2) : '';
}
function fallbackReason(reason) {
  try { return R && R.resolveReason ? R.resolveReason(reason) : reason.code; } catch (_) { return reason.code || 'Detection rule'; }
}
function explainResult(result) {
  const evidence = Array.isArray(result.evidence) ? result.evidence.slice() : [];
  if (!evidence.length) {
    for (const reason of (result.reasons || [])) evidence.push({ code: reason.code, title: 'Detection rule', detail: fallbackReason(reason), severity: result.level === 'dangerous' ? 'critical' : 'warning' });
  }
  return evidence;
}
function addText(parent, tag, text, className) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = text == null ? '' : String(text);
  parent.appendChild(el);
  return el;
}
function renderMonitor(monitor, sourceLabel) {
  const panel = $('monitor-panel');
  if (!monitor || typeof monitor !== 'object') { panel.hidden = true; return; }
  panel.hidden = false;
  const frames = Array.isArray(monitor.frames) ? monitor.frames : [];
  const elementCount = Number(monitor.totalFrameElements ?? monitor.elementCount ?? 0);
  const interactiveCount = Number(monitor.totalFrameInteractive ?? monitor.interactiveCount ?? 0);
  const frameCount = Math.max(1, Number(monitor.frameCountObserved || frames.length || 1));
  $('monitor-summary').textContent = `${sourceLabel || 'Local browser snapshot'} · ${elementCount.toLocaleString()} DOM elements observed across ${frameCount} permitted frame(s). Inventory is bounded to protect browser performance.`;
  const stats = $('monitor-stats');
  stats.replaceChildren();
  const metricItems = [
    ['DOM elements', elementCount], ['Interactive controls', interactiveCount],
    ['Forms', monitor.formCount || 0], ['Links', monitor.linkCount || 0],
    ['Scripts', monitor.scriptCount || 0], ['Frames', monitor.iframeCount || frames.length || 0],
    ['Open shadow roots', monitor.openShadowRootCount || 0], ['DOM changes', monitor.mutationCount || 0]
  ];
  for (const [label, value] of metricItems) {
    const item = document.createElement('div'); item.className = 'monitor-metric';
    addText(item, 'strong', Number(value).toLocaleString()); addText(item, 'span', label); stats.appendChild(item);
  }
  const frameBox = $('monitor-frames'); frameBox.replaceChildren();
  for (const frame of frames.slice(0, 50)) {
    addText(frameBox, 'p', `Frame ${frame.frameId ?? '—'} · ${frame.url || 'unavailable'} · ${frame.inventory && frame.inventory.elementCount || frame.elementCount || 0} elements · ${frame.inventory && frame.inventory.interactiveCount || frame.interactiveCount || 0} controls`);
  }
  if (!frames.length) addText(frameBox, 'p', 'No child-frame snapshot has been received yet. The current frame is still monitored locally.');
  const formsBox = $('monitor-forms'); formsBox.replaceChildren();
  const forms = Array.isArray(monitor.forms) ? monitor.forms : [];
  for (const form of forms.slice(0, 100)) {
    const row = document.createElement('div'); row.className = 'monitor-row';
    addText(row, 'strong', `${form.method || 'GET'} form → ${form.actionHost || 'same page'}`);
    addText(row, 'span', `${form.fieldCount || 0} field(s) · password: ${form.hasPassword ? 'yes' : 'no'} · payment-like field: ${form.hasPaymentField ? 'yes' : 'no'}`);
    formsBox.appendChild(row);
  }
  if (!forms.length) addText(formsBox, 'p', 'No forms detected in the available inventory.');
  const elementsBox = $('monitor-elements'); elementsBox.replaceChildren();
  const details = Array.isArray(monitor.elementDetails) ? monitor.elementDetails : [];
  for (const item of details.slice(0, 120)) {
    const row = document.createElement('div'); row.className = 'monitor-row';
    addText(row, 'strong', `<${item.tag || 'element'}>${item.id ? '#' + item.id : ''}${item.role ? ' · role=' + item.role : ''}${item.type ? ' · type=' + item.type : ''}`);
    addText(row, 'span', [item.hrefHost ? 'link→' + item.hrefHost : '', item.srcHost ? 'resource→' + item.srcHost : '', item.actionHost ? 'form→' + item.actionHost : '', item.hidden ? 'hidden' : '', item.disabled ? 'disabled' : '', item.required ? 'required' : ''].filter(Boolean).join(' · ') || 'No notable attributes');
    elementsBox.appendChild(row);
  }
  if (monitor.elementDetailsTruncated || monitor.inventoryTruncated) addText(elementsBox, 'p', 'Detailed element rows are capped; the full scanned element count and per-tag counts remain available. A 5,000-element scan cap may also apply.');
  const security = Array.isArray(monitor.securityAttributeFindings) ? monitor.securityAttributeFindings : [];
  for (const item of security.slice(0, 30)) addText(elementsBox, 'p', `${item.tag || 'element'} · ${item.hrefScheme || 'attribute'} · ${item.srcHost || ''} ${item.targetBlankWithoutNoopener ? ' · new tab without noopener' : ''}`, 'monitor-warning');
  if (!details.length && !security.length) addText(elementsBox, 'p', 'No element details were supplied by this scan.');
  const activityBox = $('monitor-activity'); activityBox.replaceChildren();
  const activity = Array.isArray(monitor.recentActivity) ? monitor.recentActivity : [];
  for (const item of activity.slice(-40).reverse()) {
    const when = item.at ? new Date(item.at).toLocaleTimeString() : '—';
    addText(activityBox, 'p', `${when} · ${item.type || 'interaction'} · ${item.tag || 'page element'}${item.destinationHost ? ' · destination ' + item.destinationHost : ''}${item.formActionHost ? ' · form target ' + item.formActionHost : ''}`);
  }
  const counts = monitor.activityCounts || {};
  if (!activity.length) addText(activityBox, 'p', `Interaction counts: ${Object.entries(counts).map(([key, value]) => `${key} ${value}`).join(' · ') || 'none recorded yet'}`);
}
async function inspectSample() {
  const input = $('sample').value.trim();
  if (!input) { render('unknown', 0, 'Paste a message or URL to begin.', [], null); return; }
  $('inspect').disabled = true;
  try {
    const base = SS.scoreMessage(input);
    const enriched = await SS.enrichMessageReputation(base, (host) => send('checkFeed', { host }), 1600);
    state.latest = enriched;
    const links = (enriched.links || []).length;
    const checked = enriched.reputation ? enriched.reputation.hostsChecked : 0;
    const summary = `${links} link(s) extracted; ${checked} host reputation check(s) completed. A missing feed match is not a safe verdict.`;
    render(enriched.level, enriched.score, summary, explainResult(enriched), { signals: enriched.signals, links: enriched.links, reputation: enriched.reputation });
  } catch (error) {
    render('unknown', 0, 'The message analysis failed. Try a shorter sample.', [{ title: 'Analysis error', detail: String(error && error.message || error), severity: 'warning' }], null);
  } finally { $('inspect').disabled = false; }
}
async function inspectCurrentPage() {
  $('mode-label').textContent = 'Reading the analysis from the active page';
  let page = null;
  if (Number.isInteger(tabId) && tabId > 0 && api.tabs && api.tabs.sendMessage) {
    page = await extensionCall(api.tabs.sendMessage.bind(api.tabs), [tabId, { type: 'getPageAnalysis' }]);
  }
  if (page) {
    const v = page.verdict || { level: 'unknown', score: 0, reasons: [] };
    const evidence = [];
    for (const r of (v.reasons || [])) evidence.push({ title: 'Page detection', detail: fallbackReason(r), severity: v.level === 'dangerous' ? 'critical' : 'warning' });
    const dl = page.evidence && page.evidence.downloads;
    if (dl && Array.isArray(dl.evidence)) evidence.push(...dl.evidence);
    render(v.level, v.score, `${page.title || 'Current page'} · ${page.url || state.pageUrl}`, evidence, page.evidence || v);
    renderMonitor(page.monitor, 'Live page · on-device inventory');
    return;
  }
  const v = await send('getVerdict', { tabId });
  if (v) {
    render(v.level, v.score, state.pageUrl || 'Page verdict was retrieved from the extension background worker.', (v.reasons || []).map((r) => ({ title: 'Page detection', detail: fallbackReason(r), severity: v.level === 'dangerous' ? 'critical' : 'warning' })), v);
  } else {
    render('unknown', 0, 'No page analysis result is available. Refresh the page with PhishGuard enabled, then try again.', [], null);
  }
}
const cloudApiUrl = String((globalThis.PHISHGUARD_CLOUD_CONFIG && globalThis.PHISHGUARD_CLOUD_CONFIG.apiUrl) || '').replace(/\/$/, '');
function setCloudStatus(text, ready) {
  $('service-status').textContent = text;
  $('service-status').classList.toggle('ready', !!ready);
}
async function checkService() {
  if (!cloudApiUrl || !/^https:\/\//i.test(cloudApiUrl)) {
    setCloudStatus('Not configured', false);
    $('cloud-help').textContent = 'Remote inspection is not available in this release. Local page protection remains active.';
    $('deep-inspect').disabled = true;
    return false;
  }
  try {
    const response = await fetch(cloudApiUrl + '/v1/health', { method: 'GET', cache: 'no-store' });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    const ready = !!data.ready;
    setCloudStatus(ready ? 'Available' : 'Unavailable', ready);
    $('cloud-help').textContent = ready ? 'Hosted browser verification is ready.' : 'The hosted browser service is not ready.';
    $('deep-inspect').disabled = !ready;
    return ready;
  } catch (error) {
    setCloudStatus('Unavailable', false);
    $('cloud-help').textContent = 'The hosted browser service could not be reached. Live on-device analysis continues to work.';
    $('deep-inspect').disabled = true;
    return false;
  }
}
function destinationForDeepScan() {
  let value = '';
  if (state.pageUrl && /^https?:/i.test(state.pageUrl)) value = state.pageUrl;
  else {
    const found = SS.extractMessageLinks($('sample').value);
    value = found.length ? found[0].url : '';
  }
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    url.username = ''; url.password = ''; url.search = ''; url.hash = '';
    return url.href;
  } catch (_) { return ''; }
}
async function runDeepScan() {
  const url = destinationForDeepScan();
  if (!url) { render('unknown', 0, 'No HTTP or HTTPS destination was found. Paste one full public URL first.', [], null); return; }
  if (!cloudApiUrl || !await checkService()) {
    render('unknown', 0, 'Hosted Playwright inspection is not configured or currently unavailable. Local page monitoring remains active.', [], null);
    return;
  }
  $('deep-inspect').disabled = true;
  $('deep-inspect').textContent = 'Inspecting in hosted Chromium…';
  try {
    const response = await fetch(cloudApiUrl + '/v1/analyze', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'HTTP ' + response.status);
    const evidence = (data.evidence || []).map((item, index) => ({
      title: typeof item === 'string' ? (index === 0 ? 'Headless page inspection' : 'Additional evidence') : (item.title || 'Additional evidence'),
      detail: typeof item === 'string' ? item : item.detail,
      severity: typeof item === 'object' ? item.severity : 'warning'
    }));
    render(data.level, data.score, `${data.title || data.finalUrl} · ${data.httpStatus == null ? 'No final response status' : 'HTTP ' + data.httpStatus} · ${data.requestCount} network request(s) observed.`, evidence, data);
    const hosted = Object.assign({}, data.inventory || {}, { frames: data.frames || [], frameCountObserved: (data.frames || []).length,
      totalFrameElements: data.inventory && data.inventory.elementCount || 0,
      totalFrameInteractive: data.inventory && data.inventory.interactiveCount || 0 });
    renderMonitor(hosted, 'Hosted public-URL scan · isolated Chromium');
    setCloudStatus('Available', true);
  } catch (error) {
    render('unknown', 0, 'Hosted Playwright inspection could not complete. The URL may be private, blocked by network-safety checks, or unavailable.', [{ title: 'Deep scan error', detail: String(error && error.message || error), severity: 'warning' }], null);
    setCloudStatus('Unavailable', false);
  } finally {
    $('deep-inspect').textContent = 'Deep inspect with hosted Playwright';
    $('deep-inspect').disabled = !cloudApiUrl;
  }
}

$('refresh-page').addEventListener('click', inspectCurrentPage);
$('inspect').addEventListener('click', inspectSample);
$('deep-inspect').addEventListener('click', runDeepScan);
$('check-service').addEventListener('click', checkService);
const mode = query.get('mode') || 'workspace';
const initialText = query.get('text') || '';
const initialUrl = query.get('url') || '';
if (mode === 'link') $('sample').value = initialUrl || initialText;
else if (mode === 'selection') $('sample').value = initialText + (initialUrl && !initialText.includes(initialUrl) ? '\n\nSelected link destination: ' + initialUrl : '');
else $('sample').value = initialText;
if (initialUrl) state.pageUrl = initialUrl;
checkService();
if (mode === 'page') inspectCurrentPage();
else if ($('sample').value.trim()) inspectSample();
