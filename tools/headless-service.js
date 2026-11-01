'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const path = require('node:path');
const https = require('node:https');

require('../engine/core/constants');
require('../engine/detection/features');
require('../engine/rules/brand_match');
require('../engine/rules/site_signals');
require('../engine/rules/risk_rules');
require('../engine/rules/heuristics');
require('../engine/rules/page_text_rules');
require('../engine/rules/download_rules');
require('../engine/core/verdict');
const Reasons = require('../ui/reasons');
const SS = globalThis.PhishGuard;

const CLOUD_MODE = process.env.PHISHGUARD_HEADLESS_MODE === 'cloud';
const HOST = process.env.PHISHGUARD_HEADLESS_HOST || (CLOUD_MODE ? '0.0.0.0' : '127.0.0.1');
const PORT = Number(process.env.PORT || process.env.PHISHGUARD_HEADLESS_PORT || 8765);
const ALLOWED_ORIGINS = new Set(String(process.env.PHISHGUARD_EXTENSION_ORIGINS || '').split(',').map((v) => v.trim()).filter(Boolean));
const MAX_CONCURRENT = Math.max(1, Math.min(8, Number(process.env.PHISHGUARD_MAX_CONCURRENT || 3)));
let activeInspections = 0;
const MAX_BODY = 32768;
const MAX_REQUESTS = 140;
const TRUST_PROXY = process.env.PHISHGUARD_TRUST_PROXY === '1';
const PAGE_TIMEOUT = 18000;
const dnsCache = new Map();

function ipv4Number(value) {
  const parts = value.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}
function inV4Range(ip, base, maskBits) {
  const value = ipv4Number(ip), network = ipv4Number(base);
  if (value == null || network == null) return false;
  const mask = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
  return (value & mask) === (network & mask);
}
function isPublicIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const blocked = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
      ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return !blocked.some(([base, bits]) => inV4Range(ip, base, bits));
  }
  if (version === 6) {
    let h = ip.toLowerCase().split('%')[0];
    const dotted = h.match(/(\d+\.\d+\.\d+\.\d+)$/);
    if (dotted) {
      const v4 = ipv4Number(dotted[1]);
      if (v4 == null) return false;
      h = h.slice(0, -dotted[1].length) + (v4 >>> 16).toString(16) + ':' + (v4 & 0xffff).toString(16);
    }
    const halves = h.split('::');
    if (halves.length > 2) return false;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return false;
    const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right].map((part) => parseInt(part || '0', 16));
    if (words.length !== 8 || words.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) return false;
    const value = words.reduce((acc, part) => (acc << 16n) | BigInt(part), 0n);
    // Public IPv6 unicast is restricted to 2000::/3; mapped IPv4 inherits the IPv4 policy.
    if ((value >> 125n) !== 1n) return false;
    const mappedPrefix = value >> 32n;
    if (mappedPrefix === 0xffffn) {
      const v4 = Number(value & 0xffffffffn);
      return isPublicIp([v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255].join('.'));
    }
    const first32 = Number(value >> 96n);
    if (first32 === 0x20010db8 || first32 >= 0x20010000 && first32 <= 0x200101ff ||
        first32 >= 0x20020000 && first32 <= 0x2002ffff || first32 >= 0x3fff0000 && first32 <= 0x3fff0fff) return false;
    return true;
  }
  return false;
}
function validateHttpUrl(value) {
  let url;
  try { url = new URL(String(value || '')); } catch (_) { throw new Error('Enter a complete HTTP or HTTPS URL.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS destinations can be inspected.');
  if (url.username || url.password) throw new Error('URLs containing embedded credentials are not accepted.');
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !isPublicIp(host)) throw new Error('Private, loopback, link-local, and reserved IP addresses are blocked.');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      host.endsWith('.internal') || host.endsWith('.test') || host.endsWith('.invalid') || host === '0.0.0.0') {
    throw new Error('Local, private, and reserved hostnames are blocked by the headless scanner.');
  }
  return url;
}
async function publicAddresses(host) {
  if (net.isIP(host)) return isPublicIp(host) ? [host] : [];
  const key = host.toLowerCase();
  const saved = dnsCache.get(key);
  if (saved && saved.until > Date.now()) return saved.addresses;
  let records;
  try { records = await dns.lookup(key, { all: true, verbatim: true }); }
  catch (_) { return []; }
  const addresses = records.map((record) => record.address);
  const safe = addresses.length && addresses.every(isPublicIp) ? addresses : [];
  dnsCache.set(key, { addresses: safe, until: Date.now() + 20000 });
  return safe;
}
async function assertPublicUrl(value) {
  const url = validateHttpUrl(value);
  const addresses = await publicAddresses(url.hostname);
  if (!addresses.length) throw new Error('The destination resolves to a private/reserved address or could not be resolved safely.');
  return { url, addresses };
}

function proxyPublicRequest(urlValue, method, headers, body, maxBytes) {
  return new Promise(async (resolve, reject) => {
    let checked;
    try { checked = await assertPublicUrl(urlValue); }
    catch (error) { reject(error); return; }
    const url = checked.url;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const transport = url.protocol === 'https:' ? https : http;
    const requestHeaders = Object.assign({}, headers || {});
    for (const key of Object.keys(requestHeaders)) {
      if (/^(?:host|connection|proxy-connection|content-length|accept-encoding|transfer-encoding)$/i.test(key)) delete requestHeaders[key];
    }
    requestHeaders['accept-encoding'] = 'identity';
    const pinnedLookup = (_hostname, options, callback) => {
      if (typeof options === 'function') { callback = options; options = {}; }
      const address = checked.addresses[0];
      const family = net.isIP(address);
      if (options && options.all) callback(null, [{ address, family }]);
      else callback(null, address, family);
    };
    const request = transport.request({
      protocol: url.protocol,
      hostname: host,
      port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
      method: String(method || 'GET').toUpperCase(),
      path: url.pathname + url.search,
      headers: requestHeaders,
      lookup: pinnedLookup,
      servername: net.isIP(host) ? undefined : host,
      agent: false,
      timeout: 12000
    }, (response) => {
      const chunks = [];
      const limit = Math.max(1024, Number(maxBytes) || 8 * 1024 * 1024);
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > limit) { request.destroy(new Error('A page resource exceeded the headless inspection size limit.')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const responseHeaders = Object.assign({}, response.headers);
        for (const key of Object.keys(responseHeaders)) {
          if (/^(?:connection|transfer-encoding|content-length|content-encoding|set-cookie|set-cookie2)$/i.test(key)) delete responseHeaders[key];
        }
        resolve({ status: response.statusCode || 200, headers: responseHeaders, body: Buffer.concat(chunks) });
      });
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('The remote page request timed out.')));
    request.on('error', reject);
    if (body && !['GET', 'HEAD'].includes(String(method || 'GET').toUpperCase())) request.write(body);
    request.end();
  });
}

function structuralEvidence(snapshot) {
  const items = [];
  const forms = Array.isArray(snapshot.forms) ? snapshot.forms : [];
  for (const form of forms) {
    if (!form.hasPassword && !form.hasPaymentField) continue;
    const sourceHost = form.sourceHost || (() => { try { return new URL(snapshot.url).hostname; } catch (_) { return ''; } })();
    const targetHost = form.actionHost || sourceHost;
    const targetDomain = SS.registrableDomain(targetHost);
    const sourceDomain = SS.registrableDomain(sourceHost);
    if (targetDomain !== sourceDomain && !(SS.KNOWN_AUTH_PROVIDERS || []).includes(targetDomain)) {
      items.push({ code: 'cross-domain-secret-form', title: 'Sensitive form sends data to another site', detail: `A form on ${sourceHost} collects a password or payment field but submits to ${targetHost}. Verify the recipient before entering anything.`, severity: 'critical' });
    }
  }
  return items;
}

async function inspectPublicPage(inputUrl) {
  const { chromium } = require('playwright');
  const initial = await assertPublicUrl(inputUrl);
  const browser = await chromium.launch({ headless: true });
  let context;
  try {
    context = await browser.newContext({
      acceptDownloads: false,
      javaScriptEnabled: true,
      serviceWorkers: 'block',
      ignoreHTTPSErrors: false,
      viewport: { width: 1365, height: 900 }
    });
    const page = await context.newPage();
    let requestCount = 0;
    let blockedWriteRequests = 0;
    let downloadAttempted = false;
    let popupAttempts = 0;
    let pageErrorCount = 0;
    let consoleErrorCount = 0;
    const network = [];
    const failedRequests = [];
    const frameNavigations = [];
    const redirects = [];
    const safeLocation = (value) => {
      try { const u = new URL(value); return { host: u.hostname, path: u.pathname.slice(0, 300), protocol: u.protocol }; }
      catch (_) { return { host: '', path: '', protocol: '' }; }
    };
    const pushCapped = (list, item, cap) => { if (list.length < cap) list.push(item); };
    page.on('download', (download) => {
      downloadAttempted = true;
      Promise.resolve(download.cancel()).catch(() => {});
    });
    page.on('popup', (popup) => {
      popupAttempts++;
      Promise.resolve(popup.close()).catch(() => {});
    });
    page.on('dialog', (dialog) => Promise.resolve(dialog.dismiss()).catch(() => {}));
    page.on('pageerror', () => { pageErrorCount++; });
    page.on('console', (message) => { if (message.type() === 'error') consoleErrorCount++; });
    page.on('request', (request) => {
      const loc = safeLocation(request.url());
      const previous = request.redirectedFrom();
      if (previous) pushCapped(redirects, { from: safeLocation(previous.url()), to: loc,
        method: request.method().toUpperCase() }, 80);
      pushCapped(network, { kind: 'request', method: request.method().toUpperCase(), resourceType: request.resourceType(), ...loc }, 300);
    });
    page.on('response', (item) => {
      const loc = safeLocation(item.url());
      pushCapped(network, { kind: 'response', status: item.status(), ...loc }, 300);
    });
    page.on('requestfailed', (request) => {
      const loc = safeLocation(request.url());
      pushCapped(failedRequests, { method: request.method().toUpperCase(), resourceType: request.resourceType(), error: String(request.failure() && request.failure().errorText || 'request failed').slice(0, 160), ...loc }, 100);
    });
    page.on('framenavigated', (frame) => {
      const loc = safeLocation(frame.url());
      pushCapped(frameNavigations, { mainFrame: frame === page.mainFrame(), ...loc }, 100);
    });
    if (typeof page.routeWebSocket === 'function') {
      await page.routeWebSocket('**/*', (socket) => { try { socket.close(); } catch (_) {} });
    }
    await page.route('**/*', async (route) => {
      const request = route.request();
      const requestUrl = request.url();
      if (!/^https?:/i.test(requestUrl)) { await route.abort('blockedbyclient').catch(() => {}); return; }
      // A scanner only observes pages. It never submits forms or forwards write requests.
      if (!['GET', 'HEAD'].includes(request.method().toUpperCase())) {
        blockedWriteRequests++;
        await route.abort('blockedbyclient').catch(() => {});
        return;
      }
      requestCount++;
      if (requestCount > MAX_REQUESTS) { await route.abort('blockedbyclient').catch(() => {}); return; }
      try {
        const safeHeaders = Object.assign({}, request.headers());
        delete safeHeaders.cookie; delete safeHeaders.authorization; delete safeHeaders['proxy-authorization'];
        delete safeHeaders.referer; delete safeHeaders.referrer;
        const upstream = await proxyPublicRequest(requestUrl, request.method(), safeHeaders, null);
        await route.fulfill({ status: upstream.status, headers: upstream.headers, body: upstream.body });
      } catch (_) { await route.abort('blockedbyclient').catch(() => {}); }
    });
    let response = null;
    let navigationError = '';
    try { response = await page.goto(initial.url.href, { waitUntil: 'domcontentloaded', timeout: PAGE_TIMEOUT }); }
    catch (error) { navigationError = String(error && error.message || error).slice(0, 300); }
    await page.waitForTimeout(1100).catch(() => {});
    const frameSnapshots = await Promise.all(page.frames().slice(0, 50).map(async (frame) => {
      try {
        return await frame.evaluate(() => {
          const queue = [document];
          const roots = [];
          const seen = new Set();
          const elements = [];
          let textParts = [document.body ? (document.body.innerText || document.body.textContent || '') : ''];
          while (queue.length && elements.length < 5000) {
            const current = queue.shift();
            roots.push(current);
            let descendants = [];
            try { descendants = Array.from(current.querySelectorAll('*')); } catch (_) {}
            for (const el of descendants) {
              if (seen.has(el)) continue;
              seen.add(el); elements.push(el);
              if (el.shadowRoot && roots.length + queue.length < 100) {
                queue.push(el.shadowRoot);
                try { textParts.push(el.shadowRoot.innerText || el.shadowRoot.textContent || ''); } catch (_) {}
              }
            }
          }
          const deepSelect = (selector) => {
            const found = [];
            const known = new Set();
            for (const root of roots) {
              try {
                for (const node of root.querySelectorAll(selector)) {
                  if (!known.has(node)) { known.add(node); found.push(node); }
                }
              } catch (_) {}
            }
            return found;
          };
          const tagCounts = Object.create(null);
          const elementDetails = [];
          let interactiveCount = 0;
          for (const el of elements) {
            const tag = String(el.tagName || '').toLowerCase();
            tagCounts[tag] = (tagCounts[tag] || 0) + 1;
            const role = el.getAttribute('role') || '';
            const interactive = /^(a|button|input|textarea|select|option)$/i.test(tag) || /^(button|link|menuitem|checkbox|radio|switch|tab)$/i.test(role) || el.hasAttribute('contenteditable');
            if (interactive) interactiveCount++;
            if (elementDetails.length < 1000) elementDetails.push({ tag, id: String(el.id || '').slice(0, 100), role,
              type: el.getAttribute('type') || '',
              label: String(el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder') || '').replace(/\s+/g, ' ').trim().slice(0, 160),
              hrefHost: (() => { try { return el.href ? new URL(el.href, location.href).hostname : ''; } catch (_) { return ''; } })(),
              srcHost: (() => { try { return el.src ? new URL(el.src, location.href).hostname : ''; } catch (_) { return ''; } })(),
              hrefScheme: (() => { try { return el.href ? new URL(el.href, location.href).protocol : ''; } catch (_) { return 'invalid:'; } })(),
              hidden: !!(el.hidden || el.getAttribute('aria-hidden') === 'true'), disabled: !!el.disabled, required: !!el.required,
              download: el.hasAttribute('download'), rel: el.getAttribute('rel') || '', target: el.getAttribute('target') || '',
              hasInlineHandler: Array.from(el.attributes || []).some((attr) => /^on/i.test(attr.name)) });
          }
          const fields = deepSelect('input,textarea,select');
          const forms = deepSelect('form').slice(0, 80).map((form, index) => {
            const fields = Array.from(form.querySelectorAll('input,textarea,select')).slice(0, 40);
            const action = (() => { try { const u = new URL(form.getAttribute('action') || location.href, location.href); u.username = ''; u.password = ''; u.search = ''; u.hash = ''; return { host: u.hostname, url: u.href.slice(0, 1800) }; } catch (_) { return { host: '', url: '' }; } })();
            return { id: 'F' + index, sourceHost: location.hostname, actionHost: action.host, actionUrl: action.url,
              method: String(form.getAttribute('method') || 'get').toUpperCase(),
              hasPassword: fields.some((field) => String(field.type || '').toLowerCase() === 'password'),
              hasPaymentField: fields.some((field) => /cc-number|card/i.test((field.autocomplete || '') + ' ' + (field.name || '') + ' ' + (field.id || ''))),
              hasSensitiveField: fields.some((field) => String(field.type || '').toLowerCase() === 'password' || /cc-number|card|one-time-code/i.test((field.autocomplete || '') + ' ' + (field.name || '') + ' ' + (field.id || ''))),
              fieldCount: form.querySelectorAll('input,textarea,select').length,
              fieldTypes: fields.map((field) => String(field.type || field.tagName || '').toLowerCase()).slice(0, 20),
              fieldLabels: fields.slice(0, 20).map((field) => { const label = field.labels && field.labels[0]; return String((label && (label.innerText || label.textContent)) || field.getAttribute('aria-label') || field.getAttribute('autocomplete') || field.type || field.tagName || '').replace(/\s+/g, ' ').slice(0, 80); }) };
          });
          const links = deepSelect('a[href]').slice(0, 300).map((a, index) => ({
            id: 'L' + index,
            url: (() => { try { const u = new URL(a.href); if (!/^https?:$/.test(u.protocol)) return ''; u.username = ''; u.password = ''; u.hash = ''; for (const key of Array.from(u.searchParams.keys())) if (/(?:token|auth|session|secret|password|passwd|api.?key|access.?key|signature|(^|_)sig$|csrf|oauth|code|state|email|phone|user(?:name)?)/i.test(key)) u.searchParams.delete(key); return u.href.slice(0, 2048); } catch (_) { return ''; } })(),
            host: (() => { try { return new URL(a.href).hostname; } catch (_) { return ''; } })(),
            protocol: (() => { try { return new URL(a.href).protocol; } catch (_) { return ''; } })(),
            label: String(a.innerText || a.textContent || a.getAttribute('aria-label') || a.title || '').replace(/\s+/g, ' ').trim().slice(0, 180),
            visible: (() => { try { const st = getComputedStyle(a); return st.display !== 'none' && st.visibility !== 'hidden' && a.getClientRects().length > 0; } catch (_) { return false; } })(),
            targetBlank: a.target === '_blank', rel: a.rel || '', download: a.hasAttribute('download')
          }));
          const scriptBehavior = (source) => {
            const code = String(source || '').slice(0, 30000);
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
          const scripts = deepSelect('script').slice(0, 120).map((script, index) => {
            const src = script.getAttribute('src') || '';
            const scriptType = String(script.getAttribute('type') || '').toLowerCase();
            const executable = !scriptType || /(?:java|ecma)script|module/i.test(scriptType);
            const source = !src && executable ? String(script.textContent || '').slice(0, 30000) : '';
            const behaviorSignals = scriptBehavior(source);
            return { scriptIndex: index,
              host: (() => { try { return src ? new URL(src, location.href).hostname : location.hostname; } catch (_) { return ''; } })(),
              srcHost: (() => { try { return src ? new URL(src, location.href).hostname : ''; } catch (_) { return ''; } })(),
              inline: !src, executable, type: scriptType.slice(0, 60), async: !!script.async, defer: !!script.defer,
              integrity: !!script.integrity, codeLength: source.length, codePreview: source.slice(0, 900), behaviorSignals,
              evidenceFlags: !src && executable && behaviorSignals.length >= 2 ? ['multi-behavior-inline-script'] : [] };
          });
          const frameList = deepSelect('iframe,frame').slice(0, 100).map((frame) => ({
            host: (() => { try { return new URL(frame.src || location.href, location.href).hostname; } catch (_) { return ''; } })(),
            hidden: (() => { try { const st = getComputedStyle(frame); return st.display === 'none' || st.visibility === 'hidden' || frame.offsetWidth <= 1 || frame.offsetHeight <= 1; } catch (_) { return false; } })()
          }));
          const candidates = deepSelect('a[href],a[download],button,[role="button"]').slice(0, 300).map((node) => ({
            href: (() => { try { const u = new URL(node.getAttribute('href') || '', location.href); return /^https?:$/.test(u.protocol) ? u.href.slice(0, 2048) : ''; } catch (_) { return ''; } })(),
            label: [node.innerText || node.textContent || '', node.getAttribute('aria-label') || '', node.getAttribute('title') || ''].join(' ').slice(0, 200),
            filename: node.getAttribute('download') || '', isDownload: node.hasAttribute('download') || /\b(download|install|open file|view file|run file)\b/i.test((node.innerText || node.textContent || '') + ' ' + (node.getAttribute('aria-label') || ''))
          }));
          const text = textParts.join(' ').slice(0, 50000);
          const buttons = deepSelect('button,[role="button"],input[type="submit"]').slice(0, 300);
          const ctaCount = buttons.filter((item) => /\b(verify|confirm|update|continue|sign in|log in|unlock|restore|pay|download|install|submit|claim)\b/i.test(item.innerText || item.value || item.getAttribute('aria-label') || '')).length;
          return { url: location.href, title: document.title || '', text, forms, formCount: deepSelect('form').length,
            linkCount: deepSelect('a[href]').length, links, scripts, scriptCount: deepSelect('script').length,
            ctaCount, hasPasswordField: fields.some((item) => item.type === 'password'),
            hasCardInput: fields.some((item) => /card/i.test((item.name || '') + ' ' + (item.id || '') + ' ' + (item.autocomplete || ''))),
            hiddenIframes: frameList.filter((item) => item.hidden).length, frames: frameList,
            elementCount: elements.length, elementDetails, elementsByTag: tagCounts, interactiveCount,
            elementDetailsTruncated: elements.length > elementDetails.length,
            inventoryTruncated: elements.length >= 5000, candidates,
            openShadowRootCount: elements.filter((el) => !!el.shadowRoot).length };
        });
      } catch (_) { return { url: frame.url(), frameUnavailable: true, elementCount: 0, interactiveCount: 0, forms: [], links: [], candidates: [] }; }
    }));
    const snapshot = frameSnapshots[0] || { url: page.url(), title: '', text: '', forms: [], candidates: [], formCount: 0, linkCount: 0, ctaCount: 0, hasPasswordField: false, hasCardInput: false, hiddenIframes: 0 };
    const allFrameForms = frameSnapshots.flatMap((frame) => frame.forms || []);
    const allFrameCandidates = frameSnapshots.flatMap((frame) => frame.candidates || []);
    snapshot.forms = allFrameForms;
    snapshot.formCount = allFrameForms.length;
    snapshot.candidates = allFrameCandidates;
    snapshot.text = frameSnapshots.map((frame) => frame.text || '').join(' ').slice(0, 50000);
    snapshot.title = snapshot.title || '';
    snapshot.linkCount = frameSnapshots.reduce((sum, frame) => sum + Number(frame.linkCount || 0), 0);
    snapshot.elementsByTag = {};
    for (const frame of frameSnapshots) for (const [tag, count] of Object.entries(frame.elementsByTag || {})) snapshot.elementsByTag[tag] = (snapshot.elementsByTag[tag] || 0) + count;
    snapshot.elementDetails = frameSnapshots.flatMap((frame) => frame.elementDetails || []).slice(0, 1000);
    snapshot.elementDetailsTruncated = frameSnapshots.some((frame) => frame.elementDetailsTruncated) || frameSnapshots.reduce((sum, frame) => sum + (frame.elementDetails || []).length, 0) > snapshot.elementDetails.length;
    snapshot.inventoryTruncated = frameSnapshots.some((frame) => frame.inventoryTruncated);
    snapshot.ctaCount = frameSnapshots.reduce((sum, frame) => sum + Number(frame.ctaCount || 0), 0);
    snapshot.hasPasswordField = frameSnapshots.some((frame) => frame.hasPasswordField);
    snapshot.hasCardInput = frameSnapshots.some((frame) => frame.hasCardInput);
    snapshot.hiddenIframes = frameSnapshots.reduce((sum, frame) => sum + Number(frame.hiddenIframes || 0), 0);
    snapshot.totalElementCount = frameSnapshots.reduce((sum, frame) => sum + Number(frame.elementCount || 0), 0);
    snapshot.totalInteractiveCount = frameSnapshots.reduce((sum, frame) => sum + Number(frame.interactiveCount || 0), 0);
    const downloadTargets = snapshot.candidates.filter((candidate) => candidate && candidate.href && /^https?:/i.test(candidate.href));
    // This service deliberately does not turn page wording or keyword matches
    // into a verdict. It returns rendered DOM/network observations for the
    // on-device generative model to interpret in context.
    const downloadRules = SS.scoreDownloadSurface({ host: new URL(snapshot.url || initial.url.href).hostname,
      pageText: '', candidates: downloadTargets });
    const evidence = [];
    evidence.push(...structuralEvidence(snapshot));
    for (const item of downloadRules.evidence || []) {
      evidence.push({ title: item.code || 'Download observation', detail: item.detail || '', severity: item.severity || 'info' });
    }
    if (downloadAttempted) evidence.push({ title: 'Download attempt cancelled', detail: 'The remote page attempted to start a download during inspection. PhishGuard cancelled it and did not save or execute the file.', severity: 'info' });
    const uniqueEvidence = evidence.filter((item, index, list) => list.findIndex((other) => other.title === item.title && other.detail === item.detail) === index);
    const criticalFindings = uniqueEvidence.filter((item) => item.severity === 'critical').length;
    const safeDisplayUrl = (value) => { try { const u = new URL(value); u.username = ''; u.password = ''; u.search = ''; u.hash = ''; return u.href.slice(0, 2048); } catch (_) { return ''; } };
    return {
      level: 'unknown', score: 0, confirmedMalware: false,
      url: safeDisplayUrl(initial.url.href), finalUrl: safeDisplayUrl(snapshot.url),
      title: snapshot.title, httpStatus: response ? response.status() : null, requestCount,
      downloadAttempted, blockedWriteRequests, popupAttempts, pageErrorCount, consoleErrorCount,
      navigationError, analysis: 'remote-playwright-observation-for-on-device-ai',
      contentPreview: String(snapshot.text || '').slice(0, 12000),
      network: network.slice(0, 220), failedRequests: failedRequests.slice(0, 80),
      frameNavigations: frameNavigations.slice(0, 80), redirects: redirects.slice(0, 80), criticalFindings,
      evidence: uniqueEvidence.slice(0, 30),
      frames: frameSnapshots.map((frame) => ({ url: safeDisplayUrl(frame.url), frameUnavailable: !!frame.frameUnavailable,
        elementCount: frame.elementCount || 0, interactiveCount: frame.interactiveCount || 0,
        formCount: frame.formCount || 0, linkCount: frame.linkCount || 0, scriptCount: frame.scriptCount || 0,
        openShadowRootCount: frame.openShadowRootCount || 0, inventoryTruncated: !!frame.inventoryTruncated })),
      inventory: { elementCount: snapshot.totalElementCount, interactiveCount: snapshot.totalInteractiveCount,
        elementsByTag: snapshot.elementsByTag || {}, elementDetails: snapshot.elementDetails || [], inventoryTruncated: !!snapshot.inventoryTruncated,
        openShadowRootCount: frameSnapshots.reduce((sum, frame) => sum + Number(frame.openShadowRootCount || 0), 0),
        formCount: snapshot.formCount, forms: snapshot.forms, linkCount: snapshot.linkCount,
        links: frameSnapshots.flatMap((frame) => frame.links || []).slice(0, 300),
        scriptCount: frameSnapshots.reduce((sum, frame) => sum + Number(frame.scriptCount || 0), 0),
        iframeCount: frameSnapshots.reduce((sum, frame) => sum + Number((frame.frames || []).length), 0),
        scripts: frameSnapshots.flatMap((frame) => frame.scripts || []).slice(0, 120),
        elementDetailsTruncated: !!snapshot.elementDetailsTruncated,
        downloadCandidates: snapshot.candidates.slice(0, 80) },
      signals: {
        forms: snapshot.formCount, links: snapshot.linkCount, callToActions: snapshot.ctaCount,
        passwordField: snapshot.hasPasswordField, paymentField: snapshot.hasCardInput,
        hiddenIframes: snapshot.hiddenIframes, downloadCandidates: snapshot.candidates.length,
        visibleTextLength: String(snapshot.text || '').length
      }, limitations: ['No signed-in browser cookies were reused.', 'No downloaded file bytes were scanned or executed.',
        'No malware hash or antivirus verdict is claimed by this Playwright scan.', 'The scanner follows safe GET/HEAD page requests only; some servers can still implement side effects on GET requests.',
        'Closed shadow roots and browser-internal pages are inaccessible.',
        'The service inspected the public URL in a fresh isolated browser context, not the user’s current authenticated tab.']
    };
  } finally {
    if (context) await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

const requests = new Map();
function requestClientAddress(req) {
  if (TRUST_PROXY) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded && forwarded.length <= 64) return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}
function rateAllowed(address) {
  const now = Date.now();
  const entry = requests.get(address) || { start: now, count: 0 };
  if (now - entry.start > 60000) { entry.start = now; entry.count = 0; }
  entry.count++;
  requests.set(address, entry);
  if (requests.size > 10000) {
    for (const [key, value] of requests) if (now - value.start > 120000) requests.delete(key);
  }
  return entry.count <= (CLOUD_MODE ? 4 : 8);
}
function sendJson(res, status, value, origin) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': origin || 'null',
    'Vary': 'Origin',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
  });
  if (status === 204) { res.end(); return; }
  res.end(JSON.stringify(value));
}
function allowedRequestOrigin(origin) {
  if (CLOUD_MODE) return !!origin && ALLOWED_ORIGINS.has(origin);
  return !origin || /^chrome-extension:\/\/[a-p]{32}$/.test(origin) || /^moz-extension:\/\/[a-z0-9-]+$/.test(origin);
}
function startServer() {
  if (CLOUD_MODE && (ALLOWED_ORIGINS.size === 0 || Array.from(ALLOWED_ORIGINS).some((origin) => !/^chrome-extension:\/\/[a-p]{32}$/.test(origin)))) {
    throw new Error('PHISHGUARD_EXTENSION_ORIGINS must contain one or more exact Chrome Web Store extension origins (chrome-extension:// plus 32 a-p characters).');
  }
  const token = process.env.PHISHGUARD_HEADLESS_TOKEN || crypto.randomBytes(32).toString('hex');
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') {
      sendJson(res, 200, { ready: true }, 'null'); return;
    }
    const origin = String(req.headers.origin || '');
    if (!allowedRequestOrigin(origin)) {
      sendJson(res, 403, { error: 'This origin is not allowed to use the PhishGuard inspection service.' }, 'null'); return;
    }
    const responseOrigin = origin || 'null';
    if (req.method === 'OPTIONS') { sendJson(res, 204, {}, responseOrigin); return; }
    if (req.method === 'GET' && req.url === '/v1/health') {
      sendJson(res, 200, { ready: true, service: CLOUD_MODE ? 'PhishGuard hosted Playwright inspector' : 'PhishGuard local Chromium inspector' }, responseOrigin); return;
    }
    if (req.method !== 'POST' || !['/v1/analyze', '/v1/analyze-links'].includes(req.url)) { sendJson(res, 404, { error: 'Unknown endpoint.' }, responseOrigin); return; }
    if (!CLOUD_MODE) {
      const auth = String(req.headers.authorization || '');
      const supplied = Buffer.from(auth.padEnd(72, '\0').slice(0, 72));
      const expected = Buffer.from(('Bearer ' + token).padEnd(72, '\0').slice(0, 72));
      if (!crypto.timingSafeEqual(supplied, expected)) { sendJson(res, 401, { error: 'Invalid local companion token.' }, responseOrigin); return; }
    }
    if (!rateAllowed(requestClientAddress(req))) { sendJson(res, 429, { error: 'Inspection rate limit reached. Please wait one minute.' }, responseOrigin); return; }
    if (activeInspections >= MAX_CONCURRENT) { sendJson(res, 429, { error: 'The inspection service is busy. Try again shortly.' }, responseOrigin); return; }
    const declaredLength = Number(req.headers['content-length'] || 0);
    if (declaredLength > MAX_BODY) { sendJson(res, 413, { error: 'Request body is too large.' }, responseOrigin); return; }
    let body = '', tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > MAX_BODY) { tooLarge = true; req.pause(); sendJson(res, 413, { error: 'Request body is too large.' }, responseOrigin); }
    });
    req.on('end', async () => {
      if (tooLarge) return;
      activeInspections++;
      try {
        const input = JSON.parse(body || '{}');
        if (req.url === '/v1/analyze') {
          const result = await inspectPublicPage(input.url);
          sendJson(res, 200, result, responseOrigin);
          return;
        }
        if (!Array.isArray(input.urls) || input.urls.length < 1 || input.urls.length > 8) {
          sendJson(res, 400, { error: 'Provide between 1 and 8 HTTP(S) URLs.' }, responseOrigin);
          return;
        }
        const urls = input.urls.map((value) => {
          const parsed = validateHttpUrl(value);
          parsed.username = ''; parsed.password = ''; parsed.hash = '';
          return parsed.href.slice(0, 2048);
        });
        const scans = new Array(urls.length);
        let next = 0;
        const worker = async () => {
          while (true) {
            const index = next++;
            if (index >= urls.length) return;
            try { scans[index] = { url: urls[index], result: await inspectPublicPage(urls[index]) }; }
            catch (error) { scans[index] = { url: urls[index], error: String(error && error.message || error).slice(0, 240) }; }
          }
        };
        await Promise.all(Array.from({ length: Math.min(2, urls.length) }, worker));
        sendJson(res, 200, { scans }, responseOrigin);
      } catch (error) { sendJson(res, 400, { error: String(error && error.message || error).slice(0, 300) }, responseOrigin); }
      finally { activeInspections = Math.max(0, activeInspections - 1); }
    });
  });
  server.requestTimeout = 120000;
  server.headersTimeout = 10000;
  server.listen(PORT, HOST, () => {
    console.log(`PhishGuard ${CLOUD_MODE ? 'hosted' : 'local'} Playwright inspector listening on http://${HOST}:${PORT}`);
    if (!CLOUD_MODE) {
      console.log('Access token (paste into developer tooling only):');
      console.log(token);
      console.log('This service uses an isolated, unsigned-in Chromium context and does not reuse normal browser cookies.');
    } else {
      console.log(`Allowed extension origins: ${Array.from(ALLOWED_ORIGINS).join(', ')}`);
      console.log('Cloud mode accepts URL-only scans, permits only GET/HEAD page requests, and does not forward browser cookies or authorization headers.');
    }
  });
  return server;
}

async function cli() {
  const url = process.argv[3];
  if (!url) { console.error('Usage: node tools/headless-service.js inspect https://example.com'); process.exitCode = 2; return; }
  try { console.log(JSON.stringify(await inspectPublicPage(url), null, 2)); }
  catch (error) { console.error(String(error && error.message || error)); process.exitCode = 1; }
}

if (require.main === module) {
  if (process.argv[2] === 'inspect') cli();
  else startServer();
}

module.exports = { isPublicIp, validateHttpUrl, publicAddresses, assertPublicUrl, proxyPublicRequest, structuralEvidence, inspectPublicPage, startServer };
