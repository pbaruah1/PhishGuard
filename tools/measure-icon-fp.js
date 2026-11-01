#!/usr/bin/env node
                                                                                 
                                                                               
                                                                             
                                                                               
                                                                                 
                                                                         
                                                                 
                                                                              
                                                              
'use strict';
const { chromium } = require('@playwright/test');
const fs = require('node:fs'); const path = require('node:path');
const C = require('../engine/core/constants');
const H = require('../scripts/lib/crawl_helpers');
                                                                          
                                                                            
                                                                            
                                                       
const { matchBrand } = require('../engine/detection/image_hash');

const IH_SRC = fs.readFileSync(path.join(__dirname, '..', 'engine', 'detection', 'image_hash.js'), 'utf8');
const TABLE = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'engine', 'brands', 'brand_icons.json'), 'utf8'));
const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';
const SITE_COUNT = Number((process.argv.find((a) => a.startsWith('--sites=')) || '').split('=')[1] || 400);
const MAX_DIST = Number((process.argv.find((a) => a.startsWith('--maxdist=')) || '').split('=')[1] || (C.THRESHOLDS.iconHamming || 6));
const NAV_TIMEOUT = Number((process.argv.find((a) => a.startsWith('--timeout=')) || '').split('=')[1] || 15000);

                                                                                  
                                                                    
                                                                           
                                                                              
                                                                              
                                                                              
                                                                                       
                                                                                 
const COLLECT_CANDIDATES_SRC = `
  globalThis.__ssIconCandidates = function () {
    const out = [];
    const add = (h) => { try { const u = new URL(h, location.href); if (/^https?:$/.test(u.protocol)) out.push(u.href); } catch (_) {} };
    document.querySelectorAll('link[rel~="icon"],link[rel="apple-touch-icon"]').forEach((l) => add(l.getAttribute('href') || ''));
    add('/favicon.ico');
    [...document.querySelectorAll('img')].filter((i) => /logo/i.test((i.getAttribute('src') || '') + ' ' + (i.getAttribute('alt') || '') + ' ' + i.className + ' ' + i.id) && (i.naturalWidth >= 40 || i.width >= 40)).slice(0, 2).forEach((i) => add(i.getAttribute('src') || ''));
    return [...new Set(out)].slice(0, 6);
  };
`;

async function fetchFeed(url) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 120000);
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'PhishGuardFpMeasure/0.5' }, redirect: 'follow', signal: ctl.signal });
    if (!r.ok) return null;
    return Buffer.from(await r.arrayBuffer());
  } catch (_) { return null; } finally { clearTimeout(t); }
}

async function main() {
  console.log(`Downloading Tranco (need ${SITE_COUNT} domains)…`);
  const zbuf = await fetchFeed(TRANCO_URL);
  if (!zbuf) throw new Error('Tranco feed fetch failed');
  const csv = H.readFirstZipEntry(zbuf).toString('utf8');
  const domains = csv.split('\n').slice(0, SITE_COUNT).map((l) => l.split(',')[1]).filter(Boolean).map((d) => d.trim());
  console.log(`  ${domains.length} domains`);

  const entriesByHash = new Map();
  for (const b of TABLE.brands) for (const e of (b.entries || [])) if (!entriesByHash.has(e.hash)) entriesByHash.set(e.hash, e);

  async function launch() {
    const browser = await chromium.launch();
    const context = await browser.newContext({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128 PhishGuardFpMeasure' });
    await context.addInitScript(IH_SRC);
    await context.addInitScript(COLLECT_CANDIDATES_SRC);
    return { browser, context };
  }

  let { browser, context } = await launch();
  let sitesVisited = 0, sitesWithIcons = 0, iconsHashed = 0;
  const fps = [];

                                                                             
                                                                          
                                                                           
                                                                              
                                                                             
                                                                             
                                                                           
                                                                            
                                                                            
                                                                            
                                              
  const PER_SITE_BUDGET = NAV_TIMEOUT + 15000;
  class BudgetExceeded extends Error {}
  const withBudget = (p) => Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new BudgetExceeded('per-site budget exceeded')), PER_SITE_BUDGET))
  ]);

  for (const d of domains) {
    let page;
    let wedged = false;
    try {
      page = await withBudget(context.newPage());
      await withBudget((async () => {
        await page.goto('https://' + d + '/', { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
        sitesVisited++;
        await page.waitForTimeout(300);
        const cands = await page.evaluate(() => __ssIconCandidates());
        let hashedAny = false;
        for (const url of cands) {
                                                                                 
                                                                               
                                                                            
                                                                     
                                                                             
                                             
          const hash = await page.evaluate(async (url) => {
            try {
              const ctl = new AbortController();
              const t = setTimeout(() => ctl.abort(), 5000);
              try {
                const r = await fetch(url, { credentials: 'omit', signal: ctl.signal });
                if (!r.ok) return null;
                const blob = await r.blob();
                if (!/^image\//.test(blob.type) && !/\.ico(\?|$)/i.test(url)) return null;
                return await PhishGuard.hashImageBlob(blob);
              } finally { clearTimeout(t); }
            } catch (_) { return null; }
          }, url);
          if (!hash) continue;
          iconsHashed++; hashedAny = true;
          const m = matchBrand(hash, TABLE.brands, MAX_DIST);
          if (m) {
            const legit = C.BRAND_DOMAINS[m.brand] || [];
            const reg = C.registrableDomain(d);
            const onBrand = legit.some((ld) => reg === ld || d.endsWith('.' + ld));
            if (!onBrand) {
              const entry = entriesByHash.get(m.hash);
              fps.push({ domain: d, brand: m.brand, distance: m.distance, kind: entry ? entry.kind : 'unknown', url });
            }
          }
        }
        if (hashedAny) sitesWithIcons++;
      })());
      await withBudget(page.close());
    } catch (e) {
                                                                            
      wedged = e instanceof BudgetExceeded;
      if (!wedged && page) { try { await page.close(); } catch (_) {} }
    }
    if (wedged) {
                                                                             
                                                                           
                                                                        
                                                                             
                                                                           
      try { browser.process() && browser.process().kill('SIGKILL'); } catch (_) {}
      try { await browser.close(); } catch (_) {}
      ({ browser, context } = await launch());
    }
    if (sitesVisited && sitesVisited % 20 === 0) console.log(`  ...${sitesVisited} sites visited, ${iconsHashed} icons hashed so far`);
  }
  try { await browser.close(); } catch (_) {}

  const fpRate = sitesWithIcons ? (fps.length / sitesWithIcons) * 100 : 0;
  console.log('');
  console.log(`Sites visited:       ${sitesVisited}`);
  console.log(`Sites with icons:    ${sitesWithIcons}`);
  console.log(`Icons hashed:        ${iconsHashed}`);
  console.log(`False positives:     ${fps.length} (maxDist=${MAX_DIST})`);
  console.log(`FP rate:             ${fpRate.toFixed(2)}% (of sites with hashed icons)`);
  if (fps.length) {
    console.log('');
    console.log('False positives:');
    for (const fp of fps) console.log(`  ${fp.domain} → ${fp.brand} (distance=${fp.distance}, kind=${fp.kind})`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
