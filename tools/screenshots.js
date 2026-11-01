                                                                                  
                                                            
const { chromium } = require('@playwright/test');
const path = require('path'); const fs = require('fs'); const { spawn } = require('child_process');
const EXT = path.resolve(__dirname, '..'); const OUT = path.resolve(__dirname, '../artifacts/screenshots'); const BASE = 'http://localhost:5599';
const FRAME = 'file://' + path.join(__dirname, 'frame.html').replace(/\\/g, '/');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const server = spawn('node', [path.join(__dirname, '../tests/e2e/server.js')], { stdio: 'ignore' }); await sleep(800);
  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      '--headless=new',
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      '--no-first-run', '--disable-gpu', '--disable-dev-shm-usage',
      '--window-size=1280,800',
                                                                             
                                                                              
                                     
      '--ignore-certificate-errors',
      '--host-resolver-rules=MAP amazon.ae 127.0.0.1, MAP accounts.google.com 127.0.0.1, MAP shop.contoso-fixture.com 127.0.0.1, MAP portal-hr-benefits.fixture 127.0.0.1, MAP www.aramex.com 127.0.0.1, MAP secure-paypa1-login.com 127.0.0.1'
    ]
  });
  for (let i = 0; i < 30 && !ctx.serviceWorkers()[0]; i++) await sleep(100);
  const sw = ctx.serviceWorkers()[0]; const id = sw.url().match(/chrome-extension:\/\/([^/]+)/)[1];
  await sw.evaluate(() => chrome.storage.local.set({ history: [
    { ts: Date.now() - 7200000, host: 'secure-paypa1-login.com', kind: 'page', level: 'dangerous' },
    { ts: Date.now() - 90000000, host: 'claim-airdrop.site', kind: 'wallet', level: 'dangerous' },
    { ts: Date.now() - 300000000, host: 'pc-alert-0093.top', kind: 'techscam', level: 'dangerous' } ] }));
                                                                            
                                                                              
                                                                             
                                                                           
           
  await sw.evaluate(() => setSettings({ threatsBlocked: 23, whatsNewSeen: '0.13.0' }));

                                                                              
                                                                               
                                                                              
                                                                         
                                                               
  function seedBuckets(days) {
    let s = 20250823; const rnd = () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648;
                                                           
    const key = (i) => new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    const out = [];
    for (let i = days - 1; i >= 0; i--) {
      if (i === 4 || i === 12 || i === 21) continue;                                              
      const b = { d: key(i), checked: 30 + Math.floor(rnd() * 61), threats: 0, privacy: 0 };
      if ([1, 3, 8, 14, 19, 25].includes(i)) b.threats = i === 8 ? 2 : 1;
      if ([0, 2, 6, 9, 15, 20, 24, 26].includes(i)) b.privacy = 1 + Math.floor(rnd() * 2);
      out.push(b);
    }
    return out;
  }
  async function seedStats() {
    const statsDaily = seedBuckets(28);
    await sw.evaluate((d) => chrome.storage.local.set({
      statsDaily: d.statsDaily,
      pagesCheckedTotal: 4213,
      privacyFindingsTotal: 19,
      threatsByType: { phishing: 11, fakeShop: 5, wallet: 4, techSupport: 3 },
      installedAt: d.installedAt,
                                                                          
                                                                             
                                                                               
                                              
      reviewAsk: { state: 'declined', asks: 0, snoozeUntil: 0 }
    }), { statsDaily, installedAt: Date.now() - 150 * 86400000 });
                                                                              
                                                                           
                                                    
    await sw.evaluate(() => setSettings({ threatsBlocked: 23 }));
  }

  async function compose(name, caption, shotPng, w, h, theme) {
    const f = await ctx.newPage(); await f.setViewportSize({ width: 1280, height: 800 });
    await f.goto(FRAME + '?caption=' + encodeURIComponent(caption) + (theme === 'dark' ? '&theme=dark' : ''));
    await f.evaluate(([d, w, h]) => window.__setShot(d, w, h), ['data:image/png;base64,' + shotPng.toString('base64'), w, h]);
    await sleep(200); await f.screenshot({ path: path.join(OUT, name) }); await f.close(); console.log('  ✓', name);
  }
                                                                              
                                    
  async function popupShot(contentPage, theme, after) {
    if (theme) await sw.evaluate((t) => setSettings({ theme: t }), theme);
    const p = await ctx.newPage(); await p.setViewportSize({ width: 340, height: 600 });
                                                                                     
                                                                                 
                                                                           
                                                                            
    await p.goto(`chrome-extension://${id}/popup.html`); await contentPage.bringToFront(); await p.reload(); await sleep(700);
    if (after) await after(p);
    const full = await p.evaluate(() => document.body.scrollHeight);
    let h = Math.min(600, full);
    if (full > 600) {
                                                                              
                                                                                    
                                                                          
                                                                              
                                                                            
                                                                              
                              
      h = await p.evaluate((cap) => {
        const els = document.querySelectorAll('body > *, main > *, footer > *');
        let best = 0;
        for (const el of els) {
                                                                               
                                                                             
                                                                          
          if (el.hidden || getComputedStyle(el).position === 'fixed') continue;
          const rect = el.getBoundingClientRect();
          if (rect.height <= 0 || rect.bottom > cap) continue;
          if (rect.bottom > best) best = rect.bottom;
        }
                                                                             
                                                                          
                                                                            
                                                                            
                         
        if (best < cap * 0.65) return cap;
        return Math.round(best) || cap;
      }, 600);
    }
    await p.setViewportSize({ width: 340, height: h });
    const png = await p.screenshot(); await p.close(); if (theme) await sw.evaluate(() => setSettings({ theme: 'auto' })); return { png, w: 340, h };
  }
  console.log('Capturing…');
                                                                    
                                                                           
                                                                           
                                                                             
                                                                
  let page = await ctx.newPage(); await page.goto('https://secure-paypa1-login.com:5600/brand-visual.html'); await sleep(900);
  let s = await popupShot(page); await compose('01-popup-dangerous.png', 'Spots fake login pages before you type', s.png, s.w, s.h); await page.close();
                                                                             
                                                                             
                                                                           
                                                     
  await seedStats();
  await sw.evaluate(() => setSettings({ theme: 'dark' }));
                                                                             
                                                                            
                                    
  const OW = 980;
  page = await ctx.newPage(); await page.setViewportSize({ width: OW, height: 700 }); await page.goto(`chrome-extension://${id}/options.html#stats`); await sleep(600);
                                                                               
                                                                    
  await page.click('#statsseg button[data-p="30"]'); await sleep(500);
                                                                          
                                                                    
                                                                  
  const OH = Math.min(920, Math.max(640, await page.evaluate(() => Math.ceil(document.documentElement.scrollHeight))));
  await page.setViewportSize({ width: OW, height: OH }); await sleep(400);
  await compose('02-statistics.png', 'See the work it does — counted on your device, never sent', await page.screenshot(), OW, OH, 'dark'); await page.close();
  await sw.evaluate(() => setSettings({ theme: 'auto' }));
                                                                       
                                                                            
                                                                          
                     
  page = await ctx.newPage(); await page.setViewportSize({ width: 900, height: 360 }); await page.goto(BASE + '/brand-visual.html'); await page.locator('.phishguard-banner').waitFor({ timeout: 8000 });
  await compose('03-banner-rescue.png', 'One click back to the real site', await page.screenshot(), 900, 360); await page.close();
                                                                            
                                                                              
                                                                    
                                                                    
                                                    
  page = await ctx.newPage(); await page.goto(BASE + '/clean.html'); await sleep(600);
  s = await popupShot(page, null, async (pp) => {
    await pp.waitForFunction(() => document.querySelectorAll('#langdd .langitem').length > 0);
    await pp.click('#langbtn');
    await pp.locator('#langdd').waitFor({ state: 'visible' });
                                                                                 
                                                                            
                                                      
    await pp.evaluate(() => { document.getElementById('langdd').scrollTop = 0; document.documentElement.scrollTop = 0; });
    await sleep(200);
  });
  await compose('04-language-picker.png', 'Speaks your language — 20 of them', s.png, s.w, s.h); await page.close();
                     
  page = await ctx.newPage(); await page.setViewportSize({ width: 1100, height: 640 }); await page.goto(BASE + '/drainer.html'); await sleep(700); await page.click('#go'); await page.locator('.phishguard-overlay').waitFor({ timeout: 6000 });
  await compose('05-wallet-guard.png', 'Stops wallet drainers and scare pop-ups', await page.screenshot(), 1100, 640); await page.close();
                                                                         
                                                                      
                                                                          
                                                                        
  page = await ctx.newPage(); await page.goto(BASE + '/qr-quishing.html'); await sleep(700);
  s = await popupShot(page, null, async (pp) => {
    await pp.locator('#qrcheck').waitFor({ state: 'visible' });
    await pp.evaluate(() => { document.getElementById('qrcheck').open = true; });
    await pp.click('#qrscanbtn');
    await pp.locator('#qrresult').waitFor({ state: 'visible', timeout: 8000 });
    await pp.locator('#qrlist li').first().waitFor({ timeout: 8000 });
                                                                          
                                                                            
                                                                       
                                                                            
                                                                        
    await pp.evaluate(() => {
      for (const sel of ['#siteacts', '#whypanel', '#actions', '#recent', '#shopcard', '#privacycard']) { const el = document.querySelector(sel); if (el) el.hidden = true; }
      const tiles = document.getElementById('tile-since'); if (tiles && tiles.parentElement) tiles.parentElement.hidden = true;
      document.documentElement.scrollTop = 0; document.body.scrollTop = 0;
    });
    await sleep(300);
  });
  await compose('06-qr-scan.png', 'Checks QR codes before your phone does', s.png, s.w, s.h); await page.close();
                                                                              
                                                                             
                                                                           
                                                                  
  await sw.evaluate(async () => { await applyNetworkRules(['||secure-paypa1-login.com^'], true); });
  page = await ctx.newPage(); await page.setViewportSize({ width: 900, height: 560 });
  await page.goto('https://secure-paypa1-login.com:5600/brand-visual.html'); await page.waitForURL(/blocked\.html#/, { timeout: 8000 }); await sleep(900);
  await compose('07-blocked-page.png', 'Known scam sites never even load', await page.screenshot(), 900, 560); await page.close();
  await ctx.close(); server.kill(); console.log('Done →', OUT);
})().catch((e) => { console.error(e); process.exit(1); });
