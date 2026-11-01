                                                                       
                                                                        
                                                                           
                                                                         
                           
                                                                                           
const { chromium } = require('@playwright/test'); const path = require('path'); const fs = require('fs');

                                                                              
                                                                              
                                                                            
                                                          
const ICON = 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, '../assets/icons/icon128.png')).toString('base64');
const BIG_ICON = (big) => `<img src="${ICON}" alt="" style="position:absolute;right:${big ? 140 : 26}px;top:50%;transform:translateY(-50%);width:${big ? 300 : 118}px;height:${big ? 300 : 118}px;filter:drop-shadow(0 18px 40px rgba(0,0,0,.35))">`;

const html = (w, h, big, shotDataUrl) => `<!doctype html><html><body style="margin:0;width:${w}px;height:${h}px;background:#0B6E4F;font:${big ? 44 : 22}px/1.15 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#fff;position:relative;overflow:hidden">
<div style="position:absolute;inset:0;background:radial-gradient(120% 80% at 100% 100%,rgba(255,255,255,.12),transparent 60%)"></div>
<div style="position:absolute;left:${big ? 64 : 24}px;top:${big ? 150 : 70}px;max-width:${big && shotDataUrl ? 600 : big ? 640 : 236}px">
  <div style="display:flex;align-items:center;gap:${big ? 16 : 9}px;font-weight:600;letter-spacing:-.01em"><img src="${ICON}" alt="" style="width:${big ? 56 : 30}px;height:${big ? 56 : 30}px">PhishGuard</div>
  <div style="opacity:.9;font-size:${big ? 26 : 15}px;margin-top:${big ? 14 : 8}px">Scam &amp; phishing protection that runs on your device.</div>
</div>
${shotDataUrl
  ? `<img src="${shotDataUrl}" style="position:absolute;right:40px;top:50%;transform:translateY(-50%);width:560px;height:auto;border-radius:16px;box-shadow:0 24px 64px rgba(0,0,0,.4)">`
  : BIG_ICON(big)}
</body></html>`;

                                                                            
                                                                            
                                                                     
                                                                             
                                                              
async function cropPopupCard(browser) {
  const src = fs.readFileSync(path.join(__dirname, '../store/screenshots/01-popup-dangerous.png'));
  const p = await browser.newPage();
  await p.setContent(`<img id="src" src="data:image/png;base64,${src.toString('base64')}">`);
  const dataUrl = await p.evaluate(async () => {
    const img = document.getElementById('src');
    await img.decode();
    const w = img.naturalWidth, h = img.naturalHeight;
    const full = document.createElement('canvas'); full.width = w; full.height = h;
    const fctx = full.getContext('2d'); fctx.drawImage(img, 0, 0);
    const data = fctx.getImageData(0, 0, w, h).data;
                                                                       
                                                                          
                                                                             
                           
    let minX = w, minY = h, maxX = 0, maxY = 0;
    const startX = Math.floor(w * 0.45);
    for (let y = 100; y < h; y++) {
      for (let x = startX; x < w; x++) {
        const i = (y * w + x) * 4;
        const lum = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
        if (lum > 140) {
          if (x < minX) minX = x; if (x > maxX) maxX = x;
          if (y < minY) minY = y; if (y > maxY) maxY = y;
        }
      }
    }
    if (maxX <= minX || maxY <= minY) return null;                                                 
    const pad = 4;
    minX = Math.max(0, minX - pad); minY = Math.max(0, minY - pad);
    maxX = Math.min(w, maxX + pad); maxY = Math.min(h, maxY + pad);
    const cw = maxX - minX;
                                                                             
                                                                          
                                                                         
                                                                           
                                                                              
    const ch = Math.min(maxY - minY, Math.round(cw * 0.8));
    const out = document.createElement('canvas'); out.width = cw; out.height = ch;
    out.getContext('2d').drawImage(full, minX, minY, cw, ch, 0, 0, cw, ch);
    return out.toDataURL('image/png');
  });
  await p.close();
  return dataUrl;
}

(async () => { const b = await chromium.launch();
  const shotDataUrl = await cropPopupCard(b);
  if (!shotDataUrl) console.log('  ! could not locate popup card in 01-popup-dangerous.png — marquee falls back to the shield icon');
  for (const [w, h, name, big] of [[440, 280, 'promo-small-440x280.png', false], [1400, 560, 'promo-marquee-1400x560.png', true]]) {
    const p = await b.newPage({ viewport: { width: w, height: h } });
    await p.setContent(html(w, h, big, big ? shotDataUrl : null));
    await p.screenshot({ path: path.join(__dirname, '../store', name), omitBackground: false });
    console.log('  ✓', name);
    await p.close();
  }
  await b.close(); })();
