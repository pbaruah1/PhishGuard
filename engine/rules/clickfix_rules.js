(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                              
                                                                               
                                                                              
                                                                             
                                                                             
                                                                               
                                                                
  const WIN_RUN_RE = /\b(win(dows)?(\s*(key|logo))?\s*(\+|plus|and|,)\s*r)\b|⊞\s*(\+|plus)?\s*r\b/i;
  const PASTE_RE = /\bctrl\s*(\+|plus|and|,)\s*v\b|\bpaste\s+(it|this|the (command|code|text))\b/i;
  const RUN_TARGET_RE = /\b(run\s+(dialog|box|window|command|prompt)|powershell|windows\s+terminal|command\s+prompt|cmd(\.exe)?\b)/i;
  const CAPTCHA_RE = /\b(verify\s+(that\s+)?you\s*('?re|\s*are)\s+(a\s+)?human|i\s*('?m|\s*am)\s+not\s+a\s+robot|robot\s+verification|human\s+verification|verification\s+(step|required|id)|captcha)\b/i;

  function scoreClickFix(input) {
    const s = input || {};
    const text = String(s.text || '');
    const reasons = [];
    const flags = [];
    const winRun = WIN_RUN_RE.test(text);
    const paste = PASTE_RE.test(text);
    const runTarget = RUN_TARGET_RE.test(text);
    const captcha = CAPTCHA_RE.test(text);
    const instructionHits = (winRun ? 1 : 0) + (paste ? 1 : 0) + (runTarget ? 1 : 0);
    const payload = s.clipboardLevel === 'dangerous';

    let level = 'none';
    if (payload && (winRun || paste || runTarget || captcha)) {
                                                                       
                                                                      
                              
      level = 'dangerous';
      reasons.push({ code: 'clickfixPasteRun', kind: 'clipboard' });
    } else if (winRun && paste && captcha) {
                                                                             
      level = 'dangerous';
      reasons.push({ code: 'clickfixFakeCaptcha', kind: 'clipboard' });
    } else if (winRun && (paste || runTarget)) {
      level = 'suspicious';
      reasons.push({ code: 'clickfixWinR', kind: 'clipboard' });
    } else if (payload) {
      level = 'suspicious';
    }
    if (level === 'dangerous') flags.push('clickfix');
    if (captcha && level !== 'none') reasons.push({ code: 'clickfixCaptchaDisguise', kind: 'clipboard' });
    return { level, reasons, flags };
  }

  return { scoreClickFix };
});
