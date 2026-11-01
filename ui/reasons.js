                                                      
  
                                                                            
                                                                               
                                                                               
                                                                               
                                             
  
                                                                              
                                                                            
                           
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSReasons = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                                
                                                                              
                                                            
  const EN = {
                                            
    ipHost: "The destination uses a numeric IP address rather than a conventional domain name.",
    atSymbol: "An at-sign in the address can make the visible text differ from the actual destination host.",
    urlUserInfo: "The address contains login information before the @ sign, which can disguise the actual destination host.",
    executableScheme: "This link uses an executable or active-content URL scheme rather than an ordinary web address.",
    punycodeHost: "The domain is encoded with punycode, which can appear in look-alike domain attacks.",
    idnHomograph: "Some characters in this domain visually resemble the real $1 name.",
    brandLookalike: "The domain has features commonly seen in attempts to imitate a familiar brand.",
    suspiciousTld: "This top-level domain has a higher-than-usual presence in scam reports.",
    noHttps: "This address does not use HTTPS, so network traffic may be readable or modifiable in transit.",
    manySubdomains: "The hostname contains an unusually large number of nested subdomains.",
    urgencyKeywords: "The address combines several urgency or account-security terms.",
    randomHost: "The host label has a high-entropy pattern often seen in disposable campaign domains.",
                                                                                                                                
    brandFuzzyMatch: "The hostname resembles $1’s known domain. Inspect the exact spelling before signing in.",
    deepSubdomainChain: "Several nested subdomains make the site owner harder to recognize at a glance.",
    longHostLabel: "An unusually long hostname label may be hiding brand-like words or misleading structure.",
    shortenerHost: "This link uses the shortener $1, so the final site cannot be judged from this address alone.",
    riskAbusedTld: "Domain's top-level domain ($1) has a high rate of scam abuse in PhishGuard's threat-feed risk tables.",
    riskDynamicHost: "This domain uses dynamic DNS or a free-hosting service that appears frequently in abuse reports.",
                                                                                             
    brandForeignSuffix: "The address uses $1’s name with an unfamiliar .$2 ending.",
                                                                                                      
    gatewayRedirect: "A redirect through $1 led to a different destination, which can conceal the final site.",
                                                                        
    feedBlock: "This domain matches PhishGuard's threat feed, confirmed by $1 independent source(s).",
    feedWarn: "This domain matches a lower-confidence entry in PhishGuard's threat feed ($1 source(s)) — proceed carefully.",
    remoteDestinationConfirmedMalicious: "An independent remote check confirmed malicious behavior at this link destination.",
    linkedDestinationFeedBlock: "A linked destination matches PhishGuard's exact-confirmed high-confidence blocklist.",
    aiEvidence: "$1",
                                                                                        
    newDomain: "The domain appears in a newly registered domain list; very new sites have little reputation history.",
                                                                                             
    newDomainUnvisited: "This domain appears on a newly registered domains list and has no prior visit history in PhishGuard.",
                                            
    credentialFormForeignDomain: "A password form sends credentials to a different domain from the page showing it.",
                                                                                                                     
    crossOriginCredPost: "The form sends password or card-like data to $1, which differs from the current site.",
    hiddenIframes: "The page contains hidden frames that could load content or collect input out of view.",
    scamPhrase: "The page contains giveaway or reward language associated with common scam patterns: “$1”.",
    seedPhraseAsk: "The page asks for a wallet recovery phrase. Anyone who obtains it can take control of the wallet.",
    brandImpersonationContent: "The page imitates the appearance or wording of $1 without using its verified domain.",
    deliveryFeeScam: "The page imitates $1 and requests card details for a package fee. Confirm delivery notices through the carrier’s official site.",
    brandIconMismatch: "The page displays an icon associated with $1 while using a different website address.",
                                                                                           
    credentialFormOnTenantHost: "A password form appears on shared hosting ($1), where unrelated users can publish their own pages.",
    brandInTenantHost: "$1 appears in a shared-hosting address that requests a password.",
                                                  
    contentPhishingPattern: "The combination of wording and page layout resembles previously observed phishing pages.",
    downloadDisguisedExecutable: "The shared item uses a document or image-looking filename followed by an executable extension. Do not open it.",
    downloadExecutableSurface: "The page exposes an executable or installer download ($1). Verify the publisher and file through an independent security scanner before opening it.",
    downloadScriptSurface: "The page exposes a script or command file that can execute actions on the device. Do not run it unless you can verify its origin and contents.",
    downloadSafetyEvasion: "The page asks you to weaken or bypass device security before opening a file. This is a strong malware-delivery warning.",
    downloadDeceptivePrompt: "The page uses an update or verification story to persuade you to download or run a file. Verify updates through the operating system or application itself.",
    downloadArchivePressure: "The shared archive is paired with instructions or pressure that may conceal an executable payload. Do not extract or run unexpected contents.",
                                     
    techScamScareText: "The page uses threatening technical-support language: “$1”.",
    techScamPhoneAsk: "The page pressures visitors to call a support number, a frequent pattern in impersonation scams.",
    techScamFakeAlert: "This appears to be a web-based system alert demanding attention. Verify alerts through the operating system, not the page.",
    techScamFullscreen: "The page requested fullscreen, which can be used to make scam warnings harder to dismiss.",
    techScamAlarmAudio: "The page played alarm-like audio that can pressure visitors into acting quickly.",
    techScamDialogFlood: "The page generated repeated dialogs that can obstruct normal navigation.",
    techScamHistoryTrap: "The page appears to interfere with normal Back navigation.",
                                   
    walletBlindSign: "The wallet was asked to sign opaque data whose effects are not obvious from the request.",
    walletPermitApproval: "This Permit-style signature can grant later token or NFT transfers without another prompt.",
    walletDelegation7702: "This EIP-7702 request delegates account execution to a contract; review the target and its permissions carefully.",
    walletSetApprovalAll: "This request can authorize a contract to transfer every NFT in a collection.",
    walletUnlimitedApprove: "This approval may let a contract spend an unlimited amount of the selected token.",
    walletTokenApprove: "This request grants a contract permission to spend the selected token amount.",
                                     
    clickfixPasteRun: "The page instructs you to paste and execute a system command. Treat command-paste verification as high risk.",
    clickfixFakeCaptcha: "The CAPTCHA-like step asks you to open the Windows Run dialog and execute a command, which real CAPTCHA tests do not require.",
    clickfixWinR: "The page directs you to the Windows Run box and asks you to paste text into it.",
    clickfixCaptchaDisguise: "The command instructions are presented as a human-verification task.",
                                      
    clipboardCommand: "A system command was detected on the clipboard. Do not paste it into a terminal or Run dialog unless you independently understand it.",
    clipboardCryptoAddress: "A cryptocurrency address appeared on the clipboard. Verify the destination independently before using it.",
                                       
    fakeUpdatePrompt: "A web page offers a browser or system update download. Updates should be obtained from the browser or operating system’s own updater.",
                                    
    msgOtpAsk: "The message asks for an OTP, PIN, passcode, or password. Treat requests to share these secrets as high risk.",
    msgScamWording: "The message contains wording associated with common scams: “$1”.",
    msgUrgencyDeadline: "The message uses an artificial deadline or urgent demand to pressure a quick response.",
    msgDangerousLink: "A link in the message triggered address-risk checks: $1.",
                                                                            
                                                                    
                                                                             
                                                                     
    qrCodeDestination: "A QR code resolves to $1. Review the destination before opening it on another device.",
    qrExternalAction: "The QR payload attempts to open an app or use a link type that is not a standard website. Review it before continuing.",
    qrMalformedDestination: "The QR code contains a malformed web address, so its destination cannot be reliably checked.",
                                                                                      
    shop_countdownReset: "The offer timer behaves like a resettable countdown.",
    shop_countdownReset_detail: "The offer timer appears to reset between visits, weakening the claim that the deal is about to end.",
    shop_offPlatformPay: "Checkout requests an unusually hard-to-reverse payment method.",
    shop_offPlatformPay_detail: "Checkout asks for a hard-to-reverse method such as a wire, payment app, or crypto transfer.",
    shop_fakeScarcity: "The page uses pressure based on artificial scarcity.",
    shop_fakeScarcity_detail: "The page uses injected scarcity language such as “only a few left” or viewer counters.",
    shop_badgeHotlink: "The trust badge is not independently verifiable.",
    shop_badgeHotlink_detail: "A “secure” or “verified” badge appears to be a linked or embedded image rather than independently verifiable proof.",
    shop_missingContact: "Basic seller contact information is missing.",
    shop_missingContact_detail: 'The store lacks basic business contact details, making the seller harder to verify.'
  };

                                                                          
                                                                           
  function i18n() {
    try {
      if (typeof browser !== 'undefined' && browser && browser.i18n) return browser.i18n;
      if (typeof chrome !== 'undefined' && chrome && chrome.i18n) return chrome.i18n;
    } catch (_) {}
    return null;
  }

                                                                               
                                                                              
                                                                         
                                                                              
                                                        
  const LRI = '⁦', PDI = '⁩';
  function bidiWrap(s) { return s == null ? '' : LRI + String(s) + PDI; }

                                                                                
                                                                                
                                                                          
                                                                         
                                                                       
                                                                               
                                                                             
                                                                          
  function subst(tmpl, params, isolate) {
    return String(tmpl).replace(/\$\$|\$(\d)/g, (m, i) => {
      if (i === undefined) return '$';
      const v = params && params[i - 1];
      if (v == null) return '';
      return isolate ? bidiWrap(v) : String(v);
    });
  }

                                                                              
                                                                              
                                                                           
                                                                               
                                                                            
                                                                               
                                                                                
                                                                               
                                                                             
                                                                                
                                                                            
                                                                              
                                      
    
                                                                               
                                                                           
                                                                          
                                  
  const LOCALES = ['ar', 'bn', 'de', 'en', 'es', 'fr', 'hi', 'id', 'it', 'ja', 'ko',
    'mr', 'pt_BR', 'ru', 'ta', 'te', 'tr', 'ur', 'vi', 'zh_CN'];
                                                                               
                                                                               
                                                      
  const LANG_NAMES = {
    ar: 'العربية', bn: 'বাংলা', de: 'Deutsch', en: 'English', es: 'Español',
    fr: 'Français', hi: 'हिन्दी', id: 'Bahasa Indonesia', it: 'Italiano',
    ja: '日本語', ko: '한국어', mr: 'मराठी', pt_BR: 'Português (Brasil)',
    ru: 'Русский', ta: 'தமிழ்', te: 'తెలుగు', tr: 'Türkçe', ur: 'اردو',
    vi: 'Tiếng Việt', zh_CN: '中文（简体）'
  };

                                                                                
                                                                                 
                                                                               
                                                                             
                                           
  function intlTag(lang) { return String(lang || '').replace('_', '-'); }

  let overrideLang = '', overrideDict = null;

                                                                      
  function setOverride(lang, dict) {
    const ok = !!lang && !!dict && typeof dict === 'object';
    overrideLang = ok ? String(lang) : '';
    overrideDict = ok ? dict : null;
  }
                                                                      
  function overrideLanguage() { return overrideLang; }

                                                                            
                                                                                
                                                                               
                                                              
  function tOverride(key, subs) {
    if (!overrideDict || !key) return '';
    const tmpl = overrideDict[key];
    if (typeof tmpl !== 'string' || !tmpl) return '';
    const params = subs == null ? [] : (Array.isArray(subs) ? subs : [subs]);
                                                                                
                                                                     
    return subst(tmpl, params, false);
  }

  function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

                                                                           
                                                                               
                                                                         
                                                                             
                                                                                
                                                                       
                    
  function messagesToDict(json) {
    const out = {};
    if (!json || typeof json !== 'object') return out;
    for (const key of Object.keys(json)) {
      const entry = json[key];
      if (!entry || typeof entry.message !== 'string') continue;
      let msg = entry.message;
      const ph = entry.placeholders;
      if (ph && typeof ph === 'object') {
        for (const name of Object.keys(ph)) {
          const def = ph[name];
          const m = /^\$([1-9])$/.exec(String((def && def.content) || ''));
          if (!m) continue;                                                             
                                                                               
                                                                          
                                                                            
                                                             
          msg = msg.replace(new RegExp('\\$' + escapeRe(name) + '\\$', 'gi'), () => '$' + m[1]);
        }
      }
      out[key] = msg;
    }
    return out;
  }

                                                                                
                                                                         
                                                                              
                              
  function resolveReason(r) {
    if (typeof r === 'string') return r;
    if (!r || !r.code) return '';
    const params = (r.params || []).map(String);
    const isolated = params.map(bidiWrap);
    const over = tOverride('reason_' + r.code, isolated);
    if (over) return over;
    const api = i18n();
    if (api) {
      try { const m = api.getMessage('reason_' + r.code, isolated); if (m) return m; } catch (_) {}
    }
    return subst(EN[r.code] || r.code, params, true);
  }

                                                               
  function reasonToEnglish(r) {
    if (typeof r === 'string') return r;
    if (!r || !r.code) return '';
    return subst(EN[r.code] || r.code, r.params || []);
  }

                                                           
  function reasonKind(r) { return (r && r.kind) || 'page'; }

                                                                        
                                                                          
                           
  function isRTL(lang) {
    let l = lang;
    if (l == null) {
      l = overrideLang;
      if (!l) {
        const api = i18n();
        try { l = api && api.getUILanguage ? api.getUILanguage() : ''; } catch (_) { l = ''; }
      }
    }
    return /^(ar|he|fa|ur)\b/i.test(String(l || ''));
  }

                                                                              
                                                                             
                                                                      
                                                                              
                                                                                    
                                                    

                                                                             
                                                                           
                                                                            
                                                              
  function defangHost(host) {
    const s = String(host || '');
    const i = s.lastIndexOf('.');
    return i === -1 ? s : s.slice(0, i) + '[.]' + s.slice(i + 1);
  }

                                                                   
                                                                             
                                                                            
                                                                           
                                                                            
                                                                            
                                                     
  function buildCopyReportText(o) {
    const opts = o || {};
    const lines = [opts.headerLine || '', opts.verdictLine || ''];
    const signals = (opts.reasons || []).filter(Boolean).slice(0, 4);
    if (signals.length) {
      lines.push(opts.signalsLabel || '');
      for (const s of signals) lines.push('- ' + s);
    }
    lines.push(opts.footerLine || '');
    return lines.filter((l) => l !== '').join('\n');
  }

                                                                      
                                                                            
                                                                      
                                                                    
                                                                      
                                                                     
                                                                         
                                                                        
              
  function execCommandCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.opacity = '0'; ta.style.left = '-9999px';
      (document.body || document.documentElement).appendChild(ta);
      ta.focus(); ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch (_) { return false; }
  }
  function copyToClipboard(text) {
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text).then(() => true).catch(() => execCommandCopy(text));
      }
    } catch (_) {}
    return Promise.resolve(typeof document !== 'undefined' ? execCommandCopy(text) : false);
  }

  return { resolveReason, reasonToEnglish, reasonKind, EN, isRTL, bidiWrap,
    LOCALES, LANG_NAMES, setOverride, overrideLanguage, tOverride, messagesToDict, intlTag,
    defangHost, buildCopyReportText, copyToClipboard };
});
