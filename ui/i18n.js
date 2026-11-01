                                                                          
                                                                             
                                                                              
  
                                                                             
                                                                            
                                                                               
                                                                               
                                                                            
                                                                               
                                                                         
                                                                               
                              
(function (root) {
  'use strict';
  const api = root.browser || root.chrome;
                                                                               
                                                                                
                                                                    
  const reasons = () => root.SSReasons;
                                                                             
                                                                           
                                                                                              
                                                                    
  function t(key, subs) {
    try { const R = reasons(); if (R && R.tOverride) { const o = R.tOverride(key, subs); if (o) return o; } } catch (_) {}
    try { const m = api.i18n.getMessage(key, subs); return m || ''; } catch (_) { return ''; }
  }
  function apply(scope) {
    const el = scope || document;
    el.querySelectorAll('[data-i18n]').forEach((n) => { const v = t(n.getAttribute('data-i18n')); if (v) n.textContent = v; });
    el.querySelectorAll('[data-i18n-ph]').forEach((n) => { const v = t(n.getAttribute('data-i18n-ph')); if (v) n.setAttribute('placeholder', v); });
    el.querySelectorAll('[data-i18n-title]').forEach((n) => { const v = t(n.getAttribute('data-i18n-title')); if (v) n.setAttribute('title', v); });
    el.querySelectorAll('[data-i18n-aria]').forEach((n) => { const v = t(n.getAttribute('data-i18n-aria')); if (v) n.setAttribute('aria-label', v); });
                                                         
    const titleKey = document.documentElement.getAttribute('data-i18n-doctitle');
    if (titleKey) { const v = t(titleKey); if (v) document.title = v; }
    try {
                                                                             
                                                                                 
      const R = reasons();
      const rtl = R ? R.isRTL() : false;
      document.documentElement.setAttribute('dir', rtl ? 'rtl' : 'ltr');
    } catch (_) {}
  }

                                                                       
                                                                         
                                                                           
                                   
  const ready = (async () => {
    const R = reasons();
    if (!R || !R.messagesToDict || !R.LOCALES) return '';
    let lang = '';
    try {
                                                                              
                                                                              
                                                           
      const cur = await api.storage.local.get('settings');
      lang = (cur && cur.settings && cur.settings.uiLang) || '';
    } catch (_) { return ''; }
    if (!lang || lang === 'auto' || R.LOCALES.indexOf(lang) === -1) return '';
    try {
      const res = await fetch(api.runtime.getURL('_locales/' + lang + '/messages.json'));
      R.setOverride(lang, R.messagesToDict(await res.json()));
    } catch (_) { return ''; }
    try { apply(); } catch (_) {                                              }
    return lang;
  })();

  root.SSi18n = { t, apply, ready };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => apply());
  else apply();
})(typeof globalThis !== 'undefined' ? globalThis : self);
