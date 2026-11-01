(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('../core/constants') : root.PhishGuard,
                       req ? require('../detection/features') : root.PhishGuard,
                       req ? require('./brand_match') : root.PhishGuard,
                       req ? require('./site_signals') : root.PhishGuard,
                       req ? require('./risk_rules') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C, F, BM, Sig, Risk) {
  'use strict';
  const { FEATURE_NAMES } = C;
  const clamp = (x) => Math.max(0, Math.min(1, x));
                                                                                  
                                                                             
                                                                            
                                                              
  const FUZZY_BRAND_WEIGHT = { strongest: 0.55, strong: 0.50, weak: 0.25 };

                                                                      
                                                                         
                                                                        
                                                                             
                                                                            
  function scoreUrl(urlString, riskTlds) {
    const candidate = String(urlString == null ? '' : urlString).trim();
    if (/^(?:javascript|vbscript):/i.test(candidate) || /^data:text\/html/i.test(candidate)) {
      return { score: 1, reasons: [{ code: 'executableScheme', kind: 'link' }], riskScore: 0 };
    }
    const v = F.extractUrlFeatures(candidate);
    const get = (n) => v[FEATURE_NAMES.indexOf(n)];
    const parsedUrl = F.parseHost(candidate);
    const host = parsedUrl.host;
    const reasons = [];
    let score = 0;
                                                                             
                                                                          
                                                                            
                                                              
                                                                     
                                                                    
                                                                         
                                                                          
                                                                           
                                                                       
                                                                             
                                                                          
                                           
    let riskScore = 0;

    if (get('has_ip_host')) { score += 0.45; reasons.push({ code: 'ipHost', kind: 'link' }); }
    if (get('has_at_symbol')) {
      const hasUserInfo = !!(parsedUrl.url && (parsedUrl.url.username || parsedUrl.url.password));
      if (hasUserInfo) {
        score = Math.max(score, 0.82);
        reasons.push({ code: 'atSymbol', kind: 'link' });
        reasons.push({ code: 'urlUserInfo', kind: 'link' });
      } else if (!parsedUrl.url) {
        score += 0.20;
        reasons.push({ code: 'atSymbol', kind: 'link' });
      }
    }
    if (get('has_punycode')) { score += 0.30; reasons.push({ code: 'punycodeHost', kind: 'link' }); }
                                                                             
                                                                          
                                                                            
                                                                             
    if (get('has_punycode') && F.idnHomographBrand) {
      const hb = F.idnHomographBrand(F.parseHost(urlString).host);
      if (hb) { score += 0.50; reasons.push({ code: 'idnHomograph', kind: 'brand', params: [hb] }); }
    }
    if (get('brand_lookalike')) { score += 0.45; reasons.push({ code: 'brandLookalike', kind: 'brand' }); }
    if (get('suspicious_tld')) { score += 0.20; reasons.push({ code: 'suspiciousTld', kind: 'link' }); }
    if (!get('is_https')) { score += 0.15; reasons.push({ code: 'noHttps', kind: 'link' }); }
    if (get('num_subdomains') >= 3) { score += 0.15; reasons.push({ code: 'manySubdomains', kind: 'link' }); }
    const tok = get('suspicious_token_count');
    if (tok >= 2) { score += Math.min(0.25, 0.08 * tok); reasons.push({ code: 'urgencyKeywords', kind: 'link' }); }
    if (get('host_entropy') > 3.5 && get('host_length') > 20) { score += 0.10; reasons.push({ code: 'randomHost', kind: 'link' }); }

                                                                               
                                                                          
                                                                        
                                                                       
                                                                          
                                                                              
                                                                                
                                                                              
                                                                          
                                                                      
                                   
    const fsx = BM && BM.brandForeignSuffix && BM.brandForeignSuffix(host);
    if (BM && BM.allowlistBrandMatch && !BM.allowlistBrandMatch(host)) {
      const fuzzy = BM.fuzzyBrandMatch(host);
                                                                          
                                                                            
                                                                      
                                                                              
                                                                           
                                                                          
                                                                          
      const duplicatesForeignSuffix = fuzzy && fsx && fuzzy.brand === fsx.brand &&
        ['c', 'd', 'e'].includes(fuzzy.rule);
      if (fuzzy && !duplicatesForeignSuffix) {
        score += FUZZY_BRAND_WEIGHT[fuzzy.grade] || 0;
        reasons.push({ code: 'brandFuzzyMatch', kind: 'brand', params: [C.brandDisplayName(fuzzy.brand)] });
      }
    }

    if (fsx) {
      score += 0.60;
      reasons.push({ code: 'brandForeignSuffix', kind: 'brand', params: [C.brandDisplayName(fsx.brand), fsx.suffix] });
    }

                                                                   
                                                                                  
                                                        
    if (Sig && Sig.scoreSiteSignals) {
      const site = Sig.scoreSiteSignals(host);
      score += site.score;
      for (const r of site.reasons) reasons.push(r);
    }

                                                                                    
                                                                        
    if (Risk && Risk.abusedTldWeight && riskTlds) {
      const tldHit = Risk.abusedTldWeight(host, riskTlds);
      if (tldHit) { score += 0.20; riskScore += 0.20; reasons.push({ code: 'riskAbusedTld', kind: 'link', params: [tldHit.tld] }); }
    }

    return { score: clamp(score), reasons, riskScore };
  }

                                                                                     
  const registrableDomain = C.registrableDomain;

  function scoreDom(signals) {
    const s = signals || {};
    const reasons = [];
    const flags = [];
    let score = 0;
    let independentScore = 0;
    let brand;                                                                    
    const pageDomain = registrableDomain(s.pageHost);
    const displayName = (key) => C.brandDisplayName ? C.brandDisplayName(key) : key;

    if (s.hasPasswordField) {
      const AUTH = C.KNOWN_AUTH_PROVIDERS || [];
      const foreign = (s.passwordFormActions || []).some((action) => {
        try {
          const h = new URL(action, 'https://' + (s.pageHost || 'x')).hostname;
          const actionDomain = registrableDomain(h);
          if (actionDomain === pageDomain) return false;
                                                                             
          if (AUTH.includes(actionDomain)) return false;
          return true;
        } catch (_) { return false; }
      });
      if (foreign) {
        score = Math.max(score, 0.9);
        independentScore = Math.max(independentScore, 0.9);
        flags.push('credential-form-foreign-domain');
        reasons.push({ code: 'credentialFormForeignDomain', kind: 'page' });
      }
    }

                                                                              
                                                                               
                                                                         
                                                                           
                                                                              
                                                                        
                                                                          
                                                                 
                                                                        
                                                                             
                                                                             
                                                                          
                                                                              
                                                                          
    const BRAND_DOMAINS = C.BRAND_DOMAINS || {};
    function isOnBrand(brandKey) {
      if (C.isVerifiedNamespace && C.isVerifiedNamespace(String(s.pageHost || ''))) return true;
      const legit = BRAND_DOMAINS[brandKey] || [];
      const host = String(s.pageHost || '').toLowerCase();
      const parts = C.registrableParts(host);
      const tld = parts.suffix.split('.').pop();
      const ccShaped = (C.MULTI_LABEL_SUFFIXES || []).includes(parts.suffix) || tld.length === 2;
                                                                              
                                                                            
                                                                            
                                                                               
                                                                     
      const b = (C.BRANDS_BY_KEY || {})[brandKey];
      const exactBrandCc = parts.sld === brandKey && ccShaped && !(C.SUSPICIOUS_TLDS || []).includes(tld) &&
        (!b || b.ccPolicy !== 'closed' || (b.suffixes || []).includes(parts.suffix));
      return exactBrandCc || legit.some((d) => pageDomain === d || host.endsWith('.' + d));
    }

                                                                              
                                                                            
                                                                        
                                                                          
    const tenant = C.tenantLabel ? C.tenantLabel(s.pageHost) : null;
    if (tenant && s.hasPasswordField) {
      score += 0.45;
      independentScore += 0.45;
      reasons.push({ code: 'credentialFormOnTenantHost', kind: 'page', params: [String(s.pageHost || '').slice(String(tenant).length + 1)] });
      const tb = BM && BM.tenantBrandToken ? BM.tenantBrandToken(tenant) : null;
      if (tb && !isOnBrand(tb)) {
        score = Math.max(score, 0.9); independentScore = Math.max(independentScore, 0.9); flags.push('brand-impersonation-tenant'); brand = brand || tb;
        reasons.push({ code: 'brandInTenantHost', kind: 'brand', params: [displayName(tb)] });
      }
    }

    if ((s.hiddenIframeCount || 0) > 0) {
      // Hidden frames are common for analytics, ads, payments, and SSO.
      // Treat them as a weak clue only; a frame's presence is not proof of fraud.
      score += Math.min(0.12, 0.04 * Math.min(3, s.hiddenIframeCount));
      reasons.push({ code: 'hiddenIframes', kind: 'page' });
    }

    // Phrase matches are weak language-only evidence. They must never push a
    // page into a warning state on their own: examples, search snippets, news,
    // and security education routinely quote scam wording.
    const phrases = s.scamPhrases || [];
    if (phrases.length) {
      score += Math.min(0.18, 0.06 * Math.min(3, phrases.length));
      reasons.push({ code: 'scamPhrase', kind: 'page', params: [phrases[0]] });
    }

                                                                              
    if (s.seedPhraseForm) {
      score = Math.max(score, 0.9);
      independentScore = Math.max(independentScore, 0.9);
      flags.push('seed-phrase-harvest');
      reasons.push({ code: 'seedPhraseAsk', kind: 'wallet' });
    }

                                                                                    
    if (s.clickfix && s.clickfix.level === 'dangerous') {
      score = Math.max(score, 0.9);
      independentScore = Math.max(independentScore, 0.9);
      flags.push('clickfix');
      for (const r of s.clickfix.reasons) reasons.push(r);
    } else if (s.clickfix && s.clickfix.level === 'suspicious') {
      score += 0.25;
      independentScore += 0.25;
      if (s.clickfix.reasons[0]) reasons.push(s.clickfix.reasons[0]);
    }

                                                                            
    if (s.fakeUpdate && s.fakeUpdate.level === 'dangerous') {
      score = Math.max(score, 0.9);
      independentScore = Math.max(independentScore, 0.9);
      flags.push('fake-browser-update');
      for (const r of s.fakeUpdate.reasons) reasons.push(r);
    }

                                                                                 
                                                                       
                                                                          
                        
    const matchedBrand = C.brandNameIn([s.titleBrand, s.ogSiteName, ...(s.logoAltBrands || [])].join(' | '));
    if (matchedBrand && s.hasPasswordField && !isOnBrand(matchedBrand)) {
      score = Math.max(score, 0.85); independentScore = Math.max(independentScore, 0.85); flags.push('brand-impersonation-content'); brand = matchedBrand;
      reasons.push({ code: 'brandImpersonationContent', kind: 'brand', params: [matchedBrand] });
    }

                                                                              
                                                                             
                                                                              
                                                               
    if (matchedBrand && (C.CARRIER_BRANDS || []).includes(matchedBrand) &&
        !isOnBrand(matchedBrand) && s.hasCardInput && s.deliveryFeeText) {
      score = Math.max(score, 0.9); flags.push('delivery-fee-scam'); brand = brand || matchedBrand;
      reasons.push({ code: 'deliveryFeeScam', kind: 'brand', params: [displayName(matchedBrand)] });
    }
                                                                              
                                                                               
                                                                               
                                                                   
    const icon = (s.iconMatches || []).find((m) => m && m.brand && !isOnBrand(m.brand));
    if (icon) {
      const label = displayName(icon.brand);
      const iconReason = { code: 'brandIconMismatch', kind: 'brand', params: [label] };
      if (s.hasPasswordField && icon.kind !== 'logo') {
        score = Math.max(score, 0.85); independentScore = Math.max(independentScore, 0.85); flags.push('brand-impersonation-visual'); brand = brand || icon.brand;
        reasons.push(iconReason);
      } else {
        score += 0.35; reasons.push(iconReason);
      }
    }

    // Multiple weak page clues (quoted phrases, hidden frames, or a favicon
    // mismatch) must not become a warning just by accumulating. Strong rules
    // above retain their normal scores and independent corroboration.
    const weakOnly = reasons.length > 0 && reasons.every((reason) =>
      reason && ['scamPhrase', 'hiddenIframes', 'brandIconMismatch'].includes(reason.code)
    ) && !flags.length && independentScore < 0.3;
    if (weakOnly) score = Math.min(score, 0.45);
    return { score: Math.max(0, Math.min(1, score)), independentScore: Math.max(0, Math.min(1, independentScore)), reasons, flags, brand };
  }

  return { scoreUrl, scoreDom, registrableDomain };
});
