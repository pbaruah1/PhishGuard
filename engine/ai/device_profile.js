(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  // Browser APIs expose coarse hardware hints, not exact RAM/GPU/storage.
  // Profiles are deliberately conservative and can be recalculated at runtime.
  const PROFILES = Object.freeze({
    constrained: Object.freeze({
      tier: 'constrained', label: 'Efficiency mode',
      maxDomElements: 3200, maxInteractive: 220, maxElementDetails: 350,
      maxScripts: 18, maxInlineScriptChars: 1100, maxScriptPreviewChars: 180,
      maxAiElements: 60, maxAiLinks: 14, maxAiForms: 8, maxAiScripts: 4,
      maxVisibleTextChars: 2600, maxSnapshotChars: 14000,
      onnxMaxTokens: 64, onnxMaxChars: 1600, minOnnxIntervalMs: 90000, onnxAutoDownload: false,
      mutationDebounceMs: 3800, inventoryDebounceMs: 5000,
      maxSerpAnchorScan: 160, serpObserverDebounceMs: 2200,
      minFullRescanIntervalMs: 40000, minAiIntervalMs: 45000,
      usePageModelFallback: false, maxLinkModelChecks: 6
    }),
    balanced: Object.freeze({
      tier: 'balanced', label: 'Balanced mode',
      maxDomElements: 5200, maxInteractive: 400, maxElementDetails: 650,
      maxScripts: 36, maxInlineScriptChars: 2200, maxScriptPreviewChars: 280,
      maxAiElements: 120, maxAiLinks: 24, maxAiForms: 16, maxAiScripts: 8,
      maxVisibleTextChars: 4800, maxSnapshotChars: 26000,
      onnxMaxTokens: 112, onnxMaxChars: 3600, minOnnxIntervalMs: 60000, onnxAutoDownload: false,
      mutationDebounceMs: 2800, inventoryDebounceMs: 3800,
      maxSerpAnchorScan: 320, serpObserverDebounceMs: 1600,
      minFullRescanIntervalMs: 28000, minAiIntervalMs: 28000,
      usePageModelFallback: true, maxLinkModelChecks: 12
    }),
    performance: Object.freeze({
      tier: 'performance', label: 'Full inspection mode',
      maxDomElements: 8200, maxInteractive: 650, maxElementDetails: 1000,
      maxScripts: 60, maxInlineScriptChars: 3400, maxScriptPreviewChars: 440,
      maxAiElements: 200, maxAiLinks: 36, maxAiForms: 24, maxAiScripts: 12,
      maxVisibleTextChars: 7000, maxSnapshotChars: 38000,
      onnxMaxTokens: 160, onnxMaxChars: 5200, minOnnxIntervalMs: 45000, onnxAutoDownload: false,
      mutationDebounceMs: 2000, inventoryDebounceMs: 3000,
      maxSerpAnchorScan: 600, serpObserverDebounceMs: 1200,
      minFullRescanIntervalMs: 20000, minAiIntervalMs: 20000,
      usePageModelFallback: true, maxLinkModelChecks: 18
    })
  });

  function positive(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : 0;
  }

  function readDeviceHints(source) {
    const s = source || {};
    const connection = s.connection || s.network || {};
    return Object.freeze({
      hardwareConcurrency: positive(s.hardwareConcurrency || s.cores) || null,
      deviceMemoryGiB: positive(s.deviceMemory || s.deviceMemoryGiB || s.memoryGiB) || null,
      saveData: connection.saveData === true || s.saveData === true,
      effectiveType: String(connection.effectiveType || s.effectiveType || '').slice(0, 16),
      reducedMotion: s.reducedMotion === true
    });
  }

  function deriveDeviceProfile(input) {
    const hints = readDeviceHints(input);
    const cores = hints.hardwareConcurrency || 0;
    const memory = hints.deviceMemoryGiB || 0;
    let tier = 'balanced';
    if (hints.saveData || /^(slow-2g|2g)$/i.test(hints.effectiveType) ||
        (memory > 0 && memory <= 4) || (cores > 0 && cores <= 4)) {
      tier = 'constrained';
    } else if (memory >= 8 && cores >= 12 && !/^(slow-2g|2g|3g)$/i.test(hints.effectiveType)) {
      tier = 'performance';
    }
    // BERT-small is deliberately single-threaded. Run it on constrained CPUs
    // with a smaller sequence budget. Conserve resources when the browser
    // reports data-saving mode or <=2 GiB memory; model assets are bundled.
    const canRunOnnxFallback = !hints.saveData && !(memory > 0 && memory <= 2);
    return Object.freeze(Object.assign({}, PROFILES[tier], {
      useOnnxFallback: canRunOnnxFallback,
      hardwareHintsAvailable: !!(cores || memory),
      hardwareConcurrency: cores || null,
      deviceMemoryGiB: memory || null,
      saveData: hints.saveData,
      effectiveType: hints.effectiveType || null,
      reducedMotion: hints.reducedMotion
    }));
  }

  function selectAiEngine(input) {
    const state = input || {};
    const promptApi = state.promptApi === true;
    const enabled = state.enabled === true;
    const availability = String(state.availability || 'unavailable');
    if (promptApi && enabled && (availability === 'available' || state.active === true)) {
      return Object.freeze({ id: 'gemini-nano', label: 'Gemini Nano generative AI', generative: true, ready: true });
    }
    if (state.onnxAllowed !== false) {
      return Object.freeze({ id: 'onnx-transformer', label: 'Local phishing-text model', generative: false, ready: state.onnxReady === true,
        preferred: promptApi && availability !== 'unavailable' && availability !== 'error' ? 'gemini-nano' : null });
    }
    return Object.freeze({
      id: 'local-ml', label: 'Lightweight on-device classifiers', generative: false, ready: true,
      preferred: promptApi && availability !== 'unavailable' && availability !== 'error' ? 'gemini-nano' : null
    });
  }

  return { DEVICE_PROFILES: PROFILES, readDeviceHints, deriveDeviceProfile, selectAiEngine };
});
