'use strict';
const api = globalThis.browser || globalThis.chrome;
const $ = (id) => document.getElementById(id);
const EXPECTED = { expectedInputs: [{ type: 'text', languages: ['en'] }], expectedOutputs: [{ type: 'text', languages: ['en'] }] };
let port = null;
let currentStatus = null;
let activeTabId = null;
let pageRefreshSequence = 0;

function setStatus(text, cls) {
  $('availability').textContent = text;
  $('availability').className = 'status ' + (cls || '');
}
function safeJson(value) {
  try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
}
function renderAnalysis(result, page) {
  const level = result && result.verdict || 'unknown';
  $('verdict').textContent = result && result.pending ? 'Local checks complete · deeper analysis in progress' : 'Page assessment: ' + level.toUpperCase();
  $('verdict').className = 'status ' + (level === 'dangerous' ? 'bad' : level === 'suspicious' ? 'warn' : level === 'safe' || level === 'informational' ? 'good' : '');
  $('summary').textContent = result && result.summary || 'No summary provided.';
  const selection = result && result.selection;
  $('selection-summary').textContent = selection && selection.verdict && selection.verdict !== 'not_requested'
    ? `${String(selection.verdict).toUpperCase()} (${Math.round((Number(selection.confidence) || 0) * 100)}%): ${selection.summary || 'No separate selection summary was returned.'}`
    : 'No selected content has been analyzed in this assessment.';
  const list = $('results');
  list.replaceChildren();
  for (const item of (result && result.evidence || [])) {
    const li = document.createElement('li');
    li.textContent = `[${item.id}] ${item.explanation}`;
    list.appendChild(li);
  }
  $('raw-output').textContent = safeJson({ result, page: page || {} });
  $('page-url').textContent = page && page.url || '';
}
function applyStatus(status) {
  currentStatus = status || {};
  const enabled = currentStatus.enabled === true;
  const supported = currentStatus.supported === true;
  const engine = currentStatus.engine || { id: supported && enabled ? 'gemini-nano' : 'local-ml' };
  const profile = currentStatus.deviceProfile || (globalThis.PhishGuard && globalThis.PhishGuard.deriveDeviceProfile
    ? globalThis.PhishGuard.deriveDeviceProfile({ hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory,
      connection: navigator.connection }) : { label: 'Balanced mode', tier: 'balanced' });
  $('device-profile').textContent = `${profile.label || 'Adaptive mode'} selected. ` +
    `${profile.maxDomElements || 'Adaptive'} element budget per frame; ` +
    `full rescans are rate-limited to protect browser responsiveness. ` +
    `Hardware details are approximate because browsers conceal some device metrics.`;

  // Gemini Nano remains the preferred generative engine when enabled. The
  // compact ONNX classifier is the packaged local fallback. Its inference
  // does not send page data over the network.
  $('reanalyze').disabled = false;
  if (engine.id === 'gemini-nano' && enabled && (currentStatus.availability === 'available' || currentStatus.active)) {
    setStatus('Gemini Nano generative AI is active on this device.', 'good');
    $('model-help').textContent = 'The background worker owns the local model session. Page snapshots stay on-device; no page content is sent to a cloud AI service. Device workload limits are adjusted automatically.';
    $('enable-ai').textContent = 'AI enabled';
    $('enable-ai').disabled = true;
  } else if (engine.id === 'onnx-transformer') {
    const modelReady = !!(currentStatus.onnx && currentStatus.onnx.ready);
    setStatus(modelReady ? 'Local ONNX transformer is loaded.' : 'Local text analysis is preparing. Core checks are already active.', modelReady ? 'good' : 'warn');
    $('model-help').textContent = 'PhishGuard uses a compact English BERT-small phishing-text classifier (packaged with the extension) with ONNX Runtime bundled in this extension. The model analyzes text on-device and does not require a separate download. It is not generative and cannot warn from text alone: page warnings require grounded page evidence. ' +
      (currentStatus.onnx && currentStatus.onnx.supported ? 'The model runs with a single CPU thread and device-adaptive token limits.' : 'The current device profile may defer this model to preserve resources.');
    if (supported && currentStatus.availability !== 'unavailable' && currentStatus.availability !== 'error') {
      $('enable-ai').textContent = enabled ? 'Reinitialize Gemini Nano' : 'Enable Gemini Nano (optional)';
      $('enable-ai').disabled = false;
    } else {
      $('enable-ai').textContent = modelReady ? 'Local text model ready' : 'Local protection active';
      $('enable-ai').disabled = true;
    }
  } else if (engine.id === 'local-ml') {
    setStatus('Adaptive lightweight local classifiers are active.', 'good');
    $('model-help').textContent = 'The device profile has deferred the larger transformer model to conserve resources. PhishGuard still uses its packaged lightweight page and URL classifiers. These are less capable than the transformer and will not issue warnings from keywords or passive text alone.';
    if (!supported || currentStatus.availability === 'unavailable' || currentStatus.availability === 'error') {
      $('enable-ai').textContent = 'Generative AI unavailable';
      $('enable-ai').disabled = true;
    } else if (enabled) {
      $('enable-ai').textContent = 'Reinitialize Gemini Nano';
      $('enable-ai').disabled = false;
    } else {
      $('enable-ai').textContent = currentStatus.availability === 'available' ? 'Enable Gemini Nano' : 'Download and enable Gemini Nano';
      $('enable-ai').disabled = currentStatus.availability === 'downloading';
    }
  } else if (currentStatus.availability === 'downloading') {
    setStatus('Chrome is downloading Gemini Nano. Local ML remains available meanwhile.', 'warn');
    $('enable-ai').disabled = true;
  } else if (supported && currentStatus.availability === 'available') {
    setStatus('Gemini Nano is available. Local ML remains active until you enable generative AI.', 'good');
    $('model-help').textContent = 'Enable Gemini Nano once to add generative reasoning. Page reanalysis remains available before and after setup.';
    $('enable-ai').textContent = 'Enable Gemini Nano';
    $('enable-ai').disabled = false;
  } else {
    setStatus('Adaptive local analysis is available.', 'good');
    $('model-help').textContent = 'The extension will use the best supported local analysis engine. The browser may conceal exact memory and GPU capability, so PhishGuard uses conservative estimates.';
    $('enable-ai').disabled = !supported;
    $('reanalyze').disabled = false;
  }
}

async function refreshStatus() {
  try {
    const status = await api.runtime.sendMessage({ type: 'getAiStatus', deviceHints: (globalThis.PhishGuard && globalThis.PhishGuard.readDeviceHints) ? globalThis.PhishGuard.readDeviceHints({ hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory, connection: navigator.connection }) : { hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory } });
    applyStatus(status);
  } catch (error) {
    setStatus('Could not read AI status: ' + String(error && error.message || error), 'warn');
  }
}
function connect() {
  try {
    port = api.runtime.connect({ name: 'phishguard-ai-host' });
    port.onMessage.addListener((message) => {
      if (!message) return;
      if (message.type === 'AI_STATUS') applyStatus(message.status);
      if (message.type === 'AI_DOWNLOAD_PROGRESS') {
        $('download-progress').hidden = false;
        const progress = Number.isFinite(Number(message.progress)) ? Number(message.progress) :
          (Number(message.total) > 0 ? Number(message.loaded || 0) / Number(message.total) : Number(message.loaded || 0));
        $('download-progress').value = Math.max(0, Math.min(1, progress));
        const onnx = message.engine === 'onnx-transformer';
        setStatus(onnx
          ? `Loading packaged text model (${Math.round($('download-progress').value * 100)}%). Page content remains on-device.`
          : `Downloading Gemini Nano: ${Math.round($('download-progress').value * 100)}%`, 'warn');
      }
      if (message.type === 'AI_ANALYSIS' && message.tabId === activeTabId && message.frameId === 0) {
        ++pageRefreshSequence;
        renderAnalysis(message.result, message.page);
        $('download-progress').hidden = true;
      }
    });
    port.onDisconnect.addListener(() => { port = null; });
  } catch (_) { port = null; }
}

$('enable-ai').addEventListener('click', async () => {
  $('enable-ai').disabled = true;
  $('download-progress').hidden = false;
  $('download-progress').value = 0;
  setStatus('Preparing the local AI model…', 'warn');
  try {
    // Chrome requires a user gesture to trigger the first model download. Do
    // that from this extension page, then let the background worker own the
    // long-lived session for continuous analysis after this panel is closed.
    if (!('LanguageModel' in globalThis)) throw new Error('Chrome Prompt API is not available in this browser.');
    const availability = await LanguageModel.availability(EXPECTED);
    if (availability === 'unavailable') throw new Error('Chrome reports that Gemini Nano cannot run on this device.');
    const warmup = await LanguageModel.create({ ...EXPECTED, monitor(monitor) {
      monitor.addEventListener('downloadprogress', (event) => {
        $('download-progress').value = Math.max(0, Math.min(1, Number(event.loaded) || 0));
        setStatus(`Downloading on-device model: ${Math.round($('download-progress').value * 100)}%`, 'warn');
      });
    } });
    try { warmup.destroy(); } catch (_) {}
    const response = await api.runtime.sendMessage({ type: 'enableOnDeviceAi' });
    if (!response || response.ok !== true) throw new Error(response && response.error || 'The on-device model could not be initialized.');
    applyStatus(response.status);
    $('download-progress').hidden = true;
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].id != null) await api.tabs.sendMessage(tabs[0].id, { type: 'reanalyzePage', source: 'ai-ready' }).catch(() => {});
  } catch (error) {
    setStatus('Gemini Nano initialization failed: ' + String(error && error.message || error), 'warn');
    $('enable-ai').disabled = false;
  }
});
$('reanalyze').addEventListener('click', async () => {
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  if (tabs[0] && tabs[0].id != null) await api.tabs.sendMessage(tabs[0].id, { type: 'reanalyzePage', source: 'ai-panel' }).catch(() => {});
});
$('remote-links').addEventListener('change', async () => {
  await api.runtime.sendMessage({ type: 'setSettings', patch: { remoteLinkChecks: $('remote-links').checked } });
  updateRemoteStatus();
});
async function updateRemoteStatus() {
  const settings = await api.runtime.sendMessage({ type: 'getSettings' });
  $('remote-links').checked = !!(settings && settings.remoteLinkChecks);
  const config = globalThis.PHISHGUARD_CLOUD_CONFIG || {};
  $('remote-status').textContent = config.apiUrl ? 'Configured: ' + new URL(config.apiUrl).host : 'Remote inspection is not available in this release. On-device protection remains active.';
  $('remote-links').disabled = !config.apiUrl;
}

async function refreshCurrentPage() {
  const sequence = ++pageRefreshSequence;
  try {
    const tabs = await api.tabs.query({active:true,currentWindow:true});
    if (sequence !== pageRefreshSequence) return;
    const tab = tabs[0]; activeTabId = tab && tab.id;
    $('page-url').textContent = tab && tab.url || '';
    if (activeTabId == null) return;
    const page = await api.tabs.sendMessage(activeTabId,{type:'getPageAnalysis'},{frameId:0});
    if (sequence !== pageRefreshSequence || activeTabId !== tab.id || !page) return;
    const aggregate = await api.runtime.sendMessage({type:'getVerdict',tabId:tab.id});
    if (sequence !== pageRefreshSequence) return;
    const verdict = aggregate || page.verdict || {};
    renderAnalysis({verdict:verdict.level,summary:verdict.summary,evidence:verdict.aiEvidence || [],
      selection:page.evidence && page.evidence.ai && page.evidence.ai.selection,
      pending:verdict.analysisPending, limitations:verdict.limitations || []},page);
  } catch (_) {
    if (sequence !== pageRefreshSequence) return;
    $('verdict').textContent = 'Page inspection unavailable here';
    $('summary').textContent = 'Browser-internal and protected pages cannot be inspected. Open a regular webpage to view its checks.';
  }
}
if (api.tabs.onActivated) api.tabs.onActivated.addListener(refreshCurrentPage);
if (api.tabs.onUpdated) api.tabs.onUpdated.addListener((id,change) => { if (id === activeTabId && change.status === 'complete') refreshCurrentPage(); });

connect();
refreshCurrentPage();
refreshStatus();
updateRemoteStatus();
