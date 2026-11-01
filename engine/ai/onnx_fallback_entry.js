import * as ort from 'onnxruntime-web/wasm';
import { createBertTokenizer } from './bert_tokenizer.js';

const MODEL_REVISION = 'cfe22cf';
const MODEL_ID = 'onnx-community/bert-small-phishing-ONNX';
const VOCAB_SHA256 = '07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3';
const MODEL_SHA256 = 'b82f10fd29dee2c9fe9cae51997529234bb889151965e0580c4f008e8124455e';
const CACHE_NAME = 'phishguard-onnx-model-v1';
const MAX_MODEL_BYTES = 35 * 1024 * 1024;
const MAX_VOCAB_BYTES = 400 * 1024;

let classifierPromise = null;

function sha256Hex(bytes) {
  return crypto.subtle.digest('SHA-256', bytes).then((digest) =>
    Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, '0')).join(''));
}

async function readCachedOrDownload(url, options) {
  const opts = options || {};
  // Cache Storage is an optimization, not a prerequisite. Some managed or
  // privacy-restricted browsers can deny extension cache access; still permit
  // a one-session inference after downloading and validating the assets.
  let cache = null;
  try {
    if (typeof caches !== 'undefined' && typeof caches.open === 'function') {
      cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(url);
      if (cached) {
        const bytes = await cached.arrayBuffer();
        const valid = opts.sha256 ? (await sha256Hex(bytes)) === opts.sha256 :
          bytes.byteLength >= (opts.minBytes || 1) && bytes.byteLength <= opts.maxBytes;
        if (valid) return { bytes, cached: true };
        await cache.delete(url);
      }
    }
  } catch (_) {
    cache = null;
  }

  const response = await fetch(url, {
    method: 'GET', credentials: 'omit', mode: 'cors', redirect: 'follow',
    referrerPolicy: 'no-referrer', cache: 'force-cache', signal: AbortSignal.timeout(20000)
  });
  if (!response.ok) throw new Error(`Local AI asset loading failed (HTTP ${response.status}).`);
  const contentLength = Number(response.headers.get('content-length')) || 0;
  if (contentLength > opts.maxBytes) throw new Error('Local AI asset exceeded its permitted download size.');
  const reader = response.body && response.body.getReader ? response.body.getReader() : null;
  let bytes;
  if (reader) {
    const chunks = [];
    let loaded = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      if (part.value) {
        loaded += part.value.byteLength;
        if (loaded > opts.maxBytes) { try { await reader.cancel(); } catch (_) {} throw new Error('Local AI asset exceeded its permitted download size.'); }
        chunks.push(part.value);
        if (typeof opts.onProgress === 'function') opts.onProgress({ loaded, total: contentLength || opts.maxBytes, phase: opts.phase || 'download' });
      }
    }
    const merged = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
    bytes = merged.buffer;
  } else {
    bytes = await response.arrayBuffer();
    if (bytes.byteLength > opts.maxBytes) throw new Error('Local AI asset exceeded its permitted download size.');
    if (typeof opts.onProgress === 'function') opts.onProgress({ loaded: bytes.byteLength, total: contentLength || bytes.byteLength, phase: opts.phase || 'download' });
  }

  if (opts.sha256) {
    const actual = await sha256Hex(bytes);
    if (actual !== opts.sha256) throw new Error('A packaged model asset failed its SHA-256 integrity check.');
  } else if (bytes.byteLength < (opts.minBytes || 1)) {
    throw new Error('The downloaded tokenizer vocabulary is incomplete.');
  }
  if (cache) {
    try { await cache.put(url, new Response(bytes, { headers: { 'Content-Type': 'application/octet-stream' } })); }
    catch (_) { /* Quota/private-mode failures do not block this session's inference. */ }
  }
  return { bytes, cached: false };
}

function toInt64Tensor(values, dims) {
  return new ort.Tensor('int64', BigInt64Array.from(values, (value) => BigInt(value)), dims);
}

function softmaxPair(logits) {
  if (!logits || logits.length < 2) throw new Error('The ONNX classifier returned an unexpected output tensor.');
  const first = Number(logits[0]);
  const second = Number(logits[1]);
  if (!Number.isFinite(first) || !Number.isFinite(second)) throw new Error('The ONNX classifier returned non-finite logits.');
  const max = Math.max(first, second);
  const a = Math.exp(first - max);
  const b = Math.exp(second - max);
  const denom = a + b;
  return { safeProbability: a / denom, phishingProbability: b / denom };
}

async function createClassifier(options) {
  const opts = options || {};
  if (classifierPromise) return classifierPromise;
  classifierPromise = (async () => {
    ort.env.logLevel = 'fatal';
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.proxy = false;
    if (!opts.wasmBaseUrl || typeof opts.wasmBaseUrl !== 'string') {
      throw new Error('The packaged ONNX Runtime WebAssembly path was not supplied. Rebuild the extension package.');
    }
    // Override only the binary, so ORT uses its statically bundled JS factory.
    ort.env.wasm.wasmPaths = { wasm: opts.wasmBaseUrl + 'ort-wasm-simd-threaded.wasm' };
    ort.env.wasm.initTimeout = 15000;

    const loadedBytes = { model: 0, vocab: 0 };
    const updateProgress = (detail) => {
      if (detail.phase === 'model') loadedBytes.model = detail.loaded;
      if (detail.phase === 'vocab') loadedBytes.vocab = detail.loaded;
      if (typeof opts.onProgress === 'function') opts.onProgress({
        phase: detail.phase,
        loaded: loadedBytes.model + loadedBytes.vocab,
        total: 29_300_000,
        progress: Math.min(1, (loadedBytes.model + loadedBytes.vocab) / 29_300_000)
      });
    };
    if (!opts.assetBaseUrl) throw new Error('Packaged text model assets are unavailable.');
    const [modelAsset, vocabAsset] = await Promise.all([
      readCachedOrDownload(opts.assetBaseUrl + 'model_int8.onnx', { sha256: MODEL_SHA256, maxBytes: MAX_MODEL_BYTES, phase: 'model', onProgress: updateProgress }),
      readCachedOrDownload(opts.assetBaseUrl + 'vocab.txt', { sha256:VOCAB_SHA256, minBytes: 200_000, maxBytes: MAX_VOCAB_BYTES, phase: 'vocab', onProgress: updateProgress })
    ]);
    const vocabText = new TextDecoder('utf-8', { fatal: true }).decode(vocabAsset.bytes);
    const tokenizer = createBertTokenizer(vocabText);
    if (tokenizer.vocabSize < 30000 || tokenizer.vocabSize > 31000) throw new Error('The BERT vocabulary does not match the pinned model configuration.');

    const session = await ort.InferenceSession.create(modelAsset.bytes, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all',
      executionMode: 'sequential',
      intraOpNumThreads: 1,
      interOpNumThreads: 1
    });
    if (!Array.isArray(session.inputNames) || !session.inputNames.includes('input_ids') || !session.inputNames.includes('attention_mask')) {
      try { await session.release(); } catch (_) {}
      throw new Error('The ONNX model input signature is not the expected BERT classifier signature.');
    }

    async function classify(text, settings) {
      const cfg = settings || {};
      const maxLength = Math.max(64, Math.min(192, Number(cfg.maxTokens) || 128));
      const encoded = tokenizer.encode(String(text || '').slice(0, Number(cfg.maxChars) || 5000), { maxLength });
      const dims = [1, maxLength];
      const feeds = {
        input_ids: toInt64Tensor(encoded.inputIds, dims),
        attention_mask: toInt64Tensor(encoded.attentionMask, dims)
      };
      if (session.inputNames.includes('token_type_ids')) feeds.token_type_ids = toInt64Tensor(encoded.tokenTypeIds, dims);
      const output = await session.run(feeds);
      const tensor = output[session.outputNames[0]];
      const scores = softmaxPair(tensor && tensor.data);
      return Object.assign(scores, { label: scores.phishingProbability >= 0.5 ? 'phishing-text' : 'safe-text', tokensUsed: encoded.length });
    }

    return Object.freeze({
      modelId: MODEL_ID,
      revision: MODEL_REVISION,
      quantization: 'INT8',
      modelBytes: modelAsset.bytes.byteLength,
      inputNames: session.inputNames.slice(),
      outputNames: session.outputNames.slice(),
      loadedFromCache: modelAsset.cached && vocabAsset.cached,
      classify,
      dispose: async () => { try { await session.release(); } catch (_) {} }
    });
  })();
  try { return await classifierPromise; }
  catch (error) { classifierPromise = null; throw error; }
}

globalThis.PhishGuardOnnxRuntime = Object.freeze({ createClassifier, model: Object.freeze({ id: MODEL_ID, revision: MODEL_REVISION, sha256: MODEL_SHA256, license: 'MIT' }) });
