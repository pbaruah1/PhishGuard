(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const EXECUTABLE_EXT = /\.(?:exe|msi|msp|dll|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|wsf|wsh|jar|apk|dmg|pkg|appx|msix|reg|lnk|iso|img)(?:$|[?#])/i;
  const SCRIPT_EXT = /\.(?:bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|wsf|wsh|reg|lnk)(?:$|[?#])/i;
  const ARCHIVE_EXT = /\.(?:zip|rar|7z|tar|gz|iso|img)(?:$|[?#])/i;
  const DOUBLE_EXT = /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:exe|msi|scr|bat|cmd|ps1|vbs|js|hta|jar|apk)$/i;
  const CLOUD_FILE_HOST = /(?:^|\.)(?:drive\.google\.com|docs\.google\.com|dropbox\.com|dropboxusercontent\.com|1drv\.ms|onedrive\.live\.com|sharepoint\.com|box\.com|mediafire\.com|mega\.nz|wetransfer\.com|sendspace\.com)$/i;
  const SAFETY_EVASION = /\b(?:disable|turn off|bypass|ignore|temporarily disable)\b.{0,50}\b(?:antivirus|anti-virus|defender|security|protection|firewall|smart screen|smartscreen)\b|\b(?:enable|allow)\b.{0,40}\b(?:macros|content|editing)\b/i;
  const DECEPTIVE_PROMPT = /\b(?:your browser is out of date|critical update|security update required|install the latest update|verify to download|complete verification to download|download required to view|unlock the document|password protected file|run as administrator|administrator privileges)\b/i;
  const ACTION_CONTEXT = /\b(?:download|open|run|launch|install|extract|enable|allow|view|unzip|execute)\b/i;
  const TRUST_BRAND = /\b(?:google|microsoft|adobe|apple|dropbox|docusign|sharepoint|onedrive|drive)\b/i;

  function cleanName(value) {
    return String(value || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, 180);
  }

  function classifyCandidate(candidate) {
    const item = candidate || {};
    const href = String(item.href || item.url || '').trim();
    const label = cleanName([item.label, item.title, item.download, item.filename].filter(Boolean).join(' '));
    let url;
    try { url = href ? new URL(href, item.baseUrl || undefined) : null; } catch (_) { url = null; }
    const path = url ? url.pathname : href.split(/[?#]/)[0];
    const fileName = cleanName(item.filename || item.download || path.split('/').pop() || label);
    const exec = EXECUTABLE_EXT.test(fileName) || EXECUTABLE_EXT.test(path);
    const script = SCRIPT_EXT.test(fileName) || SCRIPT_EXT.test(path);
    const archive = ARCHIVE_EXT.test(fileName) || ARCHIVE_EXT.test(path);
    const disguised = DOUBLE_EXT.test(fileName) || DOUBLE_EXT.test(path);
    const downloadAction = !!item.download || /\b(download|install|open file|view file|run file)\b/i.test(label) || !!item.isDownload;
    return { href, label, fileName, executable: exec, script, archive, disguised, downloadAction,
      external: !!(url && item.pageHost && url.hostname && url.hostname.toLowerCase() !== String(item.pageHost).toLowerCase()),
      protocol: url ? url.protocol : '', host: url ? url.hostname.toLowerCase() : '' };
  }

  function scoreDownloadSurface(input) {
    const data = input || {};
    const host = String(data.host || '').toLowerCase();
    const text = String(data.pageText || '').slice(0, 50000);
    const candidates = (Array.isArray(data.candidates) ? data.candidates : []).slice(0, 120).map(classifyCandidate);
    const cloudHost = CLOUD_FILE_HOST.test(host);
    const downloadable = candidates.filter((item) => item.downloadAction || item.executable || item.archive);
    const execFiles = candidates.filter((item) => item.executable);
    const scripts = candidates.filter((item) => item.script);
    const disguised = candidates.filter((item) => item.disguised);
    const archives = candidates.filter((item) => item.archive);
    const safetyEvasion = SAFETY_EVASION.test(text);
    const deceptivePrompt = DECEPTIVE_PROMPT.test(text);
    const action = ACTION_CONTEXT.test(text) || downloadable.length > 0;
    const claimedBrand = TRUST_BRAND.test(text);
    const reasons = [];
    const flags = [];
    let score = 0;
    const evidence = [];

    if (disguised.length) {
      score = Math.max(score, 0.98);
      flags.push('download-disguised-executable');
      reasons.push({ code: 'downloadDisguisedExecutable', kind: 'page', params: [disguised[0].fileName || disguised[0].href] });
      evidence.push({ code: 'disguised-executable', severity: 'dangerous', detail: 'A file uses a document or image extension followed by an executable extension.' });
    }
    if (execFiles.length) {
      const sample = execFiles.slice(0, 3).map((item) => item.fileName || item.href).filter(Boolean);
      const strongContext = safetyEvasion || deceptivePrompt || (claimedBrand && cloudHost);
      score = Math.max(score, strongContext ? 0.94 : (cloudHost ? 0.80 : 0.68));
      flags.push('download-executable');
      reasons.push({ code: 'downloadExecutableSurface', kind: 'page', params: [sample.join(', ')] });
      evidence.push({ code: 'executable-download', severity: strongContext ? 'dangerous' : 'suspicious', detail: `The page offers an executable or installable file${sample.length ? ': ' + sample.join(', ') : ''}.` });
    }
    if (scripts.length && (cloudHost || safetyEvasion || deceptivePrompt)) {
      score = Math.max(score, 0.92);
      flags.push('download-script-file');
      reasons.push({ code: 'downloadScriptSurface', kind: 'page' });
      evidence.push({ code: 'script-download', severity: 'dangerous', detail: 'The download is a script or command file that can execute actions on the device.' });
    }
    if (safetyEvasion && action) {
      score = Math.max(score, 0.96);
      flags.push('download-safety-evasion');
      reasons.push({ code: 'downloadSafetyEvasion', kind: 'page' });
      evidence.push({ code: 'security-evasion', severity: 'dangerous', detail: 'The page tells the visitor to weaken or bypass device security before opening a file.' });
    }
    if (deceptivePrompt && action) {
      score = Math.max(score, cloudHost ? 0.82 : 0.72);
      flags.push('download-deceptive-prompt');
      reasons.push({ code: 'downloadDeceptivePrompt', kind: 'page' });
      evidence.push({ code: 'deceptive-download-instruction', severity: 'suspicious', detail: 'The page uses an update or verification pretext to persuade the visitor to download or run a file.' });
    }
    if (cloudHost && archives.length && (safetyEvasion || deceptivePrompt || /\b(?:password|extract|unzip|archive)\b/i.test(text))) {
      score = Math.max(score, 0.72);
      flags.push('download-risky-archive-context');
      reasons.push({ code: 'downloadArchivePressure', kind: 'page' });
      evidence.push({ code: 'archive-pressure', severity: 'suspicious', detail: 'A shared-file page pairs an archive download with instructions or pressure that could conceal an executable payload.' });
    }
    if (cloudHost && downloadable.length && !execFiles.length && !safetyEvasion && !deceptivePrompt) {
      evidence.push({ code: 'cloud-file-host', severity: 'info', detail: 'This is a file-sharing page. The provider name alone does not establish that the shared file is safe.' });
    }
    return { score: Number(Math.min(1, score).toFixed(4)), reasons, flags, evidence,
      signals: { cloudFileHost: cloudHost, executableCount: execFiles.length, scriptCount: scripts.length,
        archiveCount: archives.length, disguisedExecutableCount: disguised.length, safetyEvasion, deceptivePrompt,
        candidateCount: candidates.length } };
  }

  return { classifyDownloadCandidate: classifyCandidate, scoreDownloadSurface };
});
