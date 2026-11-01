# Publish PhishGuard

A Windows-first walkthrough for the supplied v1.0.1 package. Checked against official publishing documentation on November 1, 2026. Your Chrome developer fee is already paid; you do not need to pay it again.

## 1. Put the correct files in the correct places

Extract your existing `PhishGuard-ONNX-Fallback-Delivery-Bundle(1)(1).zip` using File Explorer → right-click → **Extract All**.

| File inside the delivery bundle | What to do with it |
| --- | --- |
| `PhishGuard-Complete-Source.zip` | Extract into a folder named `PhishGuard`. This becomes the GitHub repository. |
| `phishguard-chrome.zip` | Compiled Chrome build. Load it for testing; upload this ZIP to the Chrome Web Store if no code changes are needed. |
| `phishguard-firefox.zip` | Firefox package. Do not upload it to the Chrome Web Store. |
| `PhishGuard-Changed-Files.zip` | A patch archive, not the complete repository or store upload. |

Inside your extracted `PhishGuard` folder you should see `manifest.json`, `package.json`, `background`, and `content` directly. If they are in another nested folder, that inner folder is your project root.

Extract the new publishing kit. Copy its `README.md`, `PUBLISHING.md`, and `assets` folder **into your project root**. Replace the old README. Merge the assets folders; do not delete the existing icons or other assets. The new screenshot files go in `assets/readme/`.

Keep `LICENSE`, `NOTICE`, and `LICENSES/` in the source and distribution. The README links to them. Your public repository should not include your application PDFs, personal records, `.env` files, credentials, or private logs.

## 2. Publish the source on GitHub

### Use GitHub Desktop

1. Install [GitHub Desktop](https://desktop.github.com/) and sign in to your GitHub account.
2. Select **File → Add local repository**.
3. Select the extracted `PhishGuard` project folder.
4. If Desktop says the folder is not a Git repository, click **create a repository here**. Check the name is `PhishGuard` and the local path resolves to your existing project, not an empty `PhishGuard/PhishGuard` subfolder. Leave Git ignore and license templates unset because your project already contains these files. Create the repository.
5. Inspect the **Changes** list. You should see the source files, `README.md`, the new images, and `model/bert/model_int8.onnx`. You should not see `node_modules`, `.env`, secrets, or private documents. The existing `.gitignore` already excludes `node_modules/` and `dist/`; retain it.
6. If changes remain uncommitted, enter **Prepare PhishGuard source and documentation** in Summary and click **Commit to main** (or the current branch name).
7. Click **Publish repository**.
8. Set the repository name to **PhishGuard**. Description: **Browser-based phishing checks with local analysis and clear explanations.**
9. Uncheck **Keep this code private** if you want admissions officers and other visitors to see it without access requests.
10. Click **Publish Repository**.
11. Choose **Repository → View on GitHub**. Confirm the README displays and both screenshots load. On GitHub, the model file should also exist at `model/bert/model_int8.onnx`.

The bundled model is about 29 MB. Use Desktop/Git rather than the browser's file-upload form to publish the source. Do not remove model weights to make the upload smaller.

If you already have a GitHub repository for this project, use **File → Clone repository** to get that repository, copy the updated project files into the clone while preserving its `.git` folder, review changes, commit, and **Push origin**. Do not create a competing repository or overwrite its history.

### Repository settings

- On the repository homepage, click the gear beside **About**. Add the description above and topics such as `browser-extension`, `phishing`, `cybersecurity`, and `javascript`.
- Open **Settings → General → Features** and ensure Issues is enabled for ordinary support.
- Use **Settings → Code security** to enable private vulnerability reporting if available. Keep `SECURITY.md` consistent with the contact method you actually provide.
- Check **Actions** after pushing. A workflow failure needs investigation; a public repository does not itself mean the release passed testing.

## 3. Test the build you intend to submit

You can publish source before these checks. Complete them before submitting a user-facing store release.

1. Extract `phishguard-chrome.zip` into a permanent folder such as `Documents\PhishGuard-Chrome`.
2. Open `chrome://extensions` in desktop Chrome 138 or newer.
3. Turn on **Developer mode** → **Load unpacked** → choose the folder containing `manifest.json`.
4. Disable any older PhishGuard copy. Pin the new one in Chrome's Extensions menu.
5. Visit an ordinary HTTPS webpage. Check that the popup identifies the current page and that analysis progresses to a result or an honest limitation message.
6. Switch between two tabs, navigate to a different page, and request another check. Confirm results do not remain attached to the previous page.
7. Try the text-selection/right-click analysis and QR inspection controls on harmless test content. Confirm each control does what the listing promises.
8. Test known-threat blocking using your controlled test fixtures. Do not browse live malicious URLs merely to obtain screenshots.
9. On `chrome://extensions`, inspect PhishGuard's **Errors** if shown. Investigate recurring errors. Check that the browser remains responsive during ordinary browsing.
10. Test on a device without optional Gemini support as well. The listing must not imply that every device supports Gemini.

The supplied report verifies automated tests and packaged model inference but does not complete real-browser validation. Record what you actually observe; do not use the unit-test count as an accuracy percentage.

### If code, permissions, icons, or privacy text change

Install [Node.js](https://nodejs.org/) (20 or newer). Open PowerShell in the source folder: File Explorer → open project → click address bar → type `powershell` → Enter.

Run each command separately; stop at a failure:

```powershell
npm ci
npm run test:unit
npm run build
npx playwright install chromium
npm run test:e2e
```

Test `dist/chrome` with **Load unpacked**. The rebuilt file to upload is `dist/phishguard-chrome.zip`. Do not upload the old compiled ZIP after changing the source. Keep the tested ZIP paired with the source commit that produced it.

The source targets both Chrome and Firefox, but a Firefox package alone does not establish Firefox compatibility. Keep the initial Chrome listing focused on Chrome.

## 4. Make the privacy policy publicly readable

Your source already contains `privacy.html`. Read it before submission and ensure it matches the build you tested, including threat feeds, icon requests, local history, and any optional reporting or remote service. Add a maintainer contact method you monitor. The current build has no configured remote inspection service; do not advertise it as available.

To host the existing page through GitHub:

1. Open your GitHub repository → **Settings → Pages**.
2. Under **Build and deployment**, select **Deploy from a branch**.
3. Select the branch containing your code (normally `main`) and **/(root)** → **Save**.
4. Wait for the Pages deployment to complete. Open the site URL shown by GitHub and append `/privacy.html` to the project base URL.
5. For a repository named `PhishGuard`, the usual policy URL is `https://YOUR-USERNAME.github.io/PhishGuard/privacy.html`. Replace `YOUR-USERNAME` with your actual username; use the URL GitHub provides if it differs.
6. Open that policy URL in a signed-out/private browser window. Confirm the page is readable without a login.

If Pages deployment fails, inspect its Actions log and fix the reported issue. Do not submit a broken policy URL. You can instead host the policy on another public HTTPS website you control.

Important: local processing still requires data-handling disclosures. “No data sold” and “no data handled” mean different things. The existing extension inspects page content and browsing-related metadata even when it does not send them to your server.

## 5. Prepare the Chrome Web Store listing

Open the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole) with the Google account that paid the developer fee. Complete any outstanding account requirements shown there, including contact-email verification and account security requirements.

### Upload

1. Click **Add new item** (or **New item**).
2. Select your tested `phishguard-chrome.zip`.
3. Click **Upload**.
4. If you inspect the ZIP, `manifest.json` must be at its top level. Do not ZIP the parent folder and do not upload the delivery bundle or source archive.
5. Note the extension ID assigned by the dashboard. Future updates belong under this same item.

### Store listing

Use **PhishGuard** as the product name. Choose the closest available security/privacy category or subcategory, and English as the primary language. Dashboard category names can change.

Suggested short description:

> Check webpages for phishing signals, understand the warning, and leave suspicious pages with clearer next steps.

Suggested detailed description:

> PhishGuard checks supported webpages for signs of phishing and scams, then explains the evidence behind its warnings.
>
> It checks website addresses and link destinations, examines form structure, and looks for selected behaviors associated with fake updates, tech-support scams, clipboard manipulation, and suspicious wallet requests. A packaged local text model provides a supporting signal; suspicious wording alone does not establish that a page is malicious.
>
> Open the toolbar popup to see the page status and available controls. When a page is blocked, PhishGuard identifies the address and provides a return button. Inspection controls support additional checks, including selected text and supported QR-code destinations.
>
> Ordinary page analysis runs in your browser. Public threat-list and site-icon requests can still use the network. Optional reporting and remote inspection require separate configuration and consent; remote inspection is not configured in this release.
>
> Requires desktop Chrome 138 or newer. Some browser pages and page content cannot be inspected. The English-focused text model and other checks can make mistakes. PhishGuard does not guarantee that a page is safe or that every scam will be detected.

Use only feature descriptions you confirmed in step 3. Do not claim “100% protection,” a measured detection accuracy you do not have, Chrome endorsement, or support for all devices.

### Images and links

| Field | Supply |
| --- | --- |
| Store icon | A 128 × 128 PNG; inspect the existing `assets/icons/icon128.png` before using it. |
| Screenshots | At least one actual extension screenshot; use 1280 × 800 pixels, up to five. Google also supports 640 × 400. |
| Small promotional tile | 440 × 280 pixels, PNG or JPEG. |
| Marquee tile | Optional, 1400 × 560 pixels. |
| Homepage | Your public GitHub repository URL. |
| Support | Your repository's Issues URL, if you will monitor it. |
| Privacy policy | The public policy URL you verified in step 4. |

Capture screenshots from the tested version. The small images embedded in the README are documentation assets, not correctly sized store-submission screenshots. Keep screenshots free of private information, and do not enlarge a tiny screenshot and claim it is a fresh capture. A simple promotional tile can show the actual PhishGuard icon and product name against a clean background.

## 6. Fill in Privacy practices

### Single purpose

Paste:

> Help users recognize and avoid phishing and scam-related webpages by checking addresses, page structure, and relevant behaviors, then presenting evidence-based warnings and available protective actions.

### Permission justifications

These match the supplied manifest. If the uploaded manifest differs, use its actual permissions.

| Permission | Suggested justification |
| --- | --- |
| `storage` | Save user settings, site exceptions, local counters/history, and extension configuration needed for phishing protection. |
| `declarativeNetRequest` | Block requests matching known-threat rules and apply user-controlled site exceptions. |
| `alarms` | Schedule periodic threat-list refreshes and rule-update maintenance in the background. |
| `contextMenus` | Provide right-click actions to inspect selected text or links on the current webpage. |
| `sidePanel` | Display the page assessment, explanations, and analysis controls alongside the active webpage. |
| `http://*/*` and `https://*/*` | Inspect supported webpages and permitted frames for phishing evidence, including addresses, links, form structure, and selected behaviors, and show warnings on the page. This protection must operate across the sites the user visits. |

### Remote code

The packaged JavaScript, model assets, and WASM runtime are local. The public threat-list updates are data, not downloaded executable JavaScript. For an unchanged package with no remote executable code, choose **No, I am not using remote code**. Optional browser-managed Gemini model downloads are distinct from your extension downloading and executing a remote script. Reassess this declaration if you change the build.

### Data usage

Do not blindly select “no user data” because checks are local. Google's policy explicitly covers local processing.

For this build, review **Web history**, **Website content**, and **User activity** first: the code processes page URLs/content and interaction categories. Also assess whether incidental sensitive information in page text or wallet/clipboard checks falls under other displayed categories. Do not certify categories based only on whether data reaches your own server.

Match the final selections to the actual build and policy, including local retention, network metadata, optional reports, and any service you enable. The fields in the live dashboard and the data you actually handle determine your answers. Tick the limited-use certification statements only when they are true.

## 7. Give reviewers a repeatable way to test

In the reviewer/test-instructions field, explain:

> No account or login is required. After installation, open an ordinary HTTPS webpage and open the PhishGuard toolbar popup. Inspect its page status and available reasons. Navigate to a different page and confirm the result follows the active page. Select harmless text and use the PhishGuard context-menu analysis action. Optional Gemini activation depends on browser/device eligibility; the packaged local fallback does not require a local companion server. Remote URL inspection is disabled because no publisher endpoint is configured.

Add a safe test-page URL you control if one is available, plus the exact steps and expected warning for that page. Do not claim a nonexistent demo URL. If a specific feature needs special conditions, document those conditions.

## 8. Submit and publish

1. Complete **Store listing**, **Privacy practices**, and **Distribution**.
2. For a listing anyone can find, choose **Public** distribution. Use **Unlisted** only if you want installation primarily through a direct link.
3. Select the countries/regions you intend to support and complete any required declarations shown by the dashboard.
4. Save changes and resolve every dashboard validation error.
5. Click **Submit for review**.
6. If offered, choose **deferred/manual publication** so you can inspect approval status before making the listing live. Alternatively, automatic publication releases it after approval.
7. Monitor the dashboard and developer email. Review duration varies; submission is not approval.
8. If rejected, follow the stated reason, fix the package or listing, and resubmit the same item. Increase the manifest version when uploading a changed package.
9. Once approved, click **Publish** if publication was deferred.
10. Open the live listing signed out and verify the install button and links. Install that store version into a clean Chrome profile and repeat the main checks.

After it is live, add the real Chrome Web Store URL near the top of `README.md`, replace the development-only installation emphasis with store installation, commit, and push. Do not add a fake store badge or placeholder install link before approval.

## 9. Attach a downloadable GitHub release

The source includes a release workflow triggered by tags starting with `v`. It can create or overwrite release assets after its CI jobs pass. Choose one release method rather than racing a manual upload against that workflow.

**Simple manual method:** before creating a version tag, open GitHub → **Actions → Release → … → Disable workflow** for the release workflow only. Then open the repository homepage → **Releases → Draft a new release**. Create a tag such as `v1.0.1` from the tested source commit, title it `PhishGuard 1.0.1`, attach the matching `phishguard-chrome.zip`, describe what was tested and the known limitations, and mark it **pre-release** while it remains a development candidate. Publish the release. Do not attach a stale ZIP after source changes.

**Automated method:** retain the workflow, check that `manifest.json`, `manifest.firefox.json`, `package.json`, and `CHANGELOG.md` agree on the version, then create the matching `vVERSION` tag. Allow CI to finish and inspect the assets it produces. If it fails, diagnose the Actions log instead of treating a tag as a successful release.

GitHub source publication, a GitHub release, and Chrome Web Store approval are three separate actions.

## 10. Future updates

1. Make and test the change.
2. Increase the version (for example, `1.0.1` → `1.0.2`) in both manifests and `package.json`; update lockfile metadata as needed and add the corresponding changelog entry.
3. Run tests and rebuild. Test the resulting Chrome package.
4. Commit and push the source.
5. Open the existing Chrome dashboard item → **Package → Upload new package**, upload the new Chrome ZIP, update disclosures/listing if needed, and submit the update for review.
6. Publish the corresponding GitHub release using your chosen method.

## Official references

- [Chrome Web Store publication](https://developer.chrome.com/docs/webstore/publish)
- [Privacy-practices fields](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy)
- [User-data FAQ, including local processing](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq)
- [Image sizes and requirements](https://developer.chrome.com/docs/webstore/images)
- [Developer account setup](https://developer.chrome.com/docs/webstore/set-up-account)
- [Publish an existing project with GitHub Desktop](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-an-existing-project-to-github-using-github-desktop)
- [Configure GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
