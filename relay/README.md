# PhishGuard reporting relay

This optional API receives explicitly enabled community threat reports. Deploy it to an HTTPS host you control, configure its required environment variables, and enter the deployed `/api/report` URL in PhishGuard Settings → About. A new extension installation has no default reporting destination.

Only configure a relay you control or trust. The extension sends reports only after the user enables community reporting; changing the endpoint or disabling consent clears queued reports. Review the API handler and retention configuration before making the service public.

Use the package scripts and deployment instructions supplied by your chosen hosting provider. Do not commit secrets or use an HTTP endpoint for production reporting.
