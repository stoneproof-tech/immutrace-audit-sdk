# IMMUTRACE Observer SDK (frontend, standalone)

`immutrace-observer.js` is the **backend-agnostic** browser library that IMMUTRACE
injects into upstream HTML responses (served at `/_immutrace/sdk.js`). It is the
**canonical source** — the proxy serves this exact file; there is no duplicate.

It is self-contained vanilla JS (no build step, no dependencies) and contains no
references to any specific upstream system. It:

- renders the authorization modal (justification, activity type, case id),
- intercepts `fetch()` to catch `401 X-Immutrace-Gate: blocked` and re-prompt,
- shows the persistent audit session banner.

## Use it on any system
Either let the IMMUTRACE proxy inject it automatically (zero code change on the
upstream), or include it manually:

```html
<script defer src="https://your-immutrace-host/_immutrace/sdk.js"></script>
```

The set of endpoints that trigger the authorization gate is configured server-side
in `config/sensitive_endpoints.yaml` — not here.
