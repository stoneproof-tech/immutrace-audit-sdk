# OSIRIS integration — "1 line in layout.tsx" marker

## TL;DR — this demo does NOT need it

The proxy injects `<script defer src="/_immutrace/sdk.js"></script>` into
every HTML response server-side (see `proxy/proxy.py` → `_maybe_inject`).
**OSIRIS source code is not touched in any way for this demo.** Zero forks,
zero patches, zero rebases.

## When you'd want the 1-line integration

If, in a future deployment scenario, IMMUTRACE is **NOT** in the middle as a
proxy — for example, OSIRIS is served from Vercel directly and IMMUTRACE
runs as a hosted API on a separate domain — then the analyst's browser would
not receive the auto-injected script.

In that case, **one line** in `src/app/layout.tsx` makes OSIRIS load the SDK
directly from the IMMUTRACE endpoint:

```diff
  // src/app/layout.tsx  (OSIRIS upstream)
  export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
      <html lang="en">
        <head>
+         <script defer src="https://audit.your-org.example/sdk.js"></script>
        </head>
        <body>{children}</body>
      </html>
    )
  }
```

That's the entire change. The SDK self-bootstraps:
- detects whether a session cookie exists,
- shows the authorization modal on the first sensitive `fetch()`,
- monkey-patches `window.fetch` to retry after authorization.

The `audit.your-org.example` host (the IMMUTRACE backend) is the only
runtime dependency. The OSIRIS bundle gains ~8 KB and one HTTP request.

## Why we chose the proxy path for the demo

1. **Zero touch on OSIRIS source** — no fork to maintain, no rebase debt.
2. **Stronger audit guarantee** — the proxy sits on the network path;
   an analyst cannot bypass it without DNS/networking-level privileges.
3. **Works with the prebuilt Docker image** (`ghcr.io/aiacos/osiris:latest`)
   without rebuilding.

For a managed-OSIRIS SaaS scenario, the 1-line embed would be the right
distribution model — we keep this file as documentation that the path
exists and is trivial.
