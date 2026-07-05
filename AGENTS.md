# fortidlp-policy-summarizer (public)

PUBLIC repo — `origin` is github.com/caswitz/fortidlp-policy-summarizer. Everything committed here is world-readable.

## Rules

- Nothing internal ever lands here: no lab hostnames/IPs, no customer data, no real `.policies` exports, no credentials, no references to private repos or engagements. Example data must be synthetic.
- The sibling `../policy-summarizer` (private) holds the working version used with real policy data — keep the two strictly separate; this repo receives sanitized releases.
- Python 3.9+ stdlib only — the README promises zero external dependencies; don't add any without updating that promise.
