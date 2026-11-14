# n8n-nodes-remove-ac

Official zero-dependency **[n8n](https://n8n.io)** community node for **[remove.ac](https://remove.ac)** — drop-in `/v1.0/removebg` Cloud GPU background removal ahead of the **December 1, 2026** `remove.bg` standalone site and self-serve `/v1.0/removebg` API shutdown.

- **Migration Guide (`remove.bg` → `remove.ac`):** https://remove.ac/guides/n8n-make-shopify-background-removal-api
- **API Keys & 1 Free Welcome Credit:** https://remove.ac/api-info
- **Free On-Device Browser WASM Workbench (50-Image Batch ZIP):** https://remove.ac

---

## Why Use `n8n-nodes-remove-ac`?

1. **Drop-In Replacement for Deprecated `Remove.bg` Workflows:** Accepts upstream n8n binary items (`data`) or public image URLs and outputs ready-to-upload cutout binaries (`PNG`, `WebP`, `JPG`, `ZIP`) plus `X-Foreground-*` bounding-box metadata.
2. **Automatic `> 4 MB` Zero-Disk GPU Streaming (Up to `25 MB / 40 MP`):** Large studio product photos automatically negotiate a 180-second single-use HMAC ticket (`POST /v1.0/removebg/ticket`) to bypass serverless payload caps without persisting source or output pixels to disk.
3. **AI Agent Tool Ready (`usableAsTool: true`):** Works both as a standard pipeline transform node and as a callable tool inside n8n AI Agent workflows.
4. **Zero External Runtime Dependencies & SSRF Hardened:** Built strictly on Node.js built-in primitives and n8n's `httpRequest` helper with IPv4/IPv6/NAT64/DNS private-network blocking.

---

## Installation in n8n

1. Open your self-hosted or desktop n8n instance.
2. Go to **Settings → Community Nodes → Install**.
3. Enter **`n8n-nodes-remove-ac`**, accept the prompt, and click **Install**.
4. Create a **remove.ac API** credential using your `rac_live_...` API key from https://remove.ac/api-info (verified email accounts receive **1 free credit**; non-expiring packs start at `$9 / 10` credits, monthly plans down to `$0.158 / image`; failed or timed-out calls cost `0` credits).

---

## Operations

- **Remove Background (`removeBackground`)**
  - **Binary Data:** Reads any upstream binary property (default `data`) up to `25 MB` and writes the transparent cutout binary + `json.removeAc` metadata (`creditsCharged`, `width`, `height`, `foregroundTop/Left/Width/Height`).
  - **Image URL:** Sends a validated public `https://` / `http://` URL to `POST /v1.0/removebg` and outputs the cutout binary.
- **Get Account Balance (`getAccount`)**
  - Queries `GET /v1.0/account` and returns `totalCredits` + full account breakdown.

---

## License

MIT © [remove.ac](https://remove.ac)
