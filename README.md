# n8n-nodes-remove-ac

Official zero-dependency **[n8n](https://n8n.io)** community node for **[remove.ac](https://remove.ac)** — drop-in `/v1.0/removebg` Cloud GPU background removal ahead of the **December 1, 2026** `remove.bg` standalone site and self-serve `/v1.0/removebg` API shutdown.

- **Migration Guide (`remove.bg` → `remove.ac`):** https://remove.ac/guides/n8n-make-shopify-background-removal-api
- **API Keys & 10 Full-Resolution Welcome Credits (Valid 30 Days):** https://remove.ac/api-info
- **Free On-Device Browser WASM Workbench (50-Image Batch ZIP) & Free `~612px` Cloud GPU Preview (`0` Credits):** https://remove.ac/upload
- **Dec 1 Migration Grant (`30%-50%` Off Through Dec 31, 2026) & `14`-Day Self-Serve Refund:** https://remove.ac/pricing

---

## Why Use `n8n-nodes-remove-ac`?

1. **Drop-In Replacement for Deprecated `Remove.bg` Workflows:** Accepts upstream n8n binary items (`data`) or public image URLs, supports custom background image binaries (`bgImageBinaryProperty` / `bg_image_file`) or URLs (`bgImageUrl`), and outputs ready-to-upload cutout binaries (`Auto`, `PNG`, `WebP`, `JPG`, `ZIP`) plus `X-Foreground-*` bounding-box metadata.
2. **Automatic `> 4 MB` Zero-Disk GPU Streaming (Up to `25 MB / 50 MP`):** Large studio product photos across `25mp`, `50mp`, `full`, and `auto` tiers automatically negotiate a 180-second single-use HMAC ticket (`POST /v1.0/removebg/ticket`) to bypass serverless payload caps without persisting source or output pixels to disk.
3. **AI Agent Tool Ready (`usableAsTool: true`):** Works both as a standard pipeline transform node and as a callable tool inside n8n AI Agent workflows. When attaching **remove.ac** as an AI Agent tool, set **Input Source = Image URL** (if left on Binary Data with no binary attachment, the node also auto-falls back to a supplied `imageUrl` parameter or `json.imageUrl` field).
4. **Zero External Runtime Dependencies & SSRF Hardened:** Built strictly on Node.js built-in primitives and n8n's `httpRequest` helper with IPv4/IPv6/NAT64/DNS private-network blocking.
5. **Free Interactive `~612px` Cloud Preview & Bug Rewards:** Test tricky product edges interactively at `~612px` for `0` credits on [remove.ac/upload](https://remove.ac/upload) (`5/day` on free accounts, `30/day` with paid credits) before automating in n8n, or report bugs/workflow ideas on the [remove.ac](https://remove.ac) homepage (`<= 3` submissions/24h) to earn `5-20` non-expiring Cloud GPU credits once verified and accepted.

---

## Installation in n8n

1. Open your self-hosted or desktop n8n instance.
2. Go to **Settings → Community Nodes → Install**.
3. Enter **`n8n-nodes-remove-ac`**, accept the prompt, and click **Install**.
4. Create a **remove.ac API** credential using your `rac_live_...` API key from https://remove.ac/api-info (verified email accounts receive **10 full-resolution welcome credits (valid 30 days)**; regular list prices before the auto-applied **`30%-50%` Dec 1 Migration Grant through Dec 31, 2026** start at `$9 / 10` non-expiring credits, with monthly plans down to `$0.130 / image` on `5,000/mo`; Enterprise `2,800`/`5,000` annual migration grants via `support@remove.ac`; initial orders include a `14`-day self-serve trial refund; failed or timed-out calls cost `0` credits).

---

## Operations

- **Remove Background (`removeBackground`)**
  - **Binary Data:** Reads any upstream binary property (default `data`) up to `25 MB / 50 MP` (plus optional `bgImageBinaryProperty` or `bgImageUrl` background compositing) and writes the transparent or composited cutout binary + `json.removeAc` metadata (`creditsCharged`, `width`, `height`, `foregroundTop/Left/Width/Height`).
  - **Image URL:** Sends a validated public `https://` / `http://` URL to `POST /v1.0/removebg` and outputs the cutout binary.
- **Get Account Balance (`getAccount`)**
  - Queries `GET /v1.0/account` and returns `totalCredits` + full account breakdown.

---

## License

MIT © [remove.ac](https://remove.ac)
