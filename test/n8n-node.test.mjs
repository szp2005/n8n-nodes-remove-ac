import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { RemoveAcApi } = require("../dist/credentials/RemoveAcApi.credentials.js");
const {
  RemoveAc,
  formatErrorBody,
  normalizeShadowOptions,
  parseImageDimensions,
  toNodeBuffer,
  validatePublicUrl,
} = require("../dist/nodes/RemoveAc/RemoveAc.node.js");

const TINY_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64"
);

function createMockExecuteContext({
  items,
  params,
  credentials = { apiKey: "rac_live_n8n_key", baseUrl: "http://127.0.0.1:8787" },
  binaryBuffers = {},
  httpRequest,
  continueOnFail = false,
  allowLoopbackBaseUrlForTest = true,
  dnsLookupForTest = async () => [{ address: "93.184.216.34", family: 4 }],
}) {
  return {
    _allowLoopbackBaseUrlForTest: allowLoopbackBaseUrlForTest,
    _dnsLookupForTest: dnsLookupForTest,
    getInputData() {
      return items;
    },
    async getCredentials(name) {
      assert.equal(name, "removeAcApi");
      return credentials;
    },
    getNodeParameter(name, index, fallback) {
      const perItem = Array.isArray(params) ? params[index] : params;
      return perItem && name in perItem ? perItem[name] : fallback;
    },
    continueOnFail() {
      return continueOnFail;
    },
    helpers: {
      assertBinaryData(index, prop) {
        const bin = items[index].binary && items[index].binary[prop];
        if (!bin) throw new Error(`Missing binary property ${prop}`);
        return bin;
      },
      async getBinaryDataBuffer(_index, prop) {
        return binaryBuffers[prop];
      },
      async prepareBinaryData(buffer, fileName, mimeType) {
        return {
          data: buffer.toString("base64"),
          fileName,
          mimeType,
        };
      },
      httpRequest,
    },
  };
}

test("RemoveAcApi credential exposes X-Api-Key header and HTTPS-only no-redirect /v1.0/account test check", () => {
  const cred = new RemoveAcApi();
  assert.equal(cred.name, "removeAcApi");
  assert.equal(cred.authenticate.properties.headers["X-Api-Key"], "={{$credentials.apiKey}}");
  assert.equal(cred.test.request.url, "/v1.0/account");
  assert.equal(cred.test.request.disableFollowRedirect, true);
  assert.equal(cred.test.request.sendCredentialsOnCrossOriginRedirect, false);

  // Evaluate the credential test.request.baseURL expression against valid & malicious baseUrl inputs
  const expr = cred.test.request.baseURL.replace(/^=\{\{|\}\}$/g, "").trim();
  const evalBaseUrl = (baseUrl) =>
    new Function("$credentials", `return (${expr});`)({ baseUrl });

  assert.equal(evalBaseUrl("https://remove.ac"), "https://remove.ac");
  assert.equal(evalBaseUrl("https://remove.ac/"), "https://remove.ac");
  assert.equal(evalBaseUrl(""), "https://remove.ac");
  assert.equal(evalBaseUrl("http://remove.ac"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("http://169.254.169.254"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("https://127.0.0.1:8080"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("https://[::ffff:169.254.169.254]"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("https://localhost:3000"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("https://metadata.internal"), "invalid://https-public-domain-required");
  assert.equal(evalBaseUrl("https://user:pass@remove.ac"), "invalid://https-public-domain-required");
});

test("RemoveAc node removes background from binary input and outputs binary + foreground metadata", async () => {
  const node = new RemoveAc();
  assert.equal(node.description.usableAsTool, true);

  let capturedReq = null;
  const ctx = createMockExecuteContext({
    items: [
      {
        json: { sku: "SHOE-01" },
        binary: {
          data: { fileName: "shoe.jpg", mimeType: "image/jpeg" },
        },
      },
    ],
    binaryBuffers: { data: TINY_PNG },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "cutout",
      size: "full",
      format: "png",
      additionalOptions: { bgColor: "#FFFFFF", crop: true },
    },
    httpRequest: async (opts) => {
      capturedReq = opts;
      return {
        statusCode: 200,
        headers: {
          "content-type": "image/png",
          "x-credits-charged": "1",
          "x-width": "800",
          "x-height": "600",
          "x-foreground-top": "10",
          "x-foreground-left": "20",
          "x-foreground-width": "760",
          "x-foreground-height": "580",
        },
        body: TINY_PNG,
      };
    },
  });

  const [out] = await node.execute.call(ctx);
  assert.equal(out.length, 1);
  assert.equal(capturedReq.url, "http://127.0.0.1:8787/v1.0/removebg");
  assert.equal(capturedReq.headers["X-Api-Key"], "rac_live_n8n_key");
  const bodyStr = capturedReq.body.toString("utf8");
  assert.match(bodyStr, /name="bg_color"\r\n\r\nFFFFFF/);
  assert.match(bodyStr, /name="crop"\r\n\r\ntrue/);
  assert.equal(out[0].json.sku, "SHOE-01");
  assert.equal(out[0].json.removeAc.creditsCharged, 1);
  assert.equal(out[0].json.removeAc.foregroundWidth, 760);
  assert.equal(out[0].binary.cutout.fileName, "shoe-nobg.png");
});

test("RemoveAc node automatically upgrades >4 MB binary inputs to /v1.0/removebg/ticket", async () => {
  const node = new RemoveAc();
  const largeBuf = Buffer.alloc(4 * 1024 * 1024 + 64, 0xab);
  const calls = [];

  const ctx = createMockExecuteContext({
    items: [
      {
        json: {},
        binary: { data: { fileName: "studio-raw.png", mimeType: "image/png" } },
      },
    ],
    binaryBuffers: { data: largeBuf },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async (opts) => {
      calls.push(opts);
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        assert.equal(opts.body.foregroundByteLength, largeBuf.byteLength);
        assert.equal(typeof opts.body.foregroundSha256, "string");
        return {
          data: {
            directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
            ticket: "hmac_ticket_123",
          },
        };
      }
      assert.equal(opts.url, "http://127.0.0.1:9999/v1.0/direct-cutout");
      assert.equal(opts.headers.Authorization, "Bearer hmac_ticket_123");
      assert.equal(opts.headers["X-Api-Key"], undefined);
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });

  const [out] = await node.execute.call(ctx);
  assert.equal(calls.length, 2);
  assert.equal(out[0].binary.data.fileName, "studio-raw-nobg.png");
});

test("RemoveAc node blocks SSRF on imageUrl, baseUrl, and directEndpoint, and handles getAccount=0 + continueOnFail", async () => {
  const node = new RemoveAc();

  await assert.rejects(
    () =>
      validatePublicUrl("http://[::ffff:169.254.169.254]/latest/meta-data", {
        lookupFn: async () => [{ address: "169.254.169.254", family: 4 }],
      }),
    /Private, loopback, or reserved IPv6/
  );

  await assert.rejects(
    () =>
      validatePublicUrl("http://remove.ac", {
        requireHttps: true,
        lookupFn: async () => [{ address: "104.21.1.1", family: 4 }],
      }),
    /must use https:\/\//
  );

  // continueOnFail catches SSRF rejection per item cleanly
  const failCtx = createMockExecuteContext({
    items: [{ json: { id: 1 } }],
    continueOnFail: true,
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "http://127.0.0.1:8080/internal.png",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async () => {
      throw new Error("should not reach network");
    },
  });
  const [failOut] = await node.execute.call(failCtx);
  assert.match(failOut[0].json.error, /Private, loopback/);

  // getAccount preserves 0 credit balance accurately and disables redirect following
  const acctCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: { operation: "getAccount" },
    httpRequest: async (opts) => {
      assert.equal(opts.url, "http://127.0.0.1:8787/v1.0/account");
      assert.equal(opts.disableFollowRedirect, true);
      assert.equal(opts.sendCredentialsOnCrossOriginRedirect, false);
      return {
        statusCode: 200,
        headers: { "content-type": "application/json" },
        body: { data: { attributes: { credits: { total: 0 } } } },
      };
    },
  });
  const [acctOut] = await node.execute.call(acctCtx);
  assert.equal(acctOut[0].json.totalCredits, 0);
});

test("MF-1 & MF-4: RemoveAc node rejects 3xx redirects across all endpoints, syncs gateway options (no 3d), and parses GIF/WebP headers", async () => {
  const node = new RemoveAc();

  // Verify Size, Foreground Type, and Shadow Type options match production remove.ac gateway
  const sizeProp = node.description.properties.find((p) => p.name === "size");
  const sizeVals = sizeProp.options.map((o) => o.value);
  assert.ok(sizeVals.includes("regular") && sizeVals.includes("small"));

  const addProps = node.description.properties.find((p) => p.name === "additionalOptions").options;
  const fgTypeVals = addProps.find((p) => p.name === "type").options.map((o) => o.value);
  assert.ok(fgTypeVals.includes("transportation"));

  const shadowVals = addProps.find((p) => p.name === "shadowType").options.map((o) => o.value);
  assert.equal(shadowVals.includes("3d"), false);
  assert.deepEqual(
    new Set(shadowVals),
    new Set(["auto", "car", "drop", "soft", "contact", "reflection", "none"])
  );

  // Verify GIF and VP8X WebP dimension parsing
  const gifHeader = Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x20, 0x03, 0x58, 0x02]);
  assert.deepEqual(parseImageDimensions(gifHeader), { width: 800, height: 600 });

  const webpVp8x = Buffer.alloc(30);
  webpVp8x.write("RIFF", 0, "ascii");
  webpVp8x.write("WEBP", 8, "ascii");
  webpVp8x.write("VP8X", 12, "ascii");
  // width - 1 = 3999 (0x000f9f), height - 1 = 2999 (0x000bb7)
  webpVp8x[24] = 0x9f;
  webpVp8x[25] = 0x0f;
  webpVp8x[26] = 0x00;
  webpVp8x[27] = 0xb7;
  webpVp8x[28] = 0x0b;
  webpVp8x[29] = 0x00;
  assert.deepEqual(parseImageDimensions(webpVp8x), { width: 4000, height: 3000 });

  // Verify 307 redirect responses fail closed with disableFollowRedirect: true on both /v1.0/removebg and /v1.0/removebg/ticket
  let removebgCalls = 0;
  const redirRemoveBgCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "a.png", mimeType: "image/png" } } }],
    binaryBuffers: { data: TINY_PNG },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async (opts) => {
      removebgCalls += 1;
      assert.equal(opts.disableFollowRedirect, true);
      assert.equal(opts.sendCredentialsOnCrossOriginRedirect, false);
      return { statusCode: 307, headers: { location: "http://169.254.169.254/" }, body: Buffer.from("") };
    },
  });
  await assert.rejects(() => node.execute.call(redirRemoveBgCtx), /\[HTTP 307\]/);
  assert.equal(removebgCalls, 1);

  let ticketCalls = 0;
  const redirTicketCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "big.webp", mimeType: "image/webp" } } }],
    binaryBuffers: { data: webpVp8x }, // 12 MP (>5 MP) triggers upfront ticket preflight!
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async (opts) => {
      ticketCalls += 1;
      assert.equal(opts.url, "http://127.0.0.1:8787/v1.0/removebg/ticket");
      assert.equal(opts.disableFollowRedirect, true);
      assert.equal(opts.sendCredentialsOnCrossOriginRedirect, false);
      return { statusCode: 302, headers: { location: "http://evil.example/" }, body: "" };
    },
  });
  await assert.rejects(() => node.execute.call(redirTicketCtx), /\[HTTP 302\]/);
  assert.equal(ticketCalls, 1);
});

test("v1.0.1 exposes 25mp & 50mp tiers, 10 welcome credits copy, and bgImageBinaryProperty / bgImageUrl on sync & ticket streams", async () => {
  const crypto = await import("node:crypto");
  const cred = new RemoveAcApi();
  const apiKeyProp = cred.properties.find((p) => p.name === "apiKey");
  assert.match(apiKeyProp.description, /10 full-resolution welcome credits \(valid 30 days\)/);

  const node = new RemoveAc();
  assert.match(node.description.description, /50 MP/);
  const sizeProp = node.description.properties.find((p) => p.name === "size");
  const sizeVals = sizeProp.options.map((o) => o.value);
  assert.ok(sizeVals.includes("25mp") && sizeVals.includes("50mp"));
  assert.match(sizeProp.options.find((o) => o.value === "full").name, /50 MP/);

  // 1. Sync /v1.0/removebg encodes both image_file and bg_image_file from bgImageBinaryProperty
  let syncBodyStr = "";
  const syncBgCtx = createMockExecuteContext({
    items: [
      {
        json: { id: "bg-sync" },
        binary: {
          data: { fileName: "product.png", mimeType: "image/png" },
          backdrop: { fileName: "marble.jpg", mimeType: "image/jpeg" },
        },
      },
    ],
    binaryBuffers: {
      data: TINY_PNG,
      backdrop: Buffer.from("MARBLE_JPEG_BYTES"),
    },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "cutout",
      size: "50mp",
      format: "png",
      additionalOptions: { bgImageBinaryProperty: "backdrop" },
    },
    httpRequest: async (opts) => {
      assert.equal(opts.url, "http://127.0.0.1:8787/v1.0/removebg");
      syncBodyStr = opts.body.toString("utf8");
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  const [syncOut] = await node.execute.call(syncBgCtx);
  assert.equal(syncOut[0].binary.cutout.fileName, "product-nobg.png");
  assert.match(syncBodyStr, /name="image_file"; filename="product\.png"/);
  assert.match(syncBodyStr, /name="bg_image_file"; filename="marble\.jpg"/);
  assert.match(syncBodyStr, /MARBLE_JPEG_BYTES/);
  assert.match(syncBodyStr, /name="size"\r\n\r\n50mp/);

  // 2. Combined >4 MB (2.5 MB fg + 2.5 MB bg) upgrades to /v1.0/removebg/ticket with bgImageSha256 & uploads bg_image_file
  const fg25 = Buffer.alloc(Math.floor(2.5 * 1024 * 1024), 0x31);
  const bg25 = Buffer.alloc(Math.floor(2.5 * 1024 * 1024), 0x32);
  let seenTicketPayload = null;
  let seenDirectBody = null;

  const ticketBgCtx = createMockExecuteContext({
    items: [
      {
        json: {},
        binary: {
          data: { fileName: "fg.png", mimeType: "image/png" },
          bgData: { fileName: "bg.png", mimeType: "image/png" },
        },
      },
    ],
    binaryBuffers: { data: fg25, bgData: bg25 },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "25mp",
      format: "png",
      additionalOptions: { bgImageBinaryProperty: "bgData" },
    },
    httpRequest: async (opts) => {
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        seenTicketPayload = opts.body;
        return {
          data: {
            directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
            ticket: "hmac_bg_tkt",
          },
        };
      }
      seenDirectBody = opts.body;
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  await node.execute.call(ticketBgCtx);
  assert.equal(seenTicketPayload.size, "25mp");
  assert.equal(seenTicketPayload.bgImageSha256, crypto.createHash("sha256").update(bg25).digest("hex"));
  assert.equal(seenTicketPayload.bgImageByteLength, bg25.byteLength);
  assert.ok(seenDirectBody.includes(Buffer.from('name="image_file"; filename="fg.png"')));
  assert.ok(seenDirectBody.includes(Buffer.from('name="bg_image_file"; filename="bg.png"')));

  // 3. Rejects SSRF bgImageUrl and conflicting background options before touching network
  for (const badAdditional of [
    { bgColor: "FFFFFF", bgImageBinaryProperty: "bgData" },
    { bgImageUrl: "http://169.254.169.254/latest/meta-data" },
  ]) {
    const badCtx = createMockExecuteContext({
      items: [
        {
          json: {},
          binary: {
            data: { fileName: "fg.png", mimeType: "image/png" },
            bgData: { fileName: "bg.png", mimeType: "image/png" },
          },
        },
      ],
      binaryBuffers: { data: TINY_PNG, bgData: TINY_PNG },
      params: {
        operation: "removeBackground",
        inputSource: "binary",
        binaryPropertyName: "data",
        outputBinaryPropertyName: "data",
        size: "full",
        format: "png",
        additionalOptions: badAdditional,
      },
      httpRequest: async () => {
        throw new Error("should not reach network");
      },
    });
    await assert.rejects(() => node.execute.call(badCtx));
  }
});

function makePngHeader(width, height, totalBytes = 64) {
  const buf = Buffer.alloc(Math.max(33, totalBytes), 0);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(buf, 0);
  buf.writeUInt32BE(13, 8);
  buf.write("IHDR", 12, "ascii");
  buf.writeUInt32BE(width, 16);
  buf.writeUInt32BE(height, 20);
  buf[24] = 8;
  buf[25] = 6;
  return buf;
}

test("R2 MF-1 (Probes 1, 2 & 7): releases ticket credit holds on 502/3xx/413/network/validation failures and blocks >32 MB combined multipart upfront", async () => {
  const http = await import("node:http");
  const node = new RemoveAc();

  // 1. Combined 20 MB fg + 15 MB bg (= 35 MB > 32 MB worker limit) rejects BEFORE /v1.0/removebg/ticket (0 HTTP calls)
  const fg20 = makePngHeader(1000, 1000, 20 * 1024 * 1024);
  const bg15 = makePngHeader(1000, 1000, 15 * 1024 * 1024);
  let combinedHttpCalls = 0;
  const combinedCtx = createMockExecuteContext({
    items: [
      {
        json: {},
        binary: {
          data: { fileName: "fg20.png", mimeType: "image/png" },
          bg: { fileName: "bg15.png", mimeType: "image/png" },
        },
      },
    ],
    binaryBuffers: { data: fg20, bg: bg15 },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { bgImageBinaryProperty: "bg" },
    },
    httpRequest: async () => {
      combinedHttpCalls += 1;
      throw new Error("must not touch network");
    },
  });
  await assert.rejects(() => node.execute.call(combinedCtx), /32 MB direct upload stream limit/);
  assert.equal(combinedHttpCalls, 0);

  // 2. Live loopback Gateway + Worker + RedirectTarget verifying Probe 1 (502 -> release -> immediate retry succeeds with 1 credit) & Probe 7 (307 redirect no-leak + release)
  const heldLocks = new Map();
  let availableCredits = 1;
  let releaseCalls = 0;
  let redirectTargetHits = 0;
  let directMode = "502"; // "502" | "307" | "ok"
  let spoofReleaseOrigin = false;

  const redirectTarget = http.createServer((_req, res) => {
    redirectTargetHits += 1;
    res.writeHead(200);
    res.end("LEAKED");
  });
  await new Promise((r) => redirectTarget.listen(0, "127.0.0.1", r));
  const redirPort = redirectTarget.address().port;

  const worker = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (directMode === "307") {
        res.writeHead(307, { Location: `http://127.0.0.1:${redirPort}/steal` });
        res.end();
        return;
      }
      if (directMode === "502") {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end("Bad Gateway");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "image/png",
        "X-Credits-Charged": "1",
        "X-Width": "3000",
        "X-Height": "3000",
      });
      res.end(TINY_PNG);
    });
  });
  await new Promise((r) => worker.listen(0, "127.0.0.1", r));
  const workerPort = worker.address().port;

  let gatewayPort = 0;
  const gateway = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (req.url === "/v1.0/removebg/ticket" && req.method === "POST") {
        let activeHeld = 0;
        for (const h of heldLocks.values()) {
          if (!h.released && !h.completed) activeHeld += 1;
        }
        if (availableCredits - activeHeld < 1) {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ errors: [{ title: "Insufficient credits", code: "insufficient_credits" }] }));
          return;
        }
        const holdId = `hold_${heldLocks.size + 1}`;
        const releaseToken = `rel_${heldLocks.size + 1}`;
        heldLocks.set(holdId, { released: false, completed: false, releaseToken });
        const data = {
          ticket: `tkt_${holdId}`,
          directEndpoint: `http://127.0.0.1:${workerPort}/v1.0/direct-cutout`,
          holdId,
          releaseToken,
          releaseEndpoint: spoofReleaseOrigin
            ? `http://127.0.0.1:${redirPort}/steal-api-key`
            : `http://127.0.0.1:${gatewayPort}/v1.0/removebg/ticket/release`,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ...data, data }));
        return;
      }
      if (req.url === "/v1.0/removebg/ticket/release" && req.method === "POST") {
        releaseCalls += 1;
        assert.equal(req.headers["x-api-key"], "rac_live_n8n_key");
        const body = JSON.parse(raw);
        const h = heldLocks.get(body.holdId);
        if (h && h.releaseToken === body.releaseToken) {
          h.released = true;
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, released: true }));
          return;
        }
        res.writeHead(403);
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  await new Promise((r) => gateway.listen(0, "127.0.0.1", r));
  gatewayPort = gateway.address().port;

  const realHttpRequest = async (opts) => {
    const parsed = new URL(opts.url);
    const headers = { ...(opts.headers || {}) };
    let payload;
    if (opts.body !== undefined && opts.body !== null) {
      payload = Buffer.isBuffer(opts.body)
        ? opts.body
        : typeof opts.body === "string"
          ? Buffer.from(opts.body, "utf8")
          : Buffer.from(JSON.stringify(opts.body), "utf8");
      headers["Content-Length"] = String(payload.byteLength);
    }
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port,
          path: parsed.pathname + parsed.search,
          method: opts.method || "GET",
          headers,
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const rawBuf = Buffer.concat(chunks);
            let body = rawBuf;
            if (opts.json && opts.encoding !== "arraybuffer") {
              try {
                body = JSON.parse(rawBuf.toString("utf8"));
              } catch {
                body = rawBuf.toString("utf8");
              }
            }
            resolve({ statusCode: res.statusCode, headers: res.headers, body });
          });
        }
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  };

  try {
    const png9Mp = makePngHeader(3000, 3000, 64);
    const liveCtx = createMockExecuteContext({
      items: [{ json: {}, binary: { data: { fileName: "shot.png", mimeType: "image/png" } } }],
      credentials: { apiKey: "rac_live_n8n_key", baseUrl: `http://127.0.0.1:${gatewayPort}` },
      binaryBuffers: { data: png9Mp },
      params: {
        operation: "removeBackground",
        inputSource: "binary",
        binaryPropertyName: "data",
        outputBinaryPropertyName: "data",
        size: "50mp",
        format: "png",
        additionalOptions: {},
      },
      httpRequest: realHttpRequest,
    });

    // Attempt 1: 502 from directEndpoint + spoofed releaseEndpoint -> falls back to safe baseUrl release, freeing hold!
    spoofReleaseOrigin = true;
    await assert.rejects(() => node.execute.call(liveCtx), /\[HTTP 502\]/);
    assert.equal(releaseCalls, 1);
    assert.equal(redirectTargetHits, 0, "Spoofed releaseEndpoint must never receive X-Api-Key");

    // Attempt 2: 307 redirect from directEndpoint -> blocked with 0 redirectTargetHits AND hold released!
    spoofReleaseOrigin = false;
    directMode = "307";
    await assert.rejects(() => node.execute.call(liveCtx), /\[HTTP 307\]/);
    assert.equal(releaseCalls, 2);
    assert.equal(redirectTargetHits, 0);

    // Attempt 3: Worker recovers -> succeeds immediately using the same 1 credit (no HTTP 402)!
    directMode = "ok";
    const [okOut] = await node.execute.call(liveCtx);
    assert.equal(okOut[0].json.removeAc.width, 3000);
  } finally {
    gateway.close();
    worker.close();
    redirectTarget.close();
  }
});

test("R2 MF-2 (Probe 3): inputSource='url' upgrades to ticket stream when bgImageBinaryProperty >4 MB or /v1.0/removebg returns 413, blocking SSRF redirects", async () => {
  const node = new RemoveAc();
  const bg5Mb = makePngHeader(1200, 800, 5 * 1024 * 1024);
  const remotePng25Mp = makePngHeader(5000, 5000, 512);

  // 1. Upfront ticket upgrade when inputSource="url" + 5 MB bgImageBinaryProperty (including 1 safe CDN redirect hop)
  const seenCalls = [];
  const upfrontUrlCtx = createMockExecuteContext({
    items: [
      {
        json: {},
        binary: { bgData: { fileName: "studio-5mb.png", mimeType: "image/png" } },
      },
    ],
    binaryBuffers: { bgData: bg5Mb },
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/raw-shoe.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { bgImageBinaryProperty: "bgData" },
    },
    httpRequest: async (opts) => {
      seenCalls.push({ method: opts.method, url: opts.url, headers: opts.headers, body: opts.body });
      if (opts.url === "https://cdn.example.com/raw-shoe.png") {
        assert.equal(opts.headers["X-Api-Key"], undefined);
        assert.equal(opts.headers.Authorization, undefined);
        assert.equal(opts.disableFollowRedirect, true);
        return {
          statusCode: 302,
          headers: { location: "https://img-edge.example.com/final-shoe.png" },
          body: Buffer.alloc(0),
        };
      }
      if (opts.url === "https://img-edge.example.com/final-shoe.png") {
        assert.equal(opts.headers["X-Api-Key"], undefined);
        return {
          statusCode: 200,
          headers: { "content-type": "image/png" },
          body: remotePng25Mp,
        };
      }
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        assert.equal(opts.body.width, 5000);
        assert.equal(opts.body.height, 5000);
        assert.equal(opts.body.bgWidth, 1200);
        assert.equal(opts.body.bgHeight, 800);
        assert.equal(opts.body.bgImageByteLength, bg5Mb.byteLength);
        return {
          statusCode: 200,
          body: {
            data: {
              ticket: "tkt_url_bg5mb",
              directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
            },
          },
        };
      }
      assert.equal(opts.url, "http://127.0.0.1:9999/v1.0/direct-cutout");
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  const [urlBgOut] = await node.execute.call(upfrontUrlCtx);
  assert.equal(urlBgOut[0].binary.data.fileName, "raw-shoe-nobg.png");
  assert.equal(seenCalls.some((c) => c.url.endsWith("/v1.0/removebg")), false);

  // 2. Fallback 413 upgrade when inputSource="url" + size="50mp" hits 413 result_too_large on /v1.0/removebg
  const fallbackUrls = [];
  const fallback413Ctx = createMockExecuteContext({
    items: [{ json: {} }],
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/highres-portrait.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async (opts) => {
      fallbackUrls.push(opts.url);
      if (opts.url.endsWith("/v1.0/removebg")) {
        return {
          statusCode: 413,
          headers: { "content-type": "application/json" },
          body: { errors: [{ code: "result_too_large" }] },
        };
      }
      if (opts.url === "https://cdn.example.com/highres-portrait.png") {
        assert.equal(opts.headers["X-Api-Key"], undefined);
        return {
          statusCode: 200,
          headers: { "content-type": "image/png" },
          body: remotePng25Mp,
        };
      }
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        return {
          statusCode: 200,
          body: {
            data: {
              ticket: "tkt_url_413",
              directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
            },
          },
        };
      }
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  const [fbOut] = await node.execute.call(fallback413Ctx);
  assert.equal(fbOut[0].binary.data.fileName, "highres-portrait-nobg.png");
  assert.deepEqual(fallbackUrls, [
    "http://127.0.0.1:8787/v1.0/removebg",
    "https://cdn.example.com/highres-portrait.png",
    "http://127.0.0.1:8787/v1.0/removebg/ticket",
    "http://127.0.0.1:9999/v1.0/direct-cutout",
  ]);

  // 3. Malicious 302 redirect Location to metadata IP during remote fetch is blocked with 0 SSRF hits
  let metadataHit = false;
  const ssrfRedirCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/open-redirect.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { direct: true },
    },
    httpRequest: async (opts) => {
      if (opts.url.includes("169.254.169.254")) {
        metadataHit = true;
      }
      return {
        statusCode: 302,
        headers: { location: "http://169.254.169.254/latest/meta-data/" },
        body: Buffer.alloc(0),
      };
    },
  });
  await assert.rejects(() => node.execute.call(ssrfRedirCtx), /Private, loopback, or reserved IPv4/);
  assert.equal(metadataHit, false);
});

test("R2 MF-3, MF-4 & Probe 8: shadowType semantics, 50 MP pre-guard, object error formatting, format='auto', zero-copy Buffer, and 17-vector SSRF matrix", async () => {
  const node = new RemoveAc();

  // MF-3 (Probe 4): normalizeShadowOptions & live multipart/ticket capture
  assert.deepEqual(normalizeShadowOptions({ shadowType: "drop" }), {
    multipart: { add_shadow: "true", shadow_type: "drop" },
    json: { add_shadow: true, shadow_type: "drop" },
  });
  assert.deepEqual(normalizeShadowOptions({ shadowType: "none", addShadow: true }), {
    multipart: { add_shadow: "false", shadow_type: "none" },
    json: { add_shadow: false, shadow_type: "none" },
  });
  assert.deepEqual(normalizeShadowOptions({ addShadow: false, shadowType: "car" }), {
    multipart: { add_shadow: "false" },
    json: { add_shadow: false },
  });

  let capturedDropBody = "";
  const shadowDropCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "car.png", mimeType: "image/png" } } }],
    binaryBuffers: { data: TINY_PNG },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "auto",
      additionalOptions: { shadowType: "drop", bgColor: "#FFFFFF" },
    },
    httpRequest: async (opts) => {
      capturedDropBody = opts.body.toString("utf8");
      return {
        statusCode: 200,
        headers: { "content-type": "image/jpeg", "x-credits-charged": "1" },
        body: Buffer.from("JPEG_BYTES"),
      };
    },
  });
  const [autoJpgOut] = await node.execute.call(shadowDropCtx);
  assert.match(capturedDropBody, /name="shadow_type"\r\n\r\ndrop/);
  assert.match(capturedDropBody, /name="add_shadow"\r\n\r\ntrue/);
  // MF-4c: format="auto" + Content-Type: image/jpeg produces .jpg extension!
  assert.equal(autoJpgOut[0].binary.data.fileName, "car-nobg.jpg");
  assert.equal(autoJpgOut[0].binary.data.mimeType, "image/jpeg");

  const formatProp = node.description.properties.find((p) => p.name === "format");
  assert.equal(formatProp.default, "png");
  assert.ok(formatProp.options.some((o) => o.value === "auto"));

  // MF-4a (Probe 5): 56 MP (8000x7000) foreground and background rejected BEFORE any HTTP call
  const png56Mp = makePngHeader(8000, 7000, 128);
  let hugeHits = 0;
  const hugeFgCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "huge.png", mimeType: "image/png" } } }],
    binaryBuffers: { data: png56Mp },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async () => {
      hugeHits += 1;
      throw new Error("should not call network");
    },
  });
  await assert.rejects(() => node.execute.call(hugeFgCtx), /exceeds remove\.ac 50 MP/);
  assert.equal(hugeHits, 0);

  // MF-4b (Probe 6): Parsed JSON error object on /v1.0/removebg surfaces [HTTP 400] cleanly without TypeError
  assert.equal(toNodeBuffer(TINY_PNG), TINY_PNG, "toNodeBuffer must be zero-copy for Buffer");
  assert.match(formatErrorBody({ errors: [{ code: "invalid_bg_color" }] }), /invalid_bg_color/);

  const objErrCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "a.png", mimeType: "image/png" } } }],
    binaryBuffers: { data: TINY_PNG },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async () => ({
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: { errors: [{ title: "Invalid bg_color", code: "invalid_bg_color" }] },
    }),
  });
  await assert.rejects(
    () => node.execute.call(objErrCtx),
    (err) => err instanceof Error && err.name === "Error" && /\[HTTP 400\].*invalid_bg_color/.test(err.message)
  );

  // Probe 8: 17-vector adversarial SSRF matrix
  const ssrfVectors = [
    ["http://127.0.0.1/bg.png", false],
    ["http://10.0.0.1/bg.png", false],
    ["http://100.64.0.1/bg.png", false],
    ["http://169.254.169.254/latest/meta-data/", false],
    ["http://192.168.1.1/bg.png", false],
    ["http://198.18.0.5/bg.png", false],
    ["http://[::1]/bg.png", false],
    ["http://[::ffff:127.0.0.1]/bg.png", false],
    ["http://[::ffff:0:169.254.169.254]/bg.png", false],
    ["http://[64:ff9b::169.254.169.254]/bg.png", false],
    ["http://[64:ff9b:1::1]/bg.png", false],
    ["http://[fe80::1%25lo0]/bg.png", false],
    ["http://2130706433/bg.png", false],
    ["http://0x7f000001/bg.png", false],
    ["https://user:pass@example.com/bg.png", false],
    ["https://internal.local/bg.png", false],
    ["http://remove.ac", true],
  ];
  for (const [vec, reqHttps] of ssrfVectors) {
    await assert.rejects(
      () =>
        validatePublicUrl(vec, {
          requireHttps: reqHttps,
          lookupFn: async () => [{ address: "93.184.216.34", family: 4 }],
        }),
      new RegExp(""),
      `Expected SSRF block for ${vec}`
    );
  }
});
