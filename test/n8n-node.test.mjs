import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { RemoveAcApi } = require("../dist/credentials/RemoveAcApi.credentials.js");
const {
  MAX_COMBINED_IMAGE_BYTES,
  MAX_DIRECT_BODY_BYTES,
  PACKAGE_VERSION,
  RemoveAc,
  VALID_FORMATS,
  VALID_SIZES,
  detectImageMagic,
  fetchPinnedRemoteImageBytes,
  formatErrorBody,
  isAllowedDirectEndpointHost,
  normalizeShadowOptions,
  parseForegroundMetadata,
  parseImageDimensions,
  requestPinnedRemoteHop,
  resolveValidatedPublicUrl,
  toNodeBuffer,
  validateDirectEndpointUrl,
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
  useRealPinnedRemoteFetch = false,
  remoteFetchTimeoutMsForTest,
}) {
  return {
    _allowLoopbackBaseUrlForTest: allowLoopbackBaseUrlForTest,
    _dnsLookupForTest: dnsLookupForTest,
    _remoteHttpTransportForTest: useRealPinnedRemoteFetch ? undefined : httpRequest,
    _remoteFetchTimeoutMsForTest: remoteFetchTimeoutMsForTest,
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
  await assert.rejects(() => node.execute.call(combinedCtx), /29\.5 MB combined image limit/);
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

test("M-P1-11 (P1-05): releases ticket credit holds on ALL non-2xx directEndpoint errors (401/403/408/415/422/429/500) & network errors without masking original error", async () => {
  const node = new RemoveAc();
  const png9Mp = makePngHeader(3000, 3000, 64);

  for (const statusCode of [401, 403, 408, 415, 422, 429, 500]) {
    let releaseCalls = 0;
    let releasePayload = null;
    const ctx = createMockExecuteContext({
      items: [{ json: {}, binary: { data: { fileName: "shot.png", mimeType: "image/png" } } }],
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
      httpRequest: async (opts) => {
        if (opts.url.endsWith("/v1.0/removebg/ticket")) {
          return {
            statusCode: 200,
            body: {
              data: {
                ticket: `tkt_${statusCode}`,
                directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
                holdId: `hold_${statusCode}`,
                releaseToken: `rel_${statusCode}`,
              },
            },
          };
        }
        if (opts.url.endsWith("/v1.0/removebg/ticket/release")) {
          releaseCalls += 1;
          releasePayload = opts.body;
          assert.equal(opts.headers["X-Api-Key"], "rac_live_n8n_key");
          return { statusCode: 200, body: { ok: true } };
        }
        return {
          statusCode,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ errors: [{ code: `err_${statusCode}` }] })),
        };
      },
    });

    await assert.rejects(
      () => node.execute.call(ctx),
      new RegExp(`\\[HTTP ${statusCode}\\].*err_${statusCode}`),
      `Expected HTTP ${statusCode} error to surface`
    );
    assert.equal(releaseCalls, 1, `Expected releaseTicketHold() on HTTP ${statusCode}`);
    assert.deepEqual(releasePayload, {
      holdId: `hold_${statusCode}`,
      releaseToken: `rel_${statusCode}`,
    });
  }

  // 409 Conflict or thrown error during releaseTicketHold() must NEVER mask original directEndpoint error
  for (const releaseOutcome of ["409", "throw"]) {
    let releaseAttempted = 0;
    const ctx = createMockExecuteContext({
      items: [{ json: {}, binary: { data: { fileName: "shot.png", mimeType: "image/png" } } }],
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
      httpRequest: async (opts) => {
        if (opts.url.endsWith("/v1.0/removebg/ticket")) {
          return {
            statusCode: 200,
            body: {
              data: {
                ticket: "tkt_500",
                directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
                holdId: "hold_500",
                releaseToken: "rel_500",
              },
            },
          };
        }
        if (opts.url.endsWith("/v1.0/removebg/ticket/release")) {
          releaseAttempted += 1;
          if (releaseOutcome === "throw") {
            throw new Error("release network hiccup");
          }
          return { statusCode: 409, body: { errors: [{ code: "already_captured" }] } };
        }
        return {
          statusCode: 500,
          headers: { "content-type": "text/plain" },
          body: Buffer.from("upstream failure"),
        };
      },
    });

    await assert.rejects(() => node.execute.call(ctx), /\[HTTP 500\] upstream failure/);
    assert.equal(releaseAttempted, 1);
  }

  // Thrown network/timeout error on directEndpoint releases hold and rethrows original error
  let netReleaseCalls = 0;
  const netErrCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "shot.png", mimeType: "image/png" } } }],
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
    httpRequest: async (opts) => {
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        return {
          statusCode: 200,
          body: {
            data: {
              ticket: "tkt_timeout",
              directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
              holdId: "hold_timeout",
              releaseToken: "rel_timeout",
            },
          },
        };
      }
      if (opts.url.endsWith("/v1.0/removebg/ticket/release")) {
        netReleaseCalls += 1;
        return { statusCode: 200, body: { ok: true } };
      }
      throw new Error("ETIMEDOUT direct upload");
    },
  });
  await assert.rejects(() => node.execute.call(netErrCtx), /ETIMEDOUT direct upload/);
  assert.equal(netReleaseCalls, 1);
});

test("M-P1-08 (P1-02): enforces strict directEndpoint host allowlist (rejects evil.com & *.modal.run) and hardens fetchRemoteImageBytes", async () => {
  const node = new RemoveAc();
  const png9Mp = makePngHeader(3000, 3000, 64);
  const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const tunFakeIpLookup = async () => [{ address: "198.18.0.12", family: 4 }];

  // 1. Host allowlist helper & validateDirectEndpointUrl unit checks
  assert.equal(isAllowedDirectEndpointHost("remove.ac", "remove.ac"), true);
  assert.equal(isAllowedDirectEndpointHost("api.remove.ac", "remove.ac"), true);
  assert.equal(isAllowedDirectEndpointHost("direct.edge.remove.ac", "remove.ac"), true);
  assert.equal(isAllowedDirectEndpointHost("staging.example.com", "staging.example.com"), true);
  assert.equal(isAllowedDirectEndpointHost("127.0.0.1", "127.0.0.1"), true);
  assert.equal(isAllowedDirectEndpointHost("evil.com", "remove.ac"), false);
  assert.equal(isAllowedDirectEndpointHost("evil.modal.run", "remove.ac"), false);
  assert.equal(isAllowedDirectEndpointHost("remove-ac.modal.run", "remove.ac"), false);
  assert.equal(isAllowedDirectEndpointHost("notremove.ac", "remove.ac"), false);
  assert.equal(isAllowedDirectEndpointHost("remove.ac.evil.com", "remove.ac"), false);
  assert.equal(isAllowedDirectEndpointHost(".remove.ac", "remove.ac"), false);

  // Rejects evil.com & evil.modal.run WITHOUT performing DNS lookup
  let untrustedDnsQueries = 0;
  for (const badEndpoint of [
    "https://evil.com/v1.0/direct-cutout",
    "https://evil.modal.run/v1.0/direct-cutout",
    "https://remove-ac.modal.run/v1.0/direct-cutout",
    "https://remove.ac.evil.com/v1.0/direct-cutout",
    "https://user:pass@api.remove.ac/v1.0/direct-cutout",
    "http://api.remove.ac/v1.0/direct-cutout",
  ]) {
    await assert.rejects(
      () =>
        validateDirectEndpointUrl(badEndpoint, {
          baseUrl: "https://remove.ac",
          allowLoopback: false,
          lookupFn: async () => {
            untrustedDnsQueries += 1;
            return [{ address: "93.184.216.34", family: 4 }];
          },
        }),
      /Untrusted directEndpoint host|embedded credentials|must use https:\/\//
    );
  }
  assert.equal(untrustedDnsQueries, 0, "Disallowed directEndpoint hosts must fail before DNS lookup");

  // Allows first-party https://*.remove.ac with TUN fake-IP 198.18.0.0/15, while keeping third-party & http:// blocked
  const allowedFirstParty = await validateDirectEndpointUrl("https://api.remove.ac/v1.0/direct-cutout", {
    baseUrl: "https://remove.ac",
    allowLoopback: false,
    lookupFn: tunFakeIpLookup,
  });
  assert.equal(allowedFirstParty.hostname, "api.remove.ac");

  await assert.rejects(
    () => validatePublicUrl("https://cdn.example.com/a.png", { lookupFn: tunFakeIpLookup }),
    /private IPv4 address/
  );
  await assert.rejects(
    () => validatePublicUrl("http://remove.ac/a.png", { lookupFn: tunFakeIpLookup }),
    /private IPv4 address/
  );

  // End-to-end: ticket returning evil.com or evil.modal.run is rejected with 0 hits to evil host AND releases hold
  for (const evilEndpoint of [
    "https://evil.com/v1.0/direct-cutout",
    "https://evil.modal.run/v1.0/direct-cutout",
  ]) {
    let evilHits = 0;
    let releaseHits = 0;
    const ctx = createMockExecuteContext({
      items: [{ json: {}, binary: { data: { fileName: "big.png", mimeType: "image/png" } } }],
      credentials: { apiKey: "rac_live_n8n_key", baseUrl: "https://remove.ac" },
      allowLoopbackBaseUrlForTest: false,
      dnsLookupForTest: publicLookup,
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
      httpRequest: async (opts) => {
        if (opts.url === "https://remove.ac/v1.0/removebg/ticket") {
          return {
            statusCode: 200,
            body: {
              data: {
                ticket: "tkt_evil",
                directEndpoint: evilEndpoint,
                holdId: "hold_evil",
                releaseToken: "rel_evil",
              },
            },
          };
        }
        if (opts.url === "https://remove.ac/v1.0/removebg/ticket/release") {
          releaseHits += 1;
          return { statusCode: 200, body: { ok: true } };
        }
        evilHits += 1;
        throw new Error("evil directEndpoint must never be called");
      },
    });
    await assert.rejects(() => node.execute.call(ctx), /Untrusted directEndpoint host/);
    assert.equal(evilHits, 0);
    assert.equal(releaseHits, 1);
  }

  // 2. detectImageMagic validates PNG/JPEG/WebP/GIF and rejects non-image payloads
  assert.equal(detectImageMagic(TINY_PNG), "image/png");
  assert.equal(detectImageMagic(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10])), "image/jpeg");
  assert.equal(
    detectImageMagic(Buffer.from("RIFF\x24\x00\x00\x00WEBPVP8 ", "latin1")),
    "image/webp"
  );
  assert.equal(detectImageMagic(Buffer.from("GIF87a\x01\x00\x01\x00", "latin1")), "image/gif");
  assert.equal(detectImageMagic(Buffer.from("GIF89a\x01\x00\x01\x00", "latin1")), "image/gif");
  assert.equal(detectImageMagic(Buffer.from("<html><body>secret</body></html>")), null);
  assert.equal(detectImageMagic(Buffer.from('{"secret":"token"}')), null);
  assert.equal(detectImageMagic(Buffer.from("<svg xmlns='http://www.w3.org/2000/svg'/>")), null);
  assert.equal(detectImageMagic(Buffer.from("RIFF\x24\x00\x00\x00WAVEfmt ", "latin1")), null);

  // 3. fetchRemoteImageBytes NEVER echoes raw third-party/internal HTTP error bodies
  const leakSecret = "INTERNAL_AWS_METADATA_SECRET_TOKEN_XYZ987";
  const errFetchCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/private.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { direct: true },
    },
    httpRequest: async () => ({
      statusCode: 403,
      headers: { "content-type": "text/plain" },
      body: Buffer.from(leakSecret),
    }),
  });
  await assert.rejects(
    () => node.execute.call(errFetchCtx),
    (err) => {
      assert.equal(err.message, "Failed to fetch remote image [HTTP 403]");
      assert.equal(err.message.includes(leakSecret), false);
      return true;
    }
  );

  // 4. fetchRemoteImageBytes rejects non-image payloads (even with spoofed Content-Type: image/png) BEFORE ticket call
  let ticketReached = false;
  const badMagicCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/not-an-image.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { direct: true },
    },
    httpRequest: async (opts) => {
      if (opts.url.includes("/v1.0/")) {
        ticketReached = true;
      }
      return {
        statusCode: 200,
        headers: { "content-type": "image/png" },
        body: Buffer.from("<html><body>Not actually a PNG</body></html>"),
      };
    },
  });
  await assert.rejects(
    () => node.execute.call(badMagicCtx),
    /did not return a valid PNG, JPEG, WebP, or GIF image/
  );
  assert.equal(ticketReached, false);

  // 5. fetchRemoteImageBytes rejects >25 MB remote images BEFORE ticket call
  const oversizedPng = makePngHeader(1000, 1000, 25 * 1024 * 1024 + 1);
  let oversizedTicketReached = false;
  const oversizedCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: {
      operation: "removeBackground",
      inputSource: "url",
      imageUrl: "https://cdn.example.com/huge-26mb.png",
      outputBinaryPropertyName: "data",
      size: "50mp",
      format: "png",
      additionalOptions: { direct: true },
    },
    httpRequest: async (opts) => {
      if (opts.url.includes("/v1.0/")) oversizedTicketReached = true;
      return {
        statusCode: 200,
        headers: { "content-type": "image/png" },
        body: oversizedPng,
      };
    },
  });
  await assert.rejects(() => node.execute.call(oversizedCtx), /exceeds remove\.ac 25 MB limit/);
  assert.equal(oversizedTicketReached, false);
});

test("M-P1-10 (P1-04): parses X-Foreground-* headers case-insensitively and returns null (never misleading 0x0) when omitted", async () => {
  const node = new RemoveAc();

  // 1. Unit checks for parseForegroundMetadata: mixed-case plain object, Web Headers, explicit 0, omitted, invalid
  assert.deepEqual(
    parseForegroundMetadata({
      "X-Foreground-Top": "12",
      "X-FOREGROUND-LEFT": "34",
      "x-foreground-width": "500",
      "X-Foreground-Height": "400",
    }),
    {
      foregroundTop: 12,
      foregroundLeft: 34,
      foregroundWidth: 500,
      foregroundHeight: 400,
    }
  );

  assert.deepEqual(
    parseForegroundMetadata(
      new Headers({
        "X-Foreground-Top": "0",
        "X-Foreground-Left": "0",
        "X-Foreground-Width": "800",
        "X-Foreground-Height": "600",
      })
    ),
    {
      foregroundTop: 0,
      foregroundLeft: 0,
      foregroundWidth: 800,
      foregroundHeight: 600,
    }
  );

  assert.deepEqual(parseForegroundMetadata({}), {
    foregroundTop: null,
    foregroundLeft: null,
    foregroundWidth: null,
    foregroundHeight: null,
  });

  assert.deepEqual(
    parseForegroundMetadata({
      "X-Foreground-Top": "",
      "X-Foreground-Left": "-5",
      "X-Foreground-Width": "NaN",
      "X-Foreground-Height": "120px",
    }),
    {
      foregroundTop: null,
      foregroundLeft: null,
      foregroundWidth: null,
      foregroundHeight: null,
    }
  );

  // 2. End-to-end execution when X-Foreground-* headers are omitted (e.g. direct-cutout stream without bbox headers)
  const omittedCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "item.png", mimeType: "image/png" } } }],
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
      statusCode: 200,
      headers: {
        "Content-Type": "image/png",
        "X-Credits-Charged": "1",
      },
      body: makePngHeader(1200, 900, 64),
    }),
  });
  const [omittedOut] = await node.execute.call(omittedCtx);
  assert.equal(omittedOut[0].json.removeAc.width, 1200);
  assert.equal(omittedOut[0].json.removeAc.height, 900);
  assert.equal(omittedOut[0].json.removeAc.foregroundTop, null);
  assert.equal(omittedOut[0].json.removeAc.foregroundLeft, null);
  assert.equal(omittedOut[0].json.removeAc.foregroundWidth, null);
  assert.equal(omittedOut[0].json.removeAc.foregroundHeight, null);

  // 3. End-to-end execution with mixed-case X-Foreground-* headers (including valid 0 top/left)
  const presentCtx = createMockExecuteContext({
    items: [{ json: {}, binary: { data: { fileName: "crop.png", mimeType: "image/png" } } }],
    binaryBuffers: { data: TINY_PNG },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: { crop: true },
    },
    httpRequest: async () => ({
      statusCode: 200,
      headers: {
        "Content-Type": "image/png",
        "X-Credits-Charged": "1",
        "X-Width": "640",
        "X-Height": "480",
        "X-Foreground-Top": "0",
        "X-Foreground-Left": "0",
        "X-Foreground-Width": "640",
        "X-Foreground-Height": "480",
      },
      body: TINY_PNG,
    }),
  });
  const [presentOut] = await node.execute.call(presentCtx);
  assert.equal(presentOut[0].json.removeAc.foregroundTop, 0);
  assert.equal(presentOut[0].json.removeAc.foregroundLeft, 0);
  assert.equal(presentOut[0].json.removeAc.foregroundWidth, 640);
  assert.equal(presentOut[0].json.removeAc.foregroundHeight, 480);
});

test("M-P2-15 (P2-04): usableAsTool auto-falls back to URL mode when inputSource='binary' has no binary property", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const node = new RemoveAc();
  assert.equal(node.description.usableAsTool, true);

  // 1. Default inputSource="binary", no binary attachment, imageUrl parameter supplied -> auto-switches to URL mode
  let paramBodyStr = "";
  const paramUrlCtx = createMockExecuteContext({
    items: [{ json: { toolCallId: "call_1" } }],
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      imageUrl: "https://cdn.example.com/agent-sneaker.jpg",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async (opts) => {
      paramBodyStr = opts.body.toString("utf8");
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  const [paramOut] = await node.execute.call(paramUrlCtx);
  assert.match(paramBodyStr, /name="image_url"\r\n\r\nhttps:\/\/cdn\.example\.com\/agent-sneaker\.jpg/);
  assert.equal(paramOut[0].binary.data.fileName, "agent-sneaker-nobg.png");

  // 2. Default inputSource="binary", no binary attachment, items[i].json.imageUrl (and image_url) supplied -> auto-switches to URL mode
  for (const jsonPayload of [
    { imageUrl: "https://cdn.example.com/from-json.png" },
    { image_url: "https://cdn.example.com/from-snake.webp" },
  ]) {
    let seenBody = "";
    const jsonUrlCtx = createMockExecuteContext({
      items: [{ json: jsonPayload }],
      params: {
        operation: "removeBackground",
        inputSource: "binary",
      },
      httpRequest: async (opts) => {
        seenBody = opts.body.toString("utf8");
        return {
          statusCode: 200,
          headers: { "content-type": "image/png", "x-credits-charged": "1" },
          body: TINY_PNG,
        };
      },
    });
    const [jsonOut] = await node.execute.call(jsonUrlCtx);
    const expectedUrl = jsonPayload.imageUrl || jsonPayload.image_url;
    assert.ok(seenBody.includes(expectedUrl));
    assert.ok(jsonOut[0].binary.data.fileName.endsWith("-nobg.png"));
  }

  // 3. Fallback json.imageUrl pointing to private IP is STILL blocked by SSRF check with 0 HTTP calls
  let ssrfHits = 0;
  const ssrfJsonCtx = createMockExecuteContext({
    items: [{ json: { imageUrl: "http://169.254.169.254/latest/meta-data/" } }],
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async () => {
      ssrfHits += 1;
      throw new Error("should not reach network");
    },
  });
  await assert.rejects(() => node.execute.call(ssrfJsonCtx), /Private, loopback, or reserved IPv4/);
  assert.equal(ssrfHits, 0);

  // 4. When binary property IS present AND json.imageUrl also exists, binary takes precedence
  let binPrecedenceBody = "";
  const binPrecedenceCtx = createMockExecuteContext({
    items: [
      {
        json: { imageUrl: "https://cdn.example.com/should-be-ignored.png" },
        binary: { data: { fileName: "local-upload.png", mimeType: "image/png" } },
      },
    ],
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
      binPrecedenceBody = opts.body.toString("utf8");
      return {
        statusCode: 200,
        headers: { "content-type": "image/png", "x-credits-charged": "1" },
        body: TINY_PNG,
      };
    },
  });
  const [binOut] = await node.execute.call(binPrecedenceCtx);
  assert.match(binPrecedenceBody, /name="image_file"; filename="local-upload\.png"/);
  assert.equal(binPrecedenceBody.includes("should-be-ignored.png"), false);
  assert.equal(binOut[0].binary.data.fileName, "local-upload-nobg.png");

  // 5. Missing binary property with NO fallback URL still fails cleanly via assertBinaryData
  const missingBothCtx = createMockExecuteContext({
    items: [{ json: { note: "no image here" } }],
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "full",
      format: "png",
      additionalOptions: {},
    },
    httpRequest: async () => {
      throw new Error("should not reach network");
    },
  });
  await assert.rejects(() => node.execute.call(missingBothCtx), /Missing binary property data/);

  // 6. README documents setting Input Source = Image URL when attaching as an AI Agent tool
  const readmePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "README.md");
  const readme = fs.readFileSync(readmePath, "utf8");
  assert.match(readme, /Input Source = Image URL/);
});

test("SEC-02 (v1.0.3): closes TOCTOU DNS-rebinding SSRF via zero-dep node:http/https custom lookup IP pinning", async () => {
  const dns = await import("node:dns");
  const http = await import("node:http");
  const https = await import("node:https");
  const { PassThrough } = await import("node:stream");
  const node = new RemoveAc();

  // 1. resolveValidatedPublicUrl unwraps public ::ffff:x.x.x.x to IPv4 and blocks private/metadata/198.18/trailing-dot/octal/6to4
  const mappedPublic = await resolveValidatedPublicUrl("https://cdn.example.com/item.png", {
    allowTunFakeIp: false,
    lookupFn: async () => [{ address: "::ffff:93.184.216.34", family: 6 }],
  });
  assert.deepEqual(mappedPublic.addresses, [{ address: "93.184.216.34", family: 4 }]);

  for (const badHostUrl of [
    "http://localhost./secret.png",
    "http://metadata.internal./secret.png",
    "http://0177.0.0.1/secret.png",
    "http://127.1/secret.png",
    "http://[2002:7f00:0001::1]/secret.png",
    "http://[2002:a9fe:a9fe::1]/secret.png",
  ]) {
    await assert.rejects(
      () =>
        resolveValidatedPublicUrl(badHostUrl, {
          allowTunFakeIp: false,
          lookupFn: async () => [{ address: "93.184.216.34", family: 4 }],
        }),
      /not permitted|Private, loopback/i,
      `Expected rejection for ${badHostUrl}`
    );
  }

  for (const badResolvedRecord of [
    [{ address: "::ffff:169.254.169.254", family: 6 }],
    [{ address: "::ffff:127.0.0.1", family: 6 }],
    [{ address: "::ffff:198.18.0.12", family: 6 }],
    [{ address: "198.18.0.12", family: 4 }],
    [{ address: "100.64.0.10", family: 4 }],
    [{ address: "10.0.0.5", family: 4 }],
  ]) {
    await assert.rejects(
      () =>
        resolveValidatedPublicUrl("https://remove.ac/untrusted-remote-image.png", {
          allowTunFakeIp: false,
          lookupFn: async () => badResolvedRecord,
        }),
      /private IPv[46] address/i
    );
  }

  // 2. Real loopback TCP server: requestPinnedRemoteHop pins custom lookup IP with ZERO OS dns.lookup calls,
  //    preserves Host header, hides 5xx body, enforces streaming maxBytes, and enforces hard timeout
  const seenRemoteHeaders = [];
  const srv = http.createServer((req, res) => {
    seenRemoteHeaders.push({ url: req.url, headers: { ...req.headers } });
    if (req.url === "/pinned.png") {
      res.writeHead(200, { "Content-Type": "image/png" });
      res.end(TINY_PNG);
      return;
    }
    if (req.url === "/hop1.png") {
      res.writeHead(302, { Location: "/pinned.png" });
      res.end();
      return;
    }
    if (req.url === "/err500") {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("SUPER_SECRET_ORIGIN_STACKTRACE");
      return;
    }
    if (req.url === "/chunked-oversize") {
      res.writeHead(200, { "Content-Type": "image/png" });
      res.write(Buffer.alloc(1024, 0x41));
      res.end(Buffer.alloc(1024, 0x42));
      return;
    }
    if (req.url === "/hang") {
      // Intentionally never respond to verify hard timeout
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const srvPort = srv.address().port;

  const origDnsLookup = dns.default.lookup;
  dns.default.lookup = () => {
    throw new Error("OS dns.lookup MUST NOT be invoked by requestPinnedRemoteHop");
  };
  try {
    const hopRes = await requestPinnedRemoteHop(
      new URL(`http://rebind-proof.example:${srvPort}/pinned.png`),
      [{ address: "127.0.0.1", family: 4 }],
      { maxBytes: 4096, timeoutMs: 3000 }
    );
    assert.equal(hopRes.statusCode, 200);
    assert.deepEqual(hopRes.body, TINY_PNG);
    assert.equal(seenRemoteHeaders[0].headers.host, `rebind-proof.example:${srvPort}`);
    assert.equal(seenRemoteHeaders[0].headers["user-agent"], `n8n-nodes-remove-ac/${PACKAGE_VERSION}`);
    assert.equal(seenRemoteHeaders[0].headers["x-api-key"], undefined);
    assert.equal(seenRemoteHeaders[0].headers.authorization, undefined);

    await assert.rejects(
      () =>
        requestPinnedRemoteHop(
          new URL(`http://rebind-proof.example:${srvPort}/err500`),
          [{ address: "127.0.0.1", family: 4 }],
          { maxBytes: 4096, timeoutMs: 3000 }
        ),
      (err) =>
        err.message === "Failed to fetch remote image [HTTP 500]" &&
        !err.message.includes("SUPER_SECRET_ORIGIN_STACKTRACE")
    );

    await assert.rejects(
      () =>
        requestPinnedRemoteHop(
          new URL(`http://rebind-proof.example:${srvPort}/chunked-oversize`),
          [{ address: "127.0.0.1", family: 4 }],
          { maxBytes: 1500, timeoutMs: 3000 }
        ),
      /exceeds remove\.ac 25 MB limit/
    );

    await assert.rejects(
      () =>
        requestPinnedRemoteHop(
          new URL(`http://rebind-proof.example:${srvPort}/hang`),
          [{ address: "127.0.0.1", family: 4 }],
          { maxBytes: 4096, timeoutMs: 80 }
        ),
      /Timed out fetching remote image/
    );
  } finally {
    dns.default.lookup = origDnsLookup;
    srv.close();
  }

  // 3. Production path (useRealPinnedRemoteFetch: true, _remoteHttpTransportForTest === undefined):
  //    Verify single-resolution DNS pinning defeats TTL=0 TOCTOU DNS rebinding (93.184.216.34 -> 169.254.169.254),
  //    preserves TLS SNI servername, NEVER calls helpers.httpRequest for remote image URLs, and blocks private redirect hops!
  let rebindLookupCount = 0;
  const statefulRebindLookup = async (host) => {
    if (host === "ttl0-rebind.example.com") {
      rebindLookupCount += 1;
      if (rebindLookupCount === 1) {
        return [{ address: "::ffff:93.184.216.34", family: 6 }];
      }
      // Attacker flips DNS to cloud metadata on 2nd lookup!
      return [{ address: "169.254.169.254", family: 4 }];
    }
    if (host === "cdn-hop2.example.com") {
      return [{ address: "198.51.100.99", family: 4 }]; // TEST-NET-2 reserved -> must be blocked!
    }
    if (host === "safe-hop2.example.com") {
      return [{ address: "104.21.2.2", family: 4 }];
    }
    return [{ address: "93.184.216.34", family: 4 }];
  };

  const capturedHttpsReqs = [];
  const origHttpsRequest = https.default.request;
  https.default.request = (options, cb) => {
    const pinnedFromLookup = [];
    options.lookup(options.hostname, { all: true }, (_err, addrs) => {
      pinnedFromLookup.push(...addrs);
    });
    let singleAddr = null;
    options.lookup(options.hostname, { family: 4 }, (_err, addr, fam) => {
      singleAddr = { address: addr, family: fam };
    });
    capturedHttpsReqs.push({
      hostname: options.hostname,
      servername: options.servername,
      agent: options.agent,
      headers: options.headers,
      pinnedFromLookup,
      singleAddr,
      path: options.path,
    });

    const reqStream = new PassThrough();
    reqStream.destroy = () => {};
    process.nextTick(() => {
      const resStream = new PassThrough();
      resStream.destroy = () => {};
      if (options.hostname === "ttl0-rebind.example.com" && options.path === "/redir-safe.png") {
        resStream.statusCode = 302;
        resStream.headers = { location: "https://safe-hop2.example.com/final.png" };
        cb(resStream);
        resStream.end();
        return;
      }
      if (options.hostname === "ttl0-rebind.example.com" && options.path === "/redir-evil.png") {
        resStream.statusCode = 302;
        resStream.headers = { location: "https://cdn-hop2.example.com/evil.png" };
        cb(resStream);
        resStream.end();
        return;
      }
      resStream.statusCode = 200;
      resStream.headers = { "content-type": "image/png" };
      cb(resStream);
      resStream.end(makePngHeader(3000, 3000, 128));
    });
    return reqStream;
  };

  try {
    const prodCtx = createMockExecuteContext({
      items: [{ json: {} }],
      useRealPinnedRemoteFetch: true,
      dnsLookupForTest: statefulRebindLookup,
      params: {
        operation: "removeBackground",
        inputSource: "url",
        imageUrl: "https://ttl0-rebind.example.com/redir-safe.png",
        outputBinaryPropertyName: "data",
        size: "maximum",
        format: "png",
        additionalOptions: { direct: true },
      },
      httpRequest: async (opts) => {
        // helpers.httpRequest MUST NEVER receive remote image host URLs!
        assert.equal(opts.url.includes("example.com"), false, `Unexpected httpRequest to ${opts.url}`);
        if (opts.url.endsWith("/v1.0/removebg/ticket")) {
          return {
            statusCode: 200,
            body: {
              data: {
                ticket: "tkt_sec02",
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

    const [prodOut] = await node.execute.call(prodCtx);
    assert.equal(prodOut[0].binary.data.fileName, "redir-safe-nobg.png");
    assert.equal(rebindLookupCount, 1, "Initial hostname DNS must be resolved strictly ONCE (zero TOCTOU re-lookup)");
    assert.equal(capturedHttpsReqs.length, 2);
    // Hop 0 pinned unwrapped 93.184.216.34 (NEVER 169.254.169.254) with TLS SNI servername preserved & agent:false
    assert.equal(capturedHttpsReqs[0].hostname, "ttl0-rebind.example.com");
    assert.equal(capturedHttpsReqs[0].servername, "ttl0-rebind.example.com");
    assert.equal(capturedHttpsReqs[0].agent, false);
    assert.deepEqual(capturedHttpsReqs[0].pinnedFromLookup, [{ address: "93.184.216.34", family: 4 }]);
    assert.deepEqual(capturedHttpsReqs[0].singleAddr, { address: "93.184.216.34", family: 4 });
    // Hop 1 re-validated DNS and pinned safe-hop2's 104.21.2.2 with TLS SNI preserved
    assert.equal(capturedHttpsReqs[1].hostname, "safe-hop2.example.com");
    assert.equal(capturedHttpsReqs[1].servername, "safe-hop2.example.com");
    assert.deepEqual(capturedHttpsReqs[1].singleAddr, { address: "104.21.2.2", family: 4 });

    // Redirect hop resolving to disallowed IP (198.51.100.99) is blocked BEFORE opening hop-2 socket!
    rebindLookupCount = 0;
    capturedHttpsReqs.length = 0;
    await assert.rejects(
      () =>
        fetchPinnedRemoteImageBytes("https://ttl0-rebind.example.com/redir-evil.png", {
          lookupFn: statefulRebindLookup,
        }),
      /private IPv4 address/i
    );
    assert.equal(capturedHttpsReqs.length, 1, "Disallowed redirect hop must open 0 sockets to hop-2");
  } finally {
    https.default.request = origHttpsRequest;
  }
});

test("ENG-02 (v1.0.3): supports size='maximum', format='jpeg', runtime enum guards, and exact 29.5 MiB / 30 MiB combined envelope", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  assert.equal(pkg.version, "1.0.3");
  assert.equal(PACKAGE_VERSION, "1.0.3");
  assert.equal(pkg.dependencies, undefined);

  assert.equal(MAX_COMBINED_IMAGE_BYTES, 30_932_992);
  assert.equal(MAX_DIRECT_BODY_BYTES, 30 * 1024 * 1024);
  assert.ok(VALID_SIZES.includes("maximum"));
  assert.ok(VALID_FORMATS.includes("jpeg"));

  const node = new RemoveAc();
  const sizeOptions = node.description.properties.find((p) => p.name === "size").options.map((o) => o.value);
  const formatOptions = node.description.properties.find((p) => p.name === "format").options.map((o) => o.value);
  assert.ok(sizeOptions.includes("maximum"));
  assert.ok(formatOptions.includes("jpeg"));

  // 1. Exact 29.5 MiB (15 MiB fg + 14.5 MiB bg = 30,932,992 B) with size="maximum" & format="jpeg" passes precheck and fits < 30 MiB
  const fg15 = makePngHeader(2000, 2000, 15 * 1024 * 1024);
  const bg14_5 = makePngHeader(2000, 2000, 14.5 * 1024 * 1024);
  const bgOverBy1 = makePngHeader(2000, 2000, 14.5 * 1024 * 1024 + 1);

  let seenTicketBody = null;
  let seenMultipartLen = 0;
  const okCtx = createMockExecuteContext({
    items: [
      {
        json: {},
        binary: {
          data: { fileName: "hero.png", mimeType: "image/png" },
          bg: { fileName: "backdrop.png", mimeType: "image/png" },
        },
      },
    ],
    binaryBuffers: { data: fg15, bg: bg14_5 },
    params: {
      operation: "removeBackground",
      inputSource: "binary",
      binaryPropertyName: "data",
      outputBinaryPropertyName: "data",
      size: "maximum",
      format: "jpeg",
      additionalOptions: { bgImageBinaryProperty: "bg" },
    },
    httpRequest: async (opts) => {
      if (opts.url.endsWith("/v1.0/removebg/ticket")) {
        seenTicketBody = opts.body;
        return {
          statusCode: 200,
          body: {
            data: {
              ticket: "tkt_295",
              directEndpoint: "http://127.0.0.1:9999/v1.0/direct-cutout",
            },
          },
        };
      }
      seenMultipartLen = opts.body.byteLength;
      return {
        statusCode: 200,
        headers: { "content-type": "image/jpeg", "x-credits-charged": "1" },
        body: Buffer.from([0xff, 0xd8, 0xff, 0xd9]),
      };
    },
  });
  const [okOut] = await node.execute.call(okCtx);
  assert.equal(seenTicketBody.size, "maximum");
  assert.equal(seenTicketBody.format, "jpeg");
  assert.ok(seenMultipartLen > MAX_COMBINED_IMAGE_BYTES && seenMultipartLen < MAX_DIRECT_BODY_BYTES);
  assert.equal(okOut[0].binary.data.fileName, "hero-nobg.jpg");
  assert.equal(okOut[0].binary.data.mimeType, "image/jpeg");

  // 2. 29.5 MiB + 1 B (30,932,993 B) and invalid size/format fail BEFORE any network call (0 HTTP calls)
  let badHttpHits = 0;
  for (const badCase of [
    {
      bins: { data: fg15, bg: bgOverBy1 },
      params: {
        operation: "removeBackground",
        inputSource: "binary",
        binaryPropertyName: "data",
        outputBinaryPropertyName: "data",
        size: "maximum",
        format: "jpeg",
        additionalOptions: { bgImageBinaryProperty: "bg" },
      },
      pattern: /29\.5 MB combined image limit/,
    },
    {
      bins: { data: TINY_PNG, bg: TINY_PNG },
      params: { operation: "removeBackground", inputSource: "binary", size: "999mp", format: "png" },
      pattern: /Unsupported size/,
    },
    {
      bins: { data: TINY_PNG, bg: TINY_PNG },
      params: { operation: "removeBackground", inputSource: "binary", size: "maximum", format: "bmp" },
      pattern: /Unsupported format/,
    },
  ]) {
    const badCtx = createMockExecuteContext({
      items: [
        {
          json: {},
          binary: {
            data: { fileName: "a.png", mimeType: "image/png" },
            bg: { fileName: "b.png", mimeType: "image/png" },
          },
        },
      ],
      binaryBuffers: badCase.bins,
      params: badCase.params,
      httpRequest: async () => {
        badHttpHits += 1;
        throw new Error("should not touch network");
      },
    });
    await assert.rejects(() => node.execute.call(badCtx), badCase.pattern);
  }
  assert.equal(badHttpHits, 0);
});
