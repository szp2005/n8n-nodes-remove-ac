import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { RemoveAcApi } = require("../dist/credentials/RemoveAcApi.credentials.js");
const {
  RemoveAc,
  parseImageDimensions,
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
