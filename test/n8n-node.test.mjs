import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { RemoveAcApi } = require("../dist/credentials/RemoveAcApi.credentials.js");
const { RemoveAc, validatePublicUrl } = require("../dist/nodes/RemoveAc/RemoveAc.node.js");

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

test("RemoveAcApi credential exposes X-Api-Key header and /v1.0/account test check", () => {
  const cred = new RemoveAcApi();
  assert.equal(cred.name, "removeAcApi");
  assert.equal(cred.authenticate.properties.headers["X-Api-Key"], "={{$credentials.apiKey}}");
  assert.equal(cred.test.request.url, "/v1.0/account");
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

  // getAccount preserves 0 credit balance accurately
  const acctCtx = createMockExecuteContext({
    items: [{ json: {} }],
    params: { operation: "getAccount" },
    httpRequest: async (opts) => {
      assert.equal(opts.url, "http://127.0.0.1:8787/v1.0/account");
      return { data: { attributes: { credits: { total: 0 } } } };
    },
  });
  const [acctOut] = await node.execute.call(acctCtx);
  assert.equal(acctOut[0].json.totalCredits, 0);
});
