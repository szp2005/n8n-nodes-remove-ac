"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RemoveAc =
  exports.validatePublicUrl =
  exports.isPrivateIpv6 =
  exports.isPrivateIpv4 =
  exports.parseImageDimensions =
    void 0;

const crypto = require("node:crypto");
const dns = require("node:dns");
const net = require("node:net");

const DEFAULT_BASE_URL = "https://remove.ac";
const DIRECT_THRESHOLD_BYTES = 4 * 1024 * 1024;
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const DIRECT_RGBA_PNG_PIXELS = 5_000_000;
const DIRECT_CROPPED_RGBA_PNG_PIXELS = 10_000_000;

function isPrivateIpv4Octets(a, b, c) {
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIpv4(ip) {
  const parts = String(ip)
    .split(".")
    .map((s) => (/^\d{1,3}$/.test(s) ? Number.parseInt(s, 10) : Number.NaN));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  return isPrivateIpv4Octets(parts[0], parts[1], parts[2]);
}
exports.isPrivateIpv4 = isPrivateIpv4;

function isPrivateIpv4Words(hi16, lo16) {
  return isPrivateIpv4Octets((hi16 >>> 8) & 0xff, hi16 & 0xff, (lo16 >>> 8) & 0xff);
}

function parseIpv6Words(rawIp) {
  let clean = String(rawIp).trim().toLowerCase().replace(/^\[|\]$/g, "");
  const zoneIdx = clean.indexOf("%");
  if (zoneIdx !== -1) clean = clean.slice(0, zoneIdx);
  if (!clean || !clean.includes(":")) return null;

  const lastColon = clean.lastIndexOf(":");
  const tail = clean.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = tail
      .split(".")
      .map((s) => (/^\d{1,3}$/.test(s) ? Number.parseInt(s, 10) : Number.NaN));
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return null;
    }
    const w6 = ((octets[0] << 8) | octets[1]).toString(16);
    const w7 = ((octets[2] << 8) | octets[3]).toString(16);
    clean = `${clean.slice(0, lastColon + 1)}${w6}:${w7}`;
  }

  const dblParts = clean.split("::");
  if (dblParts.length > 2) return null;

  const parseSide = (str) => {
    if (!str) return [];
    const groups = str.split(":");
    const nums = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      nums.push(Number.parseInt(g, 16));
    }
    return nums;
  };

  if (dblParts.length === 2) {
    const left = parseSide(dblParts[0]);
    const right = parseSide(dblParts[1]);
    if (!left || !right || left.length + right.length >= 8) return null;
    const zeros = new Array(8 - left.length - right.length).fill(0);
    return Uint16Array.from([...left, ...zeros, ...right]);
  }

  const full = parseSide(clean);
  if (!full || full.length !== 8) return null;
  return Uint16Array.from(full);
}

function isPrivateIpv6(ip) {
  const w = parseIpv6Words(ip);
  if (!w) return true;
  if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0) {
    if (w[6] === 0 && (w[7] === 0 || w[7] === 1)) return true;
    return isPrivateIpv4Words(w[6], w[7]);
  }
  if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff) {
    return isPrivateIpv4Words(w[6], w[7]);
  }
  if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0xffff && w[5] === 0) {
    return isPrivateIpv4Words(w[6], w[7]);
  }
  if (w[0] === 0x0064 && w[1] === 0xff9b) {
    if (w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0) {
      return isPrivateIpv4Words(w[6], w[7]);
    }
    if (w[2] === 1) return true;
  }
  if (w[0] === 0x0100 && w[1] === 0 && w[2] === 0 && w[3] === 0) return true;
  if ((w[0] & 0xfe00) === 0xfc00) return true;
  if ((w[0] & 0xffc0) === 0xfe80) return true;
  if ((w[0] & 0xffc0) === 0xfec0) return true;
  if ((w[0] & 0xff00) === 0xff00) return true;
  return false;
}
exports.isPrivateIpv6 = isPrivateIpv6;

async function validatePublicUrl(rawUrl, { requireHttps = false, lookupFn = dns.promises.lookup } = {}) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    throw new Error(`Invalid URL: '${rawUrl}'`);
  }
  if (requireHttps && parsed.protocol !== "https:") {
    throw new Error("Endpoint URL must use https://");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Only http:// and https:// URLs are supported");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not permitted");
  }
  const rawHost = parsed.hostname.toLowerCase();
  const host = rawHost.replace(/^\[|\]$/g, "");
  if (
    !host ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home.arpa")
  ) {
    throw new Error("Local or internal hostnames are not permitted");
  }
  if (rawHost.startsWith("[") || host.includes(":")) {
    if (isPrivateIpv6(host)) {
      throw new Error("Private, loopback, or reserved IPv6 addresses are not permitted");
    }
    return parsed;
  }
  if (net.isIPv4(host)) {
    if (isPrivateIpv4(host)) {
      throw new Error("Private, loopback, or reserved IPv4 addresses are not permitted");
    }
    return parsed;
  }
  if (!host.includes(".") || /^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) {
    throw new Error("Single-label or numeric hostnames are not permitted");
  }
  let records;
  try {
    records = await lookupFn(host, { all: true, verbatim: true });
  } catch {
    throw new Error(`Unable to resolve hostname '${host}'`);
  }
  const list = Array.isArray(records) ? records : records ? [records] : [];
  if (list.length === 0) {
    throw new Error(`Hostname '${host}' returned no DNS records`);
  }
  const allowTunFakeIp =
    parsed.protocol === "https:" && (host === "remove.ac" || host.endsWith(".remove.ac"));
  for (const rec of list) {
    const addr = String(rec && rec.address ? rec.address : "").trim();
    if (net.isIPv4(addr)) {
      const octs = addr.split(".").map((s) => Number.parseInt(s, 10));
      const isRfc2544 = octs.length === 4 && octs[0] === 198 && (octs[1] === 18 || octs[1] === 19);
      if (allowTunFakeIp && isRfc2544) continue;
      if (isPrivateIpv4(addr)) throw new Error(`Hostname '${host}' resolved to a private IPv4 address`);
    } else if (addr.includes(":")) {
      if (isPrivateIpv6(addr)) throw new Error(`Hostname '${host}' resolved to a private IPv6 address`);
    } else {
      throw new Error(`Hostname '${host}' resolved to an unrecognized address`);
    }
  }
  return parsed;
}
exports.validatePublicUrl = validatePublicUrl;

function parseImageDimensions(input) {
  const bytes =
    input instanceof ArrayBuffer ? new Uint8Array(input) : input instanceof Uint8Array ? input : null;
  if (!bytes || bytes.byteLength < 10) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (
    bytes.byteLength >= 24 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a &&
    bytes[12] === 0x49 &&
    bytes[13] === 0x48 &&
    bytes[14] === 0x44 &&
    bytes[15] === 0x52
  ) {
    const width = view.getUint32(16, false);
    const height = view.getUint32(20, false);
    return width > 0 && height > 0 && width <= 1_000_000 && height <= 1_000_000 ? { width, height } : null;
  }
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
    const width = view.getUint16(6, true);
    const height = view.getUint16(8, true);
    return width > 0 && height > 0 ? { width, height } : null;
  }
  if (
    bytes.byteLength >= 25 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    if (
      bytes.byteLength >= 30 &&
      bytes[12] === 0x56 &&
      bytes[13] === 0x50 &&
      bytes[14] === 0x38 &&
      bytes[15] === 0x20 &&
      bytes[23] === 0x9d &&
      bytes[24] === 0x01 &&
      bytes[25] === 0x2a
    ) {
      const width = view.getUint16(26, true) & 0x3fff;
      const height = view.getUint16(28, true) & 0x3fff;
      return width > 0 && height > 0 ? { width, height } : null;
    }
    if (bytes[12] === 0x56 && bytes[13] === 0x50 && bytes[14] === 0x38 && bytes[15] === 0x4c && bytes[20] === 0x2f) {
      const b0 = bytes[21],
        b1 = bytes[22],
        b2 = bytes[23],
        b3 = bytes[24];
      const width = 1 + (b0 | ((b1 & 0x3f) << 8));
      const height = 1 + ((b1 >> 6) | (b2 << 2) | ((b3 & 0x0f) << 10));
      return width > 0 && height > 0 ? { width, height } : null;
    }
    if (bytes.byteLength >= 30 && bytes[12] === 0x56 && bytes[13] === 0x50 && bytes[14] === 0x38 && bytes[15] === 0x58) {
      const width = 1 + (bytes[24] | (bytes[25] << 8) | (bytes[26] << 16));
      const height = 1 + (bytes[27] | (bytes[28] << 8) | (bytes[29] << 16));
      return width > 0 && height > 0 ? { width, height } : null;
    }
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    let pos = 2;
    for (let steps = 0; steps < 512 && pos + 3 < bytes.byteLength; steps++) {
      if (bytes[pos] !== 0xff) break;
      while (pos < bytes.byteLength && bytes[pos] === 0xff) pos++;
      if (pos >= bytes.byteLength) break;
      const marker = bytes[pos++];
      if (marker === 0xd9 || marker === 0xda) break;
      if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (pos + 1 >= bytes.byteLength) break;
      const segLen = (bytes[pos] << 8) | bytes[pos + 1];
      if (segLen < 2) break;
      if ((marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf)) {
        if (pos + 6 >= bytes.byteLength) break;
        const height = (bytes[pos + 3] << 8) | bytes[pos + 4];
        const width = (bytes[pos + 5] << 8) | bytes[pos + 6];
        return width > 0 && height > 0 ? { width, height } : null;
      }
      pos += segLen;
    }
  }
  return null;
}
exports.parseImageDimensions = parseImageDimensions;

function shouldPreFlightViaTicket(bytes, size, format, channels, crop) {
  if (!bytes) return false;
  if (format !== "png" && format !== "auto" && format !== "zip") return false;
  if (channels === "alpha") return false;
  const dims = parseImageDimensions(bytes);
  if (!dims) return false;
  const inputPixels = dims.width * dims.height;
  let effectivePixels = inputPixels;
  if (size === "preview" || size === "small" || size === "regular") effectivePixels = Math.min(inputPixels, 250_000);
  else if (size === "medium") effectivePixels = Math.min(inputPixels, 1_500_000);
  else if (size === "hd") effectivePixels = Math.min(inputPixels, 4_000_000);
  else if (size === "4k") effectivePixels = Math.min(inputPixels, 10_000_000);
  return effectivePixels > (crop ? DIRECT_CROPPED_RGBA_PNG_PIXELS : DIRECT_RGBA_PNG_PIXELS);
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function deriveSubIdempotencyKey(idem, suffix) {
  const trimmed = String(idem || "").trim();
  const hash = sha256Hex(Buffer.from(trimmed, "utf8")).slice(0, 32);
  return `${trimmed.slice(0, 180)}:${hash}:${suffix}`;
}

function buildMultipartFormData(fields, filePart) {
  const boundary = `----RemoveAcN8n${crypto.randomBytes(16).toString("hex")}`;
  const chunks = [];

  if (filePart) {
    const safeName = String(filePart.fileName || "image.png").replace(/[\r\n"\\]/g, "_");
    const safeMime = String(filePart.mimeType || "application/octet-stream").replace(/[\r\n]/g, "");
    chunks.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${filePart.fieldName}"; filename="${safeName}"\r\nContent-Type: ${safeMime}\r\n\r\n`,
        "utf8"
      )
    );
    chunks.push(Buffer.from(filePart.buffer));
    chunks.push(Buffer.from("\r\n", "utf8"));
  }

  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null || v === "") continue;
    const safeKey = String(k).replace(/[\r\n"\\]/g, "_");
    chunks.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${safeKey}"\r\n\r\n${String(v)}\r\n`,
        "utf8"
      )
    );
  }

  chunks.push(Buffer.from(`--${boundary}--\r\n`, "utf8"));
  return {
    boundary,
    body: Buffer.concat(chunks),
  };
}

function readHeader(headers, name) {
  if (!headers) return "";
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return Array.isArray(v) ? String(v[0] || "") : String(v ?? "");
    }
  }
  return "";
}

function extractTotalCredits(acct) {
  const top = acct && acct.data && acct.data.attributes ? acct.data.attributes : acct;
  if (top && top.credits && typeof top.credits.total === "number") return top.credits.total;
  if (top && typeof top.totalCredits === "number") return top.totalCredits;
  if (top && typeof top.total_credits === "number") return top.total_credits;
  return null;
}

class RemoveAc {
  constructor() {
    this.description = {
      displayName: "remove.ac",
      name: "removeAc",
      icon: "file:removeac.svg",
      group: ["transform"],
      version: 1,
      subtitle: '={{$parameter["operation"]}}',
      description:
        "Remove image backgrounds via remove.ac (/v1.0/removebg drop-in API + up to 25 MB zero-disk GPU streaming).",
      defaults: {
        name: "remove.ac",
      },
      inputs: ["main"],
      outputs: ["main"],
      usableAsTool: true,
      credentials: [
        {
          name: "removeAcApi",
          required: true,
        },
      ],
      properties: [
        {
          displayName: "Operation",
          name: "operation",
          type: "options",
          noDataExpression: true,
          options: [
            {
              name: "Remove Background",
              value: "removeBackground",
              description: "Remove background from a binary image or public URL",
              action: "Remove background from an image",
            },
            {
              name: "Get Account Balance",
              value: "getAccount",
              description: "Inspect remaining remove.ac API credits",
              action: "Get remove.ac account balance",
            },
          ],
          default: "removeBackground",
        },
        {
          displayName: "Input Source",
          name: "inputSource",
          type: "options",
          displayOptions: {
            show: {
              operation: ["removeBackground"],
            },
          },
          options: [
            {
              name: "Binary Data",
              value: "binary",
            },
            {
              name: "Image URL",
              value: "url",
            },
          ],
          default: "binary",
        },
        {
          displayName: "Input Binary Field",
          name: "binaryPropertyName",
          type: "string",
          default: "data",
          required: true,
          displayOptions: {
            show: {
              operation: ["removeBackground"],
              inputSource: ["binary"],
            },
          },
          description: "Name of the binary property containing the source image.",
        },
        {
          displayName: "Image URL",
          name: "imageUrl",
          type: "string",
          default: "",
          required: true,
          placeholder: "https://example.com/product.jpg",
          displayOptions: {
            show: {
              operation: ["removeBackground"],
              inputSource: ["url"],
            },
          },
          description: "Public HTTP/HTTPS URL of the image to process.",
        },
        {
          displayName: "Output Binary Field",
          name: "outputBinaryPropertyName",
          type: "string",
          default: "data",
          required: true,
          displayOptions: {
            show: {
              operation: ["removeBackground"],
            },
          },
          description: "Binary property name where the cutout image will be stored.",
        },
        {
          displayName: "Size",
          name: "size",
          type: "options",
          displayOptions: {
            show: {
              operation: ["removeBackground"],
            },
          },
          options: [
            { name: "Full (Up to 25 MB / 40 MP)", value: "full" },
            { name: "Auto", value: "auto" },
            { name: "4K (Up to 10 MP)", value: "4k" },
            { name: "HD (Up to 4 MP)", value: "hd" },
            { name: "Medium (Up to 1.5 MP)", value: "medium" },
            { name: "Regular (Up to 0.25 MP)", value: "regular" },
            { name: "Small (Up to 0.25 MP)", value: "small" },
            { name: "Preview (Up to 0.25 MP)", value: "preview" },
          ],
          default: "full",
        },
        {
          displayName: "Format",
          name: "format",
          type: "options",
          displayOptions: {
            show: {
              operation: ["removeBackground"],
            },
          },
          options: [
            { name: "PNG (Transparent)", value: "png" },
            { name: "WebP", value: "webp" },
            { name: "JPG", value: "jpg" },
            { name: "ZIP", value: "zip" },
          ],
          default: "png",
        },
        {
          displayName: "Additional Options",
          name: "additionalOptions",
          type: "collection",
          placeholder: "Add Option",
          default: {},
          displayOptions: {
            show: {
              operation: ["removeBackground"],
            },
          },
          options: [
            {
              displayName: "Background Color (Hex)",
              name: "bgColor",
              type: "string",
              default: "",
              placeholder: "FFFFFF",
              description: "Solid hex background color (e.g. FFFFFF for marketplace white).",
            },
            {
              displayName: "Crop Transparent Padding",
              name: "crop",
              type: "boolean",
              default: false,
            },
            {
              displayName: "Foreground Type",
              name: "type",
              type: "options",
              options: [
                { name: "Auto", value: "auto" },
                { name: "Product", value: "product" },
                { name: "Person", value: "person" },
                { name: "Car", value: "car" },
                { name: "Animal", value: "animal" },
                { name: "Graphic", value: "graphic" },
                { name: "Transportation", value: "transportation" },
              ],
              default: "auto",
            },
            {
              displayName: "Add Shadow",
              name: "addShadow",
              type: "boolean",
              default: false,
            },
            {
              displayName: "Shadow Type",
              name: "shadowType",
              type: "options",
              options: [
                { name: "Auto", value: "auto" },
                { name: "Contact", value: "contact" },
                { name: "Drop", value: "drop" },
                { name: "Soft", value: "soft" },
                { name: "Car", value: "car" },
                { name: "Reflection", value: "reflection" },
                { name: "None", value: "none" },
              ],
              default: "auto",
            },
            {
              displayName: "Channels",
              name: "channels",
              type: "options",
              options: [
                { name: "RGBA", value: "rgba" },
                { name: "Alpha Matte Only", value: "alpha" },
              ],
              default: "rgba",
            },
          ],
        },
      ],
    };
  }

  async execute() {
    const items = this.getInputData();
    const returnData = [];
    const creds = await this.getCredentials("removeAcApi");
    const apiKey = String((creds && creds.apiKey) || "").trim();
    if (!apiKey) {
      throw new Error("Missing remove.ac API key in credentials.");
    }

    const rawBaseUrl = String((creds && creds.baseUrl) || DEFAULT_BASE_URL).trim();
    const lookupFn = this._dnsLookupForTest || dns.promises.lookup;
    const allowLoopback = Boolean(this._allowLoopbackBaseUrlForTest);

    let baseUrl;
    if (allowLoopback) {
      baseUrl = new URL(rawBaseUrl).origin;
    } else {
      const parsedBase = await validatePublicUrl(rawBaseUrl, {
        requireHttps: true,
        lookupFn,
      });
      baseUrl = parsedBase.origin;
    }

    for (let i = 0; i < items.length; i++) {
      try {
        const operation = this.getNodeParameter("operation", i);

        if (operation === "getAccount") {
          const acctResp = await this.helpers.httpRequest({
            method: "GET",
            url: `${baseUrl}/v1.0/account`,
            headers: {
              "X-Api-Key": apiKey,
              Accept: "application/json",
            },
            json: true,
            disableFollowRedirect: true,
            sendCredentialsOnCrossOriginRedirect: false,
            returnFullResponse: true,
            ignoreHttpStatusErrors: true,
          });
          const acctStatus =
            acctResp && typeof acctResp.statusCode === "number" ? acctResp.statusCode : 200;
          const acctRawBody =
            acctResp && typeof acctResp === "object" && "statusCode" in acctResp
              ? acctResp.body
              : acctResp;
          if (acctStatus < 200 || acctStatus >= 300) {
            const errTxt =
              typeof acctRawBody === "string"
                ? acctRawBody
                : Buffer.isBuffer(acctRawBody)
                  ? acctRawBody.toString("utf8")
                  : JSON.stringify(acctRawBody ?? "");
            throw new Error(`[HTTP ${acctStatus}] ${errTxt}`);
          }
          const bodyObj = typeof acctRawBody === "string" ? JSON.parse(acctRawBody) : acctRawBody;
          const totalCredits = extractTotalCredits(bodyObj);
          returnData.push({
            json: {
              totalCredits,
              account: bodyObj,
            },
            pairedItem: { item: i },
          });
          continue;
        }

        const inputSource = this.getNodeParameter("inputSource", i);
        const outputBinaryPropertyName = this.getNodeParameter("outputBinaryPropertyName", i);
        const size = this.getNodeParameter("size", i);
        const format = this.getNodeParameter("format", i);
        const additional = this.getNodeParameter("additionalOptions", i, {}) || {};
        const channels = additional.channels || "rgba";
        const crop = Boolean(additional.crop);
        const idem = `n8n-${crypto.randomUUID()}`;

        let sourceBytes = null;
        let sourceFileName = "image.png";
        let sourceMimeType = "image/png";
        let sourceUrl = null;

        if (inputSource === "binary") {
          const binaryPropertyName = this.getNodeParameter("binaryPropertyName", i);
          const binaryMeta = this.helpers.assertBinaryData(i, binaryPropertyName);
          sourceBytes = Buffer.from(await this.helpers.getBinaryDataBuffer(i, binaryPropertyName));
          if (sourceBytes.byteLength === 0) {
            throw new Error(`Input binary property '${binaryPropertyName}' is empty.`);
          }
          if (sourceBytes.byteLength > MAX_UPLOAD_BYTES) {
            throw new Error(
              `Input image exceeds remove.ac 25 MB limit (${sourceBytes.byteLength} bytes).`
            );
          }
          sourceFileName = binaryMeta.fileName || "image.png";
          sourceMimeType = binaryMeta.mimeType || "application/octet-stream";
        } else {
          const rawImageUrl = String(this.getNodeParameter("imageUrl", i) || "").trim();
          const validated = await validatePublicUrl(rawImageUrl, {
            requireHttps: false,
            lookupFn,
          });
          sourceUrl = validated.toString();
          const urlPath = validated.pathname.split("/").pop() || "remote-image";
          sourceFileName = urlPath;
        }

        const optionFields = {
          size,
          format,
          channels,
          ...(additional.type && additional.type !== "auto" ? { type: additional.type } : {}),
          ...(additional.bgColor ? { bg_color: String(additional.bgColor).replace(/^#/, "") } : {}),
          ...(additional.crop !== undefined ? { crop: String(Boolean(additional.crop)) } : {}),
          ...(additional.addShadow !== undefined ? { add_shadow: String(Boolean(additional.addShadow)) } : {}),
          ...(additional.shadowType && additional.addShadow ? { shadow_type: additional.shadowType } : {}),
        };

        const runTicketStream = async (suffix) => {
          const ticketPayload = {
            foregroundSha256: sha256Hex(sourceBytes),
            foregroundByteLength: sourceBytes.byteLength,
            size,
            format,
            channels,
            ...(additional.type && additional.type !== "auto" ? { type: additional.type } : {}),
            ...(additional.bgColor ? { bg_color: String(additional.bgColor).replace(/^#/, "") } : {}),
            ...(additional.crop !== undefined ? { crop: Boolean(additional.crop) } : {}),
            ...(additional.addShadow !== undefined ? { add_shadow: Boolean(additional.addShadow) } : {}),
            ...(additional.shadowType && additional.addShadow ? { shadow_type: additional.shadowType } : {}),
          };

          const ticketRes = await this.helpers.httpRequest({
            method: "POST",
            url: `${baseUrl}/v1.0/removebg/ticket`,
            headers: {
              "Content-Type": "application/json",
              "X-Api-Key": apiKey,
              "Idempotency-Key": deriveSubIdempotencyKey(idem, suffix),
            },
            body: ticketPayload,
            json: true,
            disableFollowRedirect: true,
            sendCredentialsOnCrossOriginRedirect: false,
            returnFullResponse: true,
            ignoreHttpStatusErrors: true,
          });
          const ticketStatus =
            ticketRes && typeof ticketRes.statusCode === "number" ? ticketRes.statusCode : 200;
          const ticketRawBody =
            ticketRes && typeof ticketRes === "object" && "statusCode" in ticketRes
              ? ticketRes.body
              : ticketRes;
          if (ticketStatus < 200 || ticketStatus >= 300) {
            const errTxt =
              typeof ticketRawBody === "string"
                ? ticketRawBody
                : Buffer.isBuffer(ticketRawBody)
                  ? ticketRawBody.toString("utf8")
                  : JSON.stringify(ticketRawBody ?? "");
            throw new Error(`[HTTP ${ticketStatus}] ${errTxt}`);
          }
          const tJson = typeof ticketRawBody === "string" ? JSON.parse(ticketRawBody) : ticketRawBody;
          if (!tJson || !tJson.data || !tJson.data.directEndpoint || !tJson.data.ticket) {
            throw new Error("Invalid /v1.0/removebg/ticket response from remove.ac");
          }

          const directEndpoint = String(tJson.data.directEndpoint);
          if (!allowLoopback) {
            await validatePublicUrl(directEndpoint, {
              requireHttps: true,
              lookupFn,
            });
          }

          const mp = buildMultipartFormData({}, {
            fieldName: "image_file",
            fileName: sourceFileName,
            mimeType: sourceMimeType,
            buffer: sourceBytes,
          });

          const dRes = await this.helpers.httpRequest({
            method: "POST",
            url: directEndpoint,
            headers: {
              Authorization: `Bearer ${tJson.data.ticket}`,
              "Content-Type": `multipart/form-data; boundary=${mp.boundary}`,
            },
            body: mp.body,
            encoding: "arraybuffer",
            json: false,
            disableFollowRedirect: true,
            sendCredentialsOnCrossOriginRedirect: false,
            returnFullResponse: true,
            ignoreHttpStatusErrors: true,
          });

          if (dRes.statusCode < 200 || dRes.statusCode >= 300) {
            const errTxt = Buffer.from(dRes.body || "").toString("utf8");
            throw new Error(`[HTTP ${dRes.statusCode}] ${errTxt}`);
          }
          return dRes;
        };

        let rawResponse;
        const needsTicketUpfront =
          sourceBytes &&
          (sourceBytes.byteLength > DIRECT_THRESHOLD_BYTES ||
            shouldPreFlightViaTicket(sourceBytes, size, format, channels, crop));

        if (needsTicketUpfront) {
          rawResponse = await runTicketStream("direct");
        } else {
          const mp = sourceUrl
            ? buildMultipartFormData({ ...optionFields, image_url: sourceUrl }, null)
            : buildMultipartFormData(optionFields, {
                fieldName: "image_file",
                fileName: sourceFileName,
                mimeType: sourceMimeType,
                buffer: sourceBytes,
              });

          const directRes = await this.helpers.httpRequest({
            method: "POST",
            url: `${baseUrl}/v1.0/removebg`,
            headers: {
              "X-Api-Key": apiKey,
              "Idempotency-Key": idem,
              "Content-Type": `multipart/form-data; boundary=${mp.boundary}`,
            },
            body: mp.body,
            encoding: "arraybuffer",
            json: false,
            disableFollowRedirect: true,
            sendCredentialsOnCrossOriginRedirect: false,
            returnFullResponse: true,
            ignoreHttpStatusErrors: true,
          });

          if (directRes.statusCode === 413 && sourceBytes) {
            rawResponse = await runTicketStream("fallback413");
          } else if (directRes.statusCode < 200 || directRes.statusCode >= 300) {
            const errTxt = Buffer.from(directRes.body || "").toString("utf8");
            throw new Error(`[HTTP ${directRes.statusCode}] ${errTxt}`);
          } else {
            rawResponse = directRes;
          }
        }

        const cutoutBuffer = Buffer.from(rawResponse.body);
        const respHeaders = rawResponse.headers || {};
        const outExt =
          format === "jpg" ? "jpg" : format === "webp" ? "webp" : format === "zip" ? "zip" : "png";
        const defaultMime =
          format === "jpg"
            ? "image/jpeg"
            : format === "webp"
              ? "image/webp"
              : format === "zip"
                ? "application/zip"
                : "image/png";
        const outMime = readHeader(respHeaders, "content-type") || defaultMime;
        const stem = sourceFileName.replace(/\.[^.]+$/, "") || "image";
        const outFileName = `${stem}-nobg.${outExt}`;

        const preparedBinary = await this.helpers.prepareBinaryData(
          cutoutBuffer,
          outFileName,
          outMime
        );

        returnData.push({
          json: {
            ...(items[i].json || {}),
            removeAc: {
              creditsCharged: Number.parseFloat(readHeader(respHeaders, "x-credits-charged") || "0"),
              width: Number.parseInt(readHeader(respHeaders, "x-width") || "0", 10),
              height: Number.parseInt(readHeader(respHeaders, "x-height") || "0", 10),
              foregroundTop: Number.parseInt(readHeader(respHeaders, "x-foreground-top") || "0", 10),
              foregroundLeft: Number.parseInt(readHeader(respHeaders, "x-foreground-left") || "0", 10),
              foregroundWidth: Number.parseInt(readHeader(respHeaders, "x-foreground-width") || "0", 10),
              foregroundHeight: Number.parseInt(readHeader(respHeaders, "x-foreground-height") || "0", 10),
              bytes: cutoutBuffer.byteLength,
              mimeType: outMime,
              fileName: outFileName,
            },
          },
          binary: {
            ...(items[i].binary || {}),
            [outputBinaryPropertyName]: preparedBinary,
          },
          pairedItem: { item: i },
        });
      } catch (err) {
        if (this.continueOnFail()) {
          returnData.push({
            json: {
              ...(items[i].json || {}),
              error: err instanceof Error ? err.message : String(err),
            },
            pairedItem: { item: i },
          });
          continue;
        }
        throw err;
      }
    }

    return [returnData];
  }
}

exports.RemoveAc = RemoveAc;
