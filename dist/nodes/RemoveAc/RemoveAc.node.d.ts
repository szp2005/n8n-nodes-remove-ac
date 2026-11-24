import type { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from "n8n-workflow";

export declare const PACKAGE_VERSION: "1.0.3";
export declare const MAX_DIRECT_BODY_BYTES: number;
export declare const MAX_COMBINED_IMAGE_BYTES: number;
export declare const VALID_SIZES: readonly string[];
export declare const VALID_FORMATS: readonly string[];

export interface PinnedAddress {
  address: string;
  family: 4 | 6;
}

export declare function parseImageDimensions(
  input: Uint8Array | ArrayBuffer
): { width: number; height: number } | null;
export declare function isPrivateIpv4(ip: string): boolean;
export declare function isPrivateIpv6(ip: string): boolean;
export declare function resolveValidatedPublicUrl(
  rawUrl: string,
  options?: { requireHttps?: boolean; allowTunFakeIp?: boolean; lookupFn?: unknown }
): Promise<{ url: URL; host: string; addresses: PinnedAddress[] }>;
export declare function validatePublicUrl(
  rawUrl: string,
  options?: { requireHttps?: boolean; allowTunFakeIp?: boolean; lookupFn?: unknown }
): Promise<URL>;
export declare function requestPinnedRemoteHop(
  parsedUrl: URL,
  pinnedAddresses: PinnedAddress[],
  options?: { maxBytes?: number; timeoutMs?: number }
): Promise<{ statusCode: number; headers: Record<string, unknown>; body: Buffer }>;
export declare function fetchPinnedRemoteImageBytes(
  initialUrl: string,
  options?: {
    initialResolved?: { url: URL; host: string; addresses: PinnedAddress[] } | null;
    lookupFn?: unknown;
    maxBytes?: number;
    timeoutMs?: number;
    maxRedirects?: number;
    transportForTest?: unknown;
  }
): Promise<{
  buffer: Buffer;
  mimeType: string;
  dims: { width: number; height: number } | null;
  finalUrl: string;
  pinnedAddresses: PinnedAddress[];
}>;
export declare function isAllowedDirectEndpointHost(
  directHost: string,
  baseHost?: string
): boolean;
export declare function validateDirectEndpointUrl(
  rawUrl: string,
  options?: { baseUrl?: string; allowLoopback?: boolean; lookupFn?: unknown }
): Promise<URL>;
export declare function detectImageMagic(
  input: Uint8Array | ArrayBuffer
): "image/png" | "image/jpeg" | "image/webp" | "image/gif" | null;
export declare function parseForegroundMetadata(headers: unknown): {
  foregroundTop: number | null;
  foregroundLeft: number | null;
  foregroundWidth: number | null;
  foregroundHeight: number | null;
};
export declare function toNodeBuffer(val: unknown): Buffer | null;
export declare function formatErrorBody(rawBody: unknown): string;
export declare function normalizeShadowOptions(additional?: Record<string, unknown>): {
  multipart: Record<string, string>;
  json: Record<string, string | boolean>;
};

export declare class RemoveAc implements INodeType {
  description: INodeTypeDescription;
  execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]>;
}
