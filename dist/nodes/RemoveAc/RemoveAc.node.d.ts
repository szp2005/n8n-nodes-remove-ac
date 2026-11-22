import type { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from "n8n-workflow";

export declare function parseImageDimensions(
  input: Uint8Array | ArrayBuffer
): { width: number; height: number } | null;
export declare function isPrivateIpv4(ip: string): boolean;
export declare function isPrivateIpv6(ip: string): boolean;
export declare function validatePublicUrl(
  rawUrl: string,
  options?: { requireHttps?: boolean; lookupFn?: unknown }
): Promise<URL>;
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
