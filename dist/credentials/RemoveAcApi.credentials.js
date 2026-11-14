"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RemoveAcApi = void 0;

class RemoveAcApi {
  constructor() {
    this.name = "removeAcApi";
    this.displayName = "remove.ac API";
    this.documentationUrl = "https://remove.ac/api-info";
    this.properties = [
      {
        displayName: "API Key",
        name: "apiKey",
        type: "string",
        typeOptions: {
          password: true,
        },
        default: "",
        required: true,
        placeholder: "rac_live_...",
        description:
          "Your remove.ac API key. Verified email accounts include 1 free welcome credit at https://remove.ac/api-info.",
      },
      {
        displayName: "Base URL",
        name: "baseUrl",
        type: "string",
        default: "https://remove.ac",
        required: true,
        description: "HTTPS origin for the remove.ac API.",
      },
    ];
    this.authenticate = {
      type: "generic",
      properties: {
        headers: {
          "X-Api-Key": "={{$credentials.apiKey}}",
        },
      },
    };
    this.test = {
      request: {
        baseURL:
          "={{ /^https:\\/\\/[a-z0-9-]+(\\.[a-z0-9-]+)+(:[0-9]{1,5})?\\/?$/i.test(($credentials.baseUrl || 'https://remove.ac').trim()) && !/\\.(localhost|local|internal|home\\.arpa)(:[0-9]+)?\\/?$/i.test(($credentials.baseUrl || '').trim()) && !/^https:\\/\\/[0-9.]+(:[0-9]+)?\\/?$/i.test(($credentials.baseUrl || '').trim()) ? ($credentials.baseUrl || 'https://remove.ac').trim().replace(/\\/+$/, '') : 'invalid://https-public-domain-required' }}",
        url: "/v1.0/account",
        method: "GET",
        disableFollowRedirect: true,
        sendCredentialsOnCrossOriginRedirect: false,
      },
    };
  }
}

exports.RemoveAcApi = RemoveAcApi;
