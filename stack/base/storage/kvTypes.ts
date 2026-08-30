/**
 * Known storage's key and value types
 */
export interface KeyValues {
  cert: string;
  qrCert: string;
  refreshToken: string;
  expire: number;
  "channelToken:${channelId}": {
    channelId: string;
    channelAccessToken: string;
    issuedAt: string;
    lastUsedAt: string;
    issuance: "issue" | "approve-and-issue";
    reissuedAt?: string;
  };
  reqseq: Record<string, number>;
  "e2eeKeys:${keyId}": string;
  "e2eePublicKeys:${keyId}": string;
  "e2eeGroupKeys:${chatMid}": string;
}
