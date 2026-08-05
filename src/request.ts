import _makeAESCryptoWith, { Crypto, CryptoOptions, EncryptOutput } from '@elastic/node-crypto';

import { createJWKManager } from './jwk.js';
import { JWKDecryptResult, PrivateJWKS, PublicJWK, PublicJWKS } from './jwks.js';
import { generatePassphrase } from './random-bytes.js';

// @elastic/node-crypto is a CJS module. Under Node.js ESM, importing a CJS default always
// yields the full exports object, not just the .default property. Unwrap it explicitly.
const makeAESCryptoWith: (opts: CryptoOptions) => Crypto =
  (_makeAESCryptoWith as any).default || _makeAESCryptoWith;

export interface Encryptor {
  encrypt(kid: string, input: any): Promise<string>;
}

export interface Decryptor {
  getPublicComponent(kid: string): PublicJWK | null;
  getWellKnowns(): PublicJWKS;
  decrypt(encryptedBody: string): Promise<EncryptOutput | EncryptOutput[]>;
  getJWKMetadata(
    encryptedBody: string
  ): Promise<Pick<JWKDecryptResult, 'key' | 'protected' | 'header'>>;
}

export async function createRequestEncryptor(publicJWKS: PublicJWKS): Promise<Encryptor> {
  const jwkManager = await createJWKManager(publicJWKS);
  return {
    async encrypt(kid, input) {
      const AESKeyBuffer = generatePassphrase();
      const AES = makeAESCryptoWith({ encryptionKey: AESKeyBuffer });
      const encryptedPayload = await AES.encrypt(input);
      const encryptedKey = await jwkManager.encrypt(kid, AESKeyBuffer);
      return packBody(encryptedKey, encryptedPayload);
    },
  };
}

export async function createRequestDecryptor(privateJWKS: PrivateJWKS): Promise<Decryptor> {
  const jwkManager = await createJWKManager(privateJWKS);
  return {
    getPublicComponent(kid: string) {
      return jwkManager.getPublicJWK(kid);
    },
    getWellKnowns() {
      return jwkManager.getPublicJWKS();
    },
    async decrypt(encryptedBody: string) {
      const { encryptedAESKey, encryptedPayload } = unpackBody(encryptedBody);
      const { payload: encryptionKeyBuffer } = await jwkManager.decrypt(encryptedAESKey);
      const AES = makeAESCryptoWith({ encryptionKey: encryptionKeyBuffer });
      return AES.decrypt(encryptedPayload);
    },
    async getJWKMetadata(encryptedBody: string) {
      const { encryptedAESKey } = unpackBody(encryptedBody);
      const { key, protected: protectedFields, header } = await jwkManager.decrypt(encryptedAESKey);
      return { key, protected: protectedFields, header };
    },
  };
}

export function packBody(encryptedAESKey: string, encryptedPayload: string): string {
  const packedBodyStringifiedJSON = JSON.stringify({
    encryptedAESKey,
    encryptedPayload,
  });
  return Buffer.from(packedBodyStringifiedJSON, 'utf8').toString('base64url');
}

export function unpackBody(packedBody: string) {
  const decodedBody = Buffer.from(packedBody, 'base64url');
  const { encryptedAESKey, encryptedPayload } = JSON.parse(decodedBody.toString('utf8'));
  return { encryptedAESKey, encryptedPayload };
}
