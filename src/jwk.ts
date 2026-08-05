import { createJWKS, JWKS, JWKSManager, KeyStore } from './jwks.js';

export const ENC_MODULUS = 2048;

export class JWKManager extends JWKSManager {
  public addKey(kid: string) {
    return super.addKey(kid, ENC_MODULUS, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS): Promise<JWKManager> {
  const store: KeyStore = await createJWKS(jwks);
  return new JWKManager(store);
}
