import {
  compactDecrypt,
  CompactEncrypt,
  CompactJWEHeaderParameters,
  CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
} from 'jose';

export interface JWKS<T = PublicJWK | PrivateJWK> {
  keys: T[];
}

export interface PublicJWK {
  // kty: is the key type
  kty: string;
  // kid: is the unique identifier for the key
  kid: string;
  // use: is how the key was meant to be used.
  use: KeyUse;
  // alg: is the algorithm for the key
  alg: string;
  // e: public exponent
  e: string;
  // n: is the modulus for the public component
  n: string;
}

export interface PrivateJWK extends PublicJWK {
  // d: private component
  d: string;
  // q: prime 1
  p: string;
  // q: prime 2
  q: string;
  // dp: exponent1
  dp: string;
  // dq: exponent2
  dq: string;
  // qi: coefficient
  qi: string;
}

export interface JWKMetadata {
  length: number;
  kty: string;
  kid: string;
  use: string;
  alg: string;
}

export type KeyUse = 'enc' | 'desc';
export type PublicJWKS = JWKS<PublicJWK>;
export type PrivateJWKS = JWKS<PrivateJWK>;
export type JWK = PrivateJWK | PublicJWK;
export type UnsignedJWK = PrivateJWK | PublicJWK;

export const RSA_ALGORITHM = 'RSA-OAEP';
const RSA_ENC = 'A128CBC-HS256';

export interface JWKDecryptResult {
  /**
   * JWK metadata
   */
  key: JWKMetadata;
  /**
   * an object of "protected" member key values.
   */
  header: Record<string, string>;
  /**
   * array of protected member names
   */
  protected: string[];
  /**
   * plaintext Buffer (alias of payload for back-compat)
   */
  plaintext: Buffer;
  /**
   * payload Buffer
   */
  payload: Buffer;
}

export interface KeyEntry {
  kid: string;
  use: KeyUse;
  alg: string;
  privateKey?: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: PublicJWK;
  privateJwk?: PrivateJWK;
}

// tslint:disable-next-line: max-classes-per-file
export class KeyStore {
  private entries: KeyEntry[] = [];

  public async add(entry: KeyEntry): Promise<void> {
    this.entries.push(entry);
  }

  public get(kid?: string): KeyEntry | undefined {
    if (kid !== undefined) {
      return this.entries.find(e => e.kid === kid);
    }
    return this.entries[0];
  }

  public remove(jwk: PublicJWK | PrivateJWK): void {
    this.entries = this.entries.filter(e => e.kid !== jwk.kid);
  }

  public toJSON(): PublicJWKS;
  public toJSON(includePrivate: true): PrivateJWKS;
  public toJSON(includePrivate = false): PublicJWKS | PrivateJWKS {
    if (includePrivate) {
      return {
        keys: this.entries.map(
          e => (e.privateJwk != null ? e.privateJwk : e.publicJwk) as PrivateJWK
        ),
      };
    }
    return { keys: this.entries.map(e => e.publicJwk) };
  }
}

// tslint:disable-next-line: max-classes-per-file
export class JWKSManager {
  public store: KeyStore;

  constructor(store: KeyStore) {
    this.store = store;
  }

  public async addKey(kid: string | undefined, modulus: number, use: KeyUse): Promise<void> {
    const { privateKey, publicKey } = await generateKeyPair(RSA_ALGORITHM, {
      modulusLength: modulus,
      extractable: true,
    });
    const [privateJwkRaw, publicJwkRaw] = await Promise.all([
      exportJWK(privateKey as CryptoKey),
      exportJWK(publicKey as CryptoKey),
    ]);
    const resolvedKid = kid != null ? kid : '';
    const publicJwk: PublicJWK = {
      kty: publicJwkRaw.kty!,
      kid: resolvedKid,
      use,
      alg: RSA_ALGORITHM,
      e: publicJwkRaw.e!,
      n: publicJwkRaw.n!,
    };
    const privateJwk: PrivateJWK = {
      ...publicJwk,
      d: privateJwkRaw.d!,
      p: privateJwkRaw.p!,
      q: privateJwkRaw.q!,
      dp: privateJwkRaw.dp!,
      dq: privateJwkRaw.dq!,
      qi: privateJwkRaw.qi!,
    };
    await this.insertKey({
      kid: resolvedKid,
      use,
      alg: RSA_ALGORITHM,
      privateKey: privateKey as CryptoKey,
      publicKey: publicKey as CryptoKey,
      publicJwk,
      privateJwk,
    });
  }

  public async insertKey(entry: KeyEntry): Promise<void> {
    await this.store.add(entry);
  }

  public getPublicJWK(kid?: string): PublicJWK | null {
    const entry = this.store.get(kid);
    return entry != null ? entry.publicJwk : null;
  }

  public getPrivateJWK(kid?: string): PrivateJWK | null {
    const entry = this.store.get(kid);
    return entry != null && entry.privateJwk != null ? entry.privateJwk : null;
  }

  public getPublicJWKS(): PublicJWKS {
    return this.store.toJSON();
  }

  public getPrivateJWKS(): PrivateJWKS {
    return this.store.toJSON(true);
  }

  public removeKey(key: PublicJWK | PrivateJWK): void {
    this.store.remove(key);
  }

  public async encrypt(kid: string, input: Buffer): Promise<string> {
    const entry = this.store.get(kid);
    if (!entry) {
      throw new Error(`Missing kid (${kid}).`);
    }
    // Header key order matches node-jose's: zip, enc, alg, kid — preserving the wire format.
    return new CompactEncrypt(Uint8Array.from(input))
      .setProtectedHeader({ zip: 'DEF', enc: RSA_ENC, alg: RSA_ALGORITHM, kid })
      .encrypt(entry.publicKey);
  }

  public async decrypt(payload: string, store = this.store): Promise<JWKDecryptResult> {
    const keyResolver = async (header: CompactJWEHeaderParameters) => {
      const keyEntry = store.get(header.kid);
      if (!keyEntry || !keyEntry.privateKey) {
        throw new Error('no key found');
      }
      return keyEntry.privateKey;
    };
    const { plaintext, protectedHeader } = await compactDecrypt(payload, keyResolver);
    const entry = store.get((protectedHeader as CompactJWEHeaderParameters).kid);
    const payloadBuffer = Buffer.from(plaintext);
    const publicJwk = entry!.publicJwk;
    return {
      payload: payloadBuffer,
      plaintext: payloadBuffer,
      header: (protectedHeader as unknown) as Record<string, string>,
      protected: Object.keys(protectedHeader),
      key: {
        length: Buffer.from(publicJwk.n, 'base64url').length * 8,
        kty: publicJwk.kty,
        kid: publicJwk.kid,
        use: publicJwk.use,
        alg: publicJwk.alg,
      },
    };
  }

  protected getKey(kid?: string): KeyEntry | undefined {
    return this.store.get(kid);
  }
}

export async function createJWKS(jwks?: JWKS): Promise<KeyStore> {
  const store = new KeyStore();
  if (!jwks) {
    return store;
  }
  for (const key of jwks.keys) {
    const isPrivate = 'd' in key;
    const publicJwk: PublicJWK = {
      kty: key.kty,
      kid: key.kid,
      use: key.use as KeyUse,
      alg: key.alg,
      e: (key as PublicJWK).e,
      n: (key as PublicJWK).n,
    };
    // Cast to jose's JWK union; our PublicJWK is structurally compatible for import.
    const publicKey = (await importJWK(publicJwk as Parameters<typeof importJWK>[0])) as CryptoKey;
    if (isPrivate) {
      const privateJwk = key as PrivateJWK;
      const privateKey = (await importJWK(
        privateJwk as Parameters<typeof importJWK>[0],
        undefined,
        { extractable: true }
      )) as CryptoKey;
      await store.add({
        kid: key.kid,
        use: key.use as KeyUse,
        alg: key.alg,
        privateKey,
        publicKey,
        publicJwk,
        privateJwk,
      });
    } else {
      await store.add({
        kid: key.kid,
        use: key.use as KeyUse,
        alg: key.alg,
        publicKey,
        publicJwk,
      });
    }
  }
  return store;
}

export async function createJWKSManager(jwks?: JWKS): Promise<JWKSManager> {
  const store = await createJWKS(jwks);
  return new JWKSManager(store);
}
