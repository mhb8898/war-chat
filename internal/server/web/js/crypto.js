// War Chat - core crypto (ECDH, AES-GCM, mnemonic, no DB)

export function ensureCrypto() {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    const msg = 'Web Crypto API is not available. Use HTTPS or open from localhost.';
    if (typeof document !== 'undefined' && document.body) {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'padding:2rem;text-align:center;font-family:sans-serif';
      const h2 = document.createElement('h2');
      h2.textContent = 'Security Required';
      const p = document.createElement('p');
      p.textContent = msg;
      wrap.appendChild(h2);
      wrap.appendChild(p);
      document.body.replaceChildren(wrap);
    }
    throw new Error(msg);
  }
}

export function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export function arrayBufferToBase64(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}

export async function mnemonicToSeed(mnemonic) {
  ensureCrypto();
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(mnemonic.trim().toLowerCase()),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const seed = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode('war-chat-identity'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    key,
    256
  );
  return new Uint8Array(seed);
}

/** Generate ECDH P-256 keypair (no storage). */
export async function generateKeypair() {
  ensureCrypto();
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
}

export async function deriveSharedKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function deriveMessageEncryptionKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(plaintext, sharedKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    enc.encode(plaintext)
  );
  return { ciphertext: ct, iv: iv };
}

export async function decrypt(ciphertextB64, ivB64, sharedKey) {
  const ciphertext = new Uint8Array([...atob(ciphertextB64)].map((c) => c.charCodeAt(0)));
  const iv = new Uint8Array([...atob(ivB64)].map((c) => c.charCodeAt(0)));
  const dec = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    ciphertext
  );
  return new TextDecoder().decode(dec);
}

export async function importPubkeyFromBase64(b64) {
  try {
    const json = JSON.parse(atob(b64));
    return crypto.subtle.importKey('jwk', json, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } catch {
    return null;
  }
}

export async function deriveP256KeypairFromSeed(seedBytes) {
  ensureCrypto();
  if (seedBytes.length !== 32) throw new Error('Seed must be exactly 32 bytes');
  // Correct PKCS8 / PrivateKeyInfo DER for P-256.
  // Structure (lengths verified from inside out):
  //   ECPrivateKey content : version(3) + privateKey-OCTET-STRING(34) = 37  → 0x25
  //   ECPrivateKey total   : 2 + 37 = 39                                     → 0x27 for outer OCTET STRING
  //   AlgorithmIdentifier  : OID id-ecPublicKey(9) + OID P-256(10) = 19     → 0x13
  //   PrivateKeyInfo content: version(3) + AlgId(21) + OCTET-STRING(41) = 65 → 0x41
  const pkcs8Header = new Uint8Array([
    0x30, 0x41,                                     // SEQUENCE PrivateKeyInfo, len=65
    0x02, 0x01, 0x00,                               // INTEGER version=0
    0x30, 0x13,                                     // SEQUENCE AlgorithmIdentifier, len=19
    0x06, 0x07,                                     // OID, len=7
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,      // id-ecPublicKey
    0x06, 0x08,                                     // OID, len=8
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,// P-256
    0x04, 0x27,                                     // OCTET STRING, len=39
    0x30, 0x25,                                     // SEQUENCE ECPrivateKey, len=37
    0x02, 0x01, 0x01,                               // INTEGER version=1
    0x04, 0x20,                                     // OCTET STRING privateKey, len=32
  ]);
  const pkcs8 = new Uint8Array(pkcs8Header.length + 32);
  pkcs8.set(pkcs8Header);
  pkcs8.set(seedBytes, pkcs8Header.length);
  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8', pkcs8.buffer,
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey']
    );
  } catch (e) {
    throw new Error('Key derivation failed for this phrase: ' + e.message);
  }
  const privateJwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicJwk = { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y };
  const publicKey = await crypto.subtle.importKey(
    'jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []
  );
  return { privateKey, publicKey, privateJwk, publicJwk };
}

export async function exportPubkeyToBase64(pubKey) {
  const jwk = await crypto.subtle.exportKey('jwk', pubKey);
  return btoa(JSON.stringify(jwk));
}
