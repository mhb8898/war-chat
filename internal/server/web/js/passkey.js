// War Chat - WebAuthn / Passkey (create, authenticate, PRF, encrypt/decrypt keypair)

import * as db from './db.js';
import { base64ToArrayBuffer } from './crypto.js';

const PRF_SALT = new TextEncoder().encode('war-chat-prf-salt');

export function getRpId() {
  return typeof window !== 'undefined' ? (window.location.hostname || 'localhost') : 'localhost';
}

export async function isPasskeySupported() {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;
  if (!window.isSecureContext) return false;
  try {
    if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
      const caps = await PublicKeyCredential.getClientCapabilities('public-key');
      if (caps.extensions && Array.isArray(caps.extensions) && caps.extensions.includes('prf')) return true;
      if (caps.extensions && typeof caps.extensions === 'object' && caps.extensions.prf) return true;
    }
    return true;
  } catch {
    return true;
  }
}

export async function deriveKeyFromPrf(prfResult) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', prfResult, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('war-chat-passkey-kdf'), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function createPasskey(username) {
  const rpId = getRpId();
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const displayName = (username && username.trim()) || 'Personal Chat user';
  const publicKeyBase = {
    rp: { name: 'Personal Chat', id: rpId },
    user: { id: userId, name: displayName, displayName },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
  };
  const optionsWithPrf = {
    publicKey: {
      ...publicKeyBase,
      extensions: {
        prf: {
          eval: {
            first: PRF_SALT,
          },
        },
      },
    },
  };
  const optionsWithoutPrf = { publicKey: publicKeyBase };
  let credential;
  try {
    credential = await navigator.credentials.create(optionsWithPrf);
  } catch {
    credential = await navigator.credentials.create(optionsWithoutPrf);
  }
  if (!credential || !(credential instanceof PublicKeyCredential)) throw new Error('Passkey creation failed');
  const credentialId = btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const ext = credential.getClientExtensionResults();
  const prfResultRaw = ext.prf?.results?.first;
  if (prfResultRaw) {
    return { credentialId, prfResult: new Uint8Array(prfResultRaw), credential };
  }
  const fallbackKey = crypto.getRandomValues(new Uint8Array(32));
  const storedKeyB64 = btoa(String.fromCharCode.apply(null, fallbackKey));
  return { credentialId, prfResult: fallbackKey, storedKeyB64, credential };
}

export async function authenticatePasskey() {
  const rpId = getRpId();
  const publicKeyBase = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [],
    userVerification: 'required',
  };
  const optionsWithPrf = {
    publicKey: {
      ...publicKeyBase,
      extensions: {
        prf: {
          eval: {
            first: PRF_SALT,
          },
        },
      },
    },
  };
  const optionsWithoutPrf = { publicKey: publicKeyBase };
  let assertion;
  try {
    assertion = await navigator.credentials.get(optionsWithPrf);
  } catch {
    assertion = await navigator.credentials.get(optionsWithoutPrf);
  }
  if (!assertion || !(assertion instanceof PublicKeyCredential)) return null;
  const credentialId = btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.rawId)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const ext = assertion.getClientExtensionResults();
  const prfResultRaw = ext.prf?.results?.first;
  if (prfResultRaw) {
    return { credentialId, prfResult: new Uint8Array(prfResultRaw) };
  }
  return { credentialId, useStoredKey: true };
}

export async function encryptKeypairWithPasskey(keypair, prfResult) {
  const key = await deriveKeyFromPrf(prfResult);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify({ privateJwk: keypair.privateJwk, publicJwk: keypair.publicJwk }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    encrypted: btoa(String.fromCharCode.apply(null, new Uint8Array(ct))),
    iv: btoa(String.fromCharCode.apply(null, iv)),
  };
}

export async function decryptKeypairWithPasskey(encryptedB64, ivB64, prfResult) {
  const key = await deriveKeyFromPrf(prfResult);
  const ct = new Uint8Array([...atob(encryptedB64)].map((c) => c.charCodeAt(0)));
  const iv = new Uint8Array([...atob(ivB64)].map((c) => c.charCodeAt(0)));
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(dec));
}

export async function storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64) {
  await db.storePasskeyCredential(credentialId, username, encrypted, iv, storedKeyB64);
}

export async function getPasskeyCredentialByCredentialId(credentialId) {
  return db.getPasskeyCredentialByCredentialId(credentialId);
}

export async function updatePasskeyCredentialUsername(credentialId, username) {
  return db.updatePasskeyCredentialUsername(credentialId, username);
}

export async function hasPasskeyCredentials() {
  return db.hasPasskeyCredentials();
}
