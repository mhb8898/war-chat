// War Chat - auth & session (restore, logout, derive keypair from mnemonic)

import { state } from './state.js';
import {
  SESSION_USER,
  SESSION_MNEMONIC,
  STORAGE_USER,
  PASSKEY_SESSION,
} from './config.js';
import * as db from './db.js';
import {
  mnemonicToSeed,
  generateKeypair,
  deriveP256KeypairFromSeed,
  exportPubkeyToBase64,
} from './crypto.js';
import * as passkey from './passkey.js';
import { clearMessageEncryptionKeyCache } from './crypto-storage.js';

export function isLoggedIn() {
  return !!(typeof sessionStorage !== 'undefined' && sessionStorage.getItem(SESSION_USER) && state.keys);
}

export function getStoredUsername() {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem(STORAGE_USER) || sessionStorage.getItem(SESSION_USER);
}

export function setStoredUsername(username) {
  if (typeof localStorage === 'undefined') return;
  if (username) {
    localStorage.setItem(STORAGE_USER, username);
    sessionStorage.setItem(SESSION_USER, username);
  } else {
    localStorage.removeItem(STORAGE_USER);
    sessionStorage.removeItem(SESSION_USER);
  }
}

export function restorePasskeySessionFromStorage() {
  try {
    const raw = sessionStorage.getItem(PASSKEY_SESSION);
    if (!raw) return false;
    const { username, privateJwk, publicJwk } = JSON.parse(raw);
    if (!username || !privateJwk || !publicJwk) return false;
    return { username, privateJwk, publicJwk };
  } catch {
    return false;
  }
}

export function savePasskeySessionToStorage(username, privateJwk, publicJwk) {
  sessionStorage.setItem(PASSKEY_SESSION, JSON.stringify({ username, privateJwk, publicJwk }));
}

/** Derive keypair from mnemonic; cache in IDB. */
export async function deriveKeypair(mnemonic) {
  const seed = await mnemonicToSeed(mnemonic);
  const seedKey = btoa(String.fromCharCode.apply(null, seed));

  const stored = await db.getKeypair(seedKey);

  if (stored && stored.privateJwk && stored.publicJwk) {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      stored.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      stored.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    return { privateKey, publicKey, seedKey };
  }

  const kp = await deriveP256KeypairFromSeed(seed);
  await db.putKeypair({ seed: seedKey, privateJwk: kp.privateJwk, publicJwk: kp.publicJwk });
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, seedKey };
}

/** Generate keypair for passkey (no storage). */
export async function generateKeypairForPasskey() {
  const kp = await generateKeypair();
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, privateJwk, publicJwk };
}

export async function restoreSession() {
  const username = getStoredUsername();
  if (!username) return false;
  const session = await db.getSession(username);
  if (!session || !session.seedKey) return false;
  if (session.authMethod === 'passkey') return false;
  const stored = await db.getKeypair(session.seedKey);
  if (!stored || !stored.privateJwk || !stored.publicJwk) return false;
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    stored.privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    stored.publicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  state.keys = { privateKey, publicKey };
  state.currentUsername = username;
  setStoredUsername(username);
  if (session.mnemonic) {
    sessionStorage.setItem(SESSION_MNEMONIC, session.mnemonic);
  }
  return true;
}

export async function restorePasskeySession() {
  const data = restorePasskeySessionFromStorage();
  if (!data) return false;
  try {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      data.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      data.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    state.keys = { privateKey, publicKey };
    state.currentUsername = data.username;
    setStoredUsername(data.username);
    return true;
  } catch {
    sessionStorage.removeItem(PASSKEY_SESSION);
    return false;
  }
}

export async function restoreSessionWithPasskeyFromResult(result) {
  if (!result) return false;
  const { credentialId, prfResult, useStoredKey } = result;
  const rec = await passkey.getPasskeyCredentialByCredentialId(credentialId);
  if (!rec || !rec.username) return false;
  let keypair;
  if (prfResult) {
    keypair = await passkey.decryptKeypairWithPasskey(rec.encryptedKeypair, rec.iv, prfResult);
  } else if (useStoredKey && rec.storedKeyB64) {
    const storedKey = new Uint8Array([...atob(rec.storedKeyB64)].map((c) => c.charCodeAt(0)));
    keypair = await passkey.decryptKeypairWithPasskey(rec.encryptedKeypair, rec.iv, storedKey);
  } else {
    return false;
  }
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    keypair.privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    keypair.publicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  state.keys = { privateKey, publicKey };
  state.currentUsername = rec.username;
  setStoredUsername(rec.username);
  savePasskeySessionToStorage(rec.username, keypair.privateJwk, keypair.publicJwk);
  await db.saveSession(rec.username, 'passkey', null, 'passkey', credentialId);
  return true;
}

/** Clear state only. Caller should navigate and re-render. */
export function logout() {
  state.keys = null;
  state.currentUsername = null;
  state.currentRecipient = null;
  setStoredUsername(null);
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.removeItem(SESSION_MNEMONIC);
    sessionStorage.removeItem(PASSKEY_SESSION);
    sessionStorage.removeItem('war-chat-redirect');
  }
  state.pubkeyCache = {};
  clearMessageEncryptionKeyCache();
  if (state.ws) {
    state.ws.close();
    state.ws = null;
  }
}

export async function saveSession(username, seedKey, mnemonic, authMethod, credentialId) {
  await db.saveSession(username, seedKey, mnemonic, authMethod, credentialId);
}
