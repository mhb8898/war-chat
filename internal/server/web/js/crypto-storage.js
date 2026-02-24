// War Chat - message encryption for local storage (key cache, encrypt/decrypt payloads)

import { state } from './state.js';
import { deriveMessageEncryptionKey } from './crypto.js';

let msgEncKeyCache = null;

export async function getMessageEncryptionKey() {
  const keys = state.keys;
  if (!keys?.privateKey || !keys?.publicKey) return null;
  if (msgEncKeyCache) return msgEncKeyCache;
  msgEncKeyCache = await deriveMessageEncryptionKey(keys.privateKey, keys.publicKey);
  return msgEncKeyCache;
}

export function clearMessageEncryptionKeyCache() {
  msgEncKeyCache = null;
}

export async function encryptMessageForStorage(msg) {
  const key = await getMessageEncryptionKey();
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify({ from: msg.from, text: msg.text, ts: msg.ts, peer: msg.peer }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    encryptedPayload: btoa(String.fromCharCode.apply(null, new Uint8Array(ct))),
    iv: btoa(String.fromCharCode.apply(null, iv)),
  };
}

export async function decryptMessageFromStorage(record) {
  if (record.encryptedPayload && record.iv) {
    const key = await getMessageEncryptionKey();
    if (!key) return null;
    try {
      const ct = new Uint8Array([...atob(record.encryptedPayload)].map((c) => c.charCodeAt(0)));
      const iv = new Uint8Array([...atob(record.iv)].map((c) => c.charCodeAt(0)));
      const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      const payload = JSON.parse(new TextDecoder().decode(dec));
      return { id: record.id, owner: record.owner, ...payload };
    } catch {
      return null;
    }
  }
  return record;
}
