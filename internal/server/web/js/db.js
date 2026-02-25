// War Chat - IndexedDB access (messages, groups, sessions, keypairs, passkey credentials)

import { state } from './state.js';
import {
  DB_NAME,
  DB_VERSION,
  STORE_MSGS,
  STORE_GROUPS,
  STORE_PENDING_GROUP_INVITES,
  STORE_KEYPAIRS,
  STORE_PASSKEY_CREDS,
} from './config.js';
import { peerFromGroupId } from './groups.js';
import {
  encryptMessageForStorage,
  decryptMessageFromStorage,
} from './crypto-storage.js';

export function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      state.db = req.result;
      resolve(req.result);
    };
    req.onupgradeneeded = (e) => {
      const database = e.target.result;
      if (!database.objectStoreNames.contains(STORE_MSGS)) {
        database.createObjectStore(STORE_MSGS, { keyPath: 'id' });
      }
      if (!database.objectStoreNames.contains('keys')) {
        database.createObjectStore('keys', { keyPath: 'username' });
      }
      if (!database.objectStoreNames.contains(STORE_KEYPAIRS)) {
        database.createObjectStore(STORE_KEYPAIRS, { keyPath: 'seed' });
      }
      if (!database.objectStoreNames.contains('sessions')) {
        database.createObjectStore('sessions', { keyPath: 'username' });
      }
      if (!database.objectStoreNames.contains(STORE_PASSKEY_CREDS)) {
        database.createObjectStore(STORE_PASSKEY_CREDS, { keyPath: 'credentialId' });
      }
      if (!database.objectStoreNames.contains(STORE_GROUPS)) {
        database.createObjectStore(STORE_GROUPS, { keyPath: 'id' });
      }
      if (!database.objectStoreNames.contains(STORE_PENDING_GROUP_INVITES)) {
        database.createObjectStore(STORE_PENDING_GROUP_INVITES, { keyPath: 'id' });
      }
    };
  });
}

export async function saveMessage(msg) {
  const db = state.db;
  const currentUsername = state.currentUsername;
  if (!currentUsername || !db) return;
  const owner = currentUsername;
  const id = `${owner}:${msg.id}`;
  const enc = await encryptMessageForStorage(msg);
  if (!enc) {
    console.error('Message encryption failed - keys may not be ready');
    return;
  }
  const stored = { id, owner, encryptedPayload: enc.encryptedPayload, iv: enc.iv };
  const tx = db.transaction(STORE_MSGS, 'readwrite');
  tx.objectStore(STORE_MSGS).put(stored);
  return new Promise((resolve) => (tx.oncomplete = resolve));
}

export async function getMessages(peer) {
  const db = state.db;
  const currentUsername = state.currentUsername;
  if (!currentUsername || !db) return [];
  const raw = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  const byOwner = raw.filter((m) => m.owner === currentUsername);
  const decrypted = [];
  for (const r of byOwner) {
    const m = await decryptMessageFromStorage(r);
    if (m && m.peer === peer) decrypted.push(m);
  }
  let all = decrypted.sort((a, b) => a.ts - b.ts);
  if (peer === currentUsername) {
    const seen = new Set();
    all = all.filter((m) => {
      const key = m.text + '|' + m.ts;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  return all;
}

export async function getConversations() {
  const db = state.db;
  const currentUsername = state.currentUsername;
  if (!currentUsername || !db) return [];
  const raw = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  const byOwner = raw.filter((m) => m.owner === currentUsername);
  const byPeer = {};
  for (const r of byOwner) {
    const m = await decryptMessageFromStorage(r);
    if (!m) continue;
    const ts = Number(m.ts) || 0;
    const id = m.id || '';
    const cur = byPeer[m.peer];
    if (!cur || ts > cur.lastTs || (ts === cur.lastTs && id > cur.lastId)) {
      byPeer[m.peer] = { peer: m.peer, lastMsg: m.text, lastTs: ts, lastId: id };
    }
  }
  const groups = await getAllGroups();
  for (const g of groups) {
    const peer = peerFromGroupId(g.id);
    if (!byPeer[peer]) {
      byPeer[peer] = { peer, lastMsg: 'No messages', lastTs: g.createdAt || 0, lastId: '', groupName: g.name };
    } else {
      byPeer[peer].groupName = g.name;
    }
  }
  return Object.values(byPeer).sort((a, b) => b.lastTs - a.lastTs);
}

export async function saveGroup(record) {
  const db = state.db;
  if (!db) return;
  const store = db.transaction(STORE_GROUPS, 'readwrite').objectStore(STORE_GROUPS);
  store.put(record);
  return new Promise((resolve) => { store.transaction.oncomplete = resolve; });
}

export async function getGroup(groupId) {
  const db = state.db;
  if (!db) return null;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readonly');
    tx.objectStore(STORE_GROUPS).get(groupId).onsuccess = (e) => resolve(e.target.result || null);
    tx.onerror = () => reject(tx.error);
  });
}

export async function deleteGroup(groupId) {
  const db = state.db;
  if (!db) return;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readwrite');
    tx.objectStore(STORE_GROUPS).delete(groupId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getAllGroups() {
  const db = state.db;
  if (!db) return [];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_GROUPS, 'readonly');
    tx.objectStore(STORE_GROUPS).getAll().onsuccess = (e) => resolve(e.target.result || []);
    tx.onerror = () => reject(tx.error);
  });
}

export async function savePendingGroupInvite(inv) {
  const db = state.db;
  if (!db) return;
  const store = db.transaction(STORE_PENDING_GROUP_INVITES, 'readwrite').objectStore(STORE_PENDING_GROUP_INVITES);
  store.put(inv);
  return new Promise((resolve) => { store.transaction.oncomplete = resolve; });
}

export async function getPendingGroupInvites() {
  const db = state.db;
  if (!db) return [];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PENDING_GROUP_INVITES, 'readonly');
    tx.objectStore(STORE_PENDING_GROUP_INVITES).getAll().onsuccess = (e) => resolve(e.target.result || []);
    tx.onerror = () => reject(tx.error);
  });
}

export async function deletePendingGroupInvite(groupId) {
  const db = state.db;
  if (!db) return;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PENDING_GROUP_INVITES, 'readwrite');
    tx.objectStore(STORE_PENDING_GROUP_INVITES).delete(groupId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export function getSession(username) {
  const db = state.db;
  if (!db) return Promise.resolve(null);
  return new Promise((resolve) => {
    try {
      const tx = db.transaction('sessions', 'readonly');
      const req = tx.objectStore('sessions').get(username);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function saveSession(username, seedKey, mnemonic, authMethod, credentialId) {
  const db = state.db;
  if (!db) return;
  try {
    const tx = db.transaction('sessions', 'readwrite');
    const session = { username, seedKey: seedKey || 'passkey', authMethod: authMethod || 'mnemonic' };
    if (mnemonic) session.mnemonic = mnemonic;
    if (credentialId) session.credentialId = credentialId;
    tx.objectStore('sessions').put(session);
    await new Promise((resolve) => (tx.oncomplete = resolve));
  } catch (e) {
    console.error('Save session failed', e);
  }
}

export function getKeypair(seedKey) {
  const db = state.db;
  if (!db) return Promise.resolve(null);
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_KEYPAIRS, 'readonly');
    const req = tx.objectStore(STORE_KEYPAIRS).get(seedKey);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
}

export async function putKeypair(record) {
  const db = state.db;
  if (!db) return;
  const tx = db.transaction(STORE_KEYPAIRS, 'readwrite');
  tx.objectStore(STORE_KEYPAIRS).put(record);
  return new Promise((resolve) => (tx.oncomplete = resolve));
}

export function getPasskeyCredentialByCredentialId(credentialId) {
  const db = state.db;
  if (!db) return Promise.resolve(null);
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_PASSKEY_CREDS, 'readonly');
    const req = tx.objectStore(STORE_PASSKEY_CREDS).get(credentialId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
}

export async function storePasskeyCredential(credentialId, username, encryptedKeypair, iv, storedKeyB64) {
  const db = state.db;
  if (!db) return;
  const record = { credentialId, username: username || null, encryptedKeypair, iv };
  if (storedKeyB64 != null) record.storedKeyB64 = storedKeyB64;
  const tx = db.transaction(STORE_PASSKEY_CREDS, 'readwrite');
  tx.objectStore(STORE_PASSKEY_CREDS).put(record);
  await new Promise((resolve) => (tx.oncomplete = resolve));
}

export async function updatePasskeyCredentialUsername(credentialId, username) {
  const rec = await getPasskeyCredentialByCredentialId(credentialId);
  if (!rec) return;
  rec.username = username;
  const db = state.db;
  if (!db) return;
  const tx = db.transaction(STORE_PASSKEY_CREDS, 'readwrite');
  tx.objectStore(STORE_PASSKEY_CREDS).put(rec);
  await new Promise((resolve) => (tx.oncomplete = resolve));
}

export function hasPasskeyCredentials() {
  const db = state.db;
  if (!db) return Promise.resolve(false);
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_PASSKEY_CREDS, 'readonly');
    const req = tx.objectStore(STORE_PASSKEY_CREDS).count();
    req.onsuccess = () => resolve(req.result > 0);
    req.onerror = () => resolve(false);
  });
}

/** Raw getAll for messages (for migration). */
export function getAllMessagesRaw() {
  const db = state.db;
  if (!db) return Promise.resolve([]);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_MSGS, 'readonly');
    const req = tx.objectStore(STORE_MSGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

/** Put one message record (for migration). */
export async function putMessage(record) {
  const db = state.db;
  if (!db) return;
  const tx = db.transaction(STORE_MSGS, 'readwrite');
  tx.objectStore(STORE_MSGS).put(record);
  return new Promise((resolve) => (tx.oncomplete = resolve));
}
