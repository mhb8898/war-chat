// War Chat - HTTP API (users, register, pubkey fetch)

import { state } from './state.js';
import { API_BASE } from './config.js';
import { exportPubkeyToBase64 } from './crypto.js';

export async function fetchUsers() {
  const resp = await fetch(`${API_BASE}/users`);
  if (!resp.ok) return [];
  const json = await resp.json();
  const currentUsername = state.currentUsername;
  return (json.users || []).filter((u) => u && u !== currentUsername).sort((a, b) => a.localeCompare(b));
}

export async function getRecipientPubkey(username) {
  if (state.pubkeyCache[username]) return state.pubkeyCache[username];
  const resp = await fetch(`${API_BASE}/keys/${encodeURIComponent(username)}`);
  if (!resp.ok) throw new Error('User not found');
  const json = await resp.json();
  state.pubkeyCache[username] = json.pubkey;
  return json.pubkey;
}

export async function fetchConfig() {
  try {
    const resp = await fetch(`${API_BASE}/config`);
    return resp.ok ? resp.json() : null;
  } catch { return null; }
}

export async function ensureRegisteredWithServer() {
  const currentUsername = state.currentUsername;
  const keys = state.keys;
  if (!currentUsername || !keys?.publicKey) return;
  const keysResp = await fetch(`${API_BASE}/keys/${encodeURIComponent(currentUsername)}`);
  if (keysResp.ok) return;
  if (keysResp.status !== 404) throw new Error('Server error checking registration');
  const pubkey = await exportPubkeyToBase64(keys.publicKey);
  const regResp = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: currentUsername, pubkey }),
  });
  if (regResp.status === 202) {
    throw new Error('pending_approval');
  }
  if (regResp.status === 409) {
    throw new Error('Username was taken by another user. Sign in with a different account.');
  }
  if (!regResp.ok) {
    const msg = await regResp.text();
    throw new Error(msg || 'Registration failed');
  }
}
