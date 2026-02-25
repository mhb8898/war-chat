// War Chat - profile view (backup, restore, recovery phrase, add passkey)

import { state } from './state.js';
import { API_BASE, DB_NAME } from './config.js';
import { SESSION_MNEMONIC } from './config.js';
import * as auth from './auth.js';
import * as db from './db.js';
import * as passkey from './passkey.js';

let postRestoreCallback = null;

export function setPostRestoreCallback(cb) {
  postRestoreCallback = cb;
}

async function deriveBackupKey(mnemonic) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(mnemonic.trim().toLowerCase()),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('war-chat-backup'), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function showQR(text) {
  const container = document.getElementById('qrcode');
  if (!container) return;
  container.innerHTML = '';
  if (typeof window !== 'undefined' && typeof QRCode !== 'undefined') {
    new QRCode(container, { text, width: 128, height: 128 });
  }
}

async function getSessionAuthMethod() {
  const session = await db.getSession(state.currentUsername);
  return session?.authMethod || 'mnemonic';
}

export function renderProfile() {
  const profileUsername = document.getElementById('profileUsername');
  if (profileUsername) profileUsername.textContent = state.currentUsername || '';
  const link = `${API_BASE}/u/${state.currentUsername}`;
  const chatLink = document.getElementById('chatLink');
  if (chatLink) chatLink.textContent = link;
  showQR(link);
  const btnCopyLink = document.getElementById('btnCopyLink');
  if (btnCopyLink) btnCopyLink.onclick = () => {
    navigator.clipboard.writeText(link);
    alert('Link copied!');
  };
  getSessionAuthMethod().then(async (authMethod) => {
    const session = await db.getSession(state.currentUsername);
    const hasRecoveryPhrase = !!(session?.mnemonic || sessionStorage.getItem(SESSION_MNEMONIC));
    const recoverySection = document.getElementById('profile-recovery-section');
    const passkeySection = document.getElementById('profile-passkey-section');
    const addPasskeySection = document.getElementById('profile-add-passkey-section');
    const exportBackupBtn = document.getElementById('btnExportBackup');
    if (authMethod === 'passkey') {
      if (hasRecoveryPhrase) {
        if (recoverySection) recoverySection.classList.remove('hidden');
        if (passkeySection) passkeySection.classList.add('hidden');
        if (exportBackupBtn) { exportBackupBtn.disabled = false; exportBackupBtn.title = ''; }
      } else {
        if (recoverySection) recoverySection.classList.add('hidden');
        if (passkeySection) passkeySection.classList.remove('hidden');
        if (exportBackupBtn) { exportBackupBtn.disabled = true; exportBackupBtn.title = 'Add a recovery phrase first to export backup.'; }
      }
      if (addPasskeySection) addPasskeySection.classList.add('hidden');
    } else {
      if (recoverySection) recoverySection.classList.remove('hidden');
      if (passkeySection) passkeySection.classList.add('hidden');
      const pkSupported = await passkey.isPasskeySupported();
      if (addPasskeySection && pkSupported) addPasskeySection.classList.remove('hidden');
      else if (addPasskeySection) addPasskeySection.classList.add('hidden');
      if (exportBackupBtn) { exportBackupBtn.disabled = false; exportBackupBtn.title = ''; }
    }
  });
  const btnShowMnemonic = document.getElementById('btnShowMnemonic');
  if (btnShowMnemonic) btnShowMnemonic.onclick = async () => {
    let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
    if (!mnemonic) {
      const session = await db.getSession(state.currentUsername);
      mnemonic = session && session.mnemonic ? session.mnemonic : null;
    }
    const el = document.getElementById('mnemonicDisplay');
    if (mnemonic) {
      if (el) { el.textContent = mnemonic; el.classList.remove('hidden'); }
    } else {
      alert('Recovery phrase not stored. Log in with your phrase to store it.');
    }
  };
  const btnAddRecoveryPhrase = document.getElementById('btnAddRecoveryPhrase');
  if (btnAddRecoveryPhrase) btnAddRecoveryPhrase.onclick = addRecoveryPhraseForPasskeyUser;
  const btnAddPasskey = document.getElementById('btnAddPasskey');
  if (btnAddPasskey) btnAddPasskey.onclick = addPasskeyForMnemonicUser;
  const btnExportBackup = document.getElementById('btnExportBackup');
  if (btnExportBackup) btnExportBackup.onclick = exportBackup;
  const btnRestoreBackup = document.getElementById('btnRestoreBackup');
  if (btnRestoreBackup) btnRestoreBackup.onclick = restoreBackup;
  const btnDeleteMyAccount = document.getElementById('btnDeleteMyAccount');
  if (btnDeleteMyAccount) btnDeleteMyAccount.onclick = deleteMyAccount;
}

/** Delete the current user's account: remove from server so username can be reused, then clear local data and log out. */
async function deleteMyAccount() {
  if (!confirm('Delete your account? Your username will be removed from the server and all local data on this device will be cleared. You can create a new account with the same or different name later.')) return;
  const username = state.currentUsername;
  if (username) {
    try {
      const r = await fetch(`${API_BASE}/deregister`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      if (!r.ok) {
        const msg = await r.text();
        console.warn('Deregister failed:', msg);
      }
    } catch (e) {
      console.warn('Deregister request failed:', e);
    }
  }
  if (state.db) {
    state.db.close();
    state.db = null;
  }
  auth.logout();
  const req = indexedDB.deleteDatabase(DB_NAME);
  function reload() {
    window.location.reload();
  }
  req.onsuccess = reload;
  req.onerror = reload;
  req.onblocked = reload;
}

async function addRecoveryPhraseForPasskeyUser() {
  const mnemonic = prompt('Enter a 12-word recovery phrase (or generate one on the setup screen and paste it):');
  if (!mnemonic || !mnemonic.trim()) return;
  try {
    const backup = {
      username: state.currentUsername,
      privateJwk: await crypto.subtle.exportKey('jwk', state.keys.privateKey),
      publicJwk: await crypto.subtle.exportKey('jwk', state.keys.publicKey),
    };
    const key = await deriveBackupKey(mnemonic);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(backup))
    );
    const blob = JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
    navigator.clipboard.writeText(btoa(blob));
    sessionStorage.setItem(SESSION_MNEMONIC, mnemonic);
    const session = await db.getSession(state.currentUsername);
    if (session) {
      session.mnemonic = mnemonic;
      await db.saveSession(state.currentUsername, session.seedKey, mnemonic, session.authMethod, session.credentialId);
    }
    alert('Backup copied to clipboard. Save your phrase and backup in a safe place. You can now export backup.');
    renderProfile();
  } catch (e) {
    alert('Failed: ' + (e.message || e));
  }
}

async function addPasskeyForMnemonicUser() {
  try {
    const { credentialId, prfResult, storedKeyB64 } = await passkey.createPasskey(state.currentUsername);
    const privateJwk = await crypto.subtle.exportKey('jwk', state.keys.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', state.keys.publicKey);
    const { encrypted, iv } = await passkey.encryptKeypairWithPasskey({ privateJwk, publicJwk }, prfResult);
    await passkey.storePasskeyCredential(credentialId, state.currentUsername, encrypted, iv, storedKeyB64);
    alert('Passkey added. You can now sign in with passkey on this device.');
    renderProfile();
  } catch (e) {
    alert('Failed to add passkey: ' + (e.message || e));
  }
}

async function exportBackup() {
  let mnemonic = sessionStorage.getItem(SESSION_MNEMONIC);
  if (!mnemonic) {
    const session = await db.getSession(state.currentUsername);
    mnemonic = session && session.mnemonic ? session.mnemonic : null;
  }
  if (!mnemonic) {
    alert('Recovery phrase not stored. Use "Show recovery phrase" after logging in with your phrase.');
    return;
  }
  try {
    let privateJwk, publicJwk;
    if (state.keys) {
      privateJwk = await crypto.subtle.exportKey('jwk', state.keys.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', state.keys.publicKey);
    } else {
      const kp = await auth.deriveKeypair(mnemonic);
      privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    }
    const backup = { username: state.currentUsername, privateJwk, publicJwk };
    const key = await deriveBackupKey(mnemonic);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(backup))
    );
    const blob = JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
    navigator.clipboard.writeText(btoa(blob));
    alert('Backup copied to clipboard. Save it somewhere safe.');
  } catch (e) {
    alert('Export failed: ' + e.message);
  }
}

async function restoreBackup() {
  const mnemonic = prompt('Enter your 12-word phrase:');
  if (!mnemonic) return;
  const restoreBackupEl = document.getElementById('restoreBackup');
  const backupB64 = restoreBackupEl && restoreBackupEl.value.trim();
  if (!backupB64) return alert('Paste your backup first');
  try {
    const { iv, ct } = JSON.parse(atob(backupB64));
    const key = await deriveBackupKey(mnemonic);
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      new Uint8Array(ct)
    );
    const backup = JSON.parse(new TextDecoder().decode(dec));
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      backup.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits', 'deriveKey']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      backup.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    state.keys = { privateKey, publicKey };
    state.currentUsername = backup.username;
    auth.setStoredUsername(backup.username);
    const seed = await (await import('./crypto.js')).mnemonicToSeed(mnemonic);
    const seedKey = btoa(String.fromCharCode.apply(null, seed));
    await db.putKeypair({
      seed: seedKey,
      privateJwk: backup.privateJwk,
      publicJwk: backup.publicJwk,
    });
    const regResp = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: backup.username, pubkey: btoa(JSON.stringify(backup.publicJwk)) }),
    });
    if (!regResp.ok) {
      const msg = await regResp.text();
      throw new Error(msg || 'Registration failed');
    }
    if (restoreBackupEl) restoreBackupEl.value = '';
    alert('Restored!');
    const redirect = sessionStorage.getItem('war-chat-redirect');
    if (redirect) sessionStorage.removeItem('war-chat-redirect');
    if (postRestoreCallback) postRestoreCallback(redirect);
  } catch (e) {
    alert('Restore failed: ' + e.message);
  }
}
