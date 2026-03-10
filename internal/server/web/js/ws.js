// War Chat - WebSocket (connect, register, incoming handlers, sendMessage)

import { state } from './state.js';
import * as db from './db.js';
import {
  decrypt,
  deriveSharedKey,
  importPubkeyFromBase64,
  exportPubkeyToBase64,
  encrypt,
  arrayBufferToBase64,
} from './crypto.js';
import * as api from './api.js';
import * as groups from './groups.js';
import { peerFromGroupId } from './groups.js';

let onMessageCallback = null;

export function setOnMessageCallback(cb) {
  onMessageCallback = cb;
}

function notify(payload) {
  if (onMessageCallback) onMessageCallback(payload);
}

function playNotificationSound() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    osc.frequency.value = 800;
    osc.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.1);
  } catch (_) {}
}

function maybeNotify(from, text) {
  if (typeof document !== 'undefined' && document.hidden && typeof Notification !== 'undefined') {
    if (Notification.permission === 'granted') {
      new Notification('Personal Chat', { body: 'Message from ' + from });
    } else if (Notification.permission === 'default') {
      Notification.requestPermission().then((p) => {
        if (p === 'granted') new Notification('Personal Chat', { body: 'Message from ' + from });
      });
    }
    playNotificationSound();
  }
}

export function connectWS() {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    registerWS();
    return;
  }
  const proto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = typeof window !== 'undefined' ? window.location.host : '';
  state.ws = new WebSocket(`${proto}//${host}/ws`);

  state.ws.onopen = () => registerWS();

  state.ws.onmessage = async (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'offline_messages') {
      for (const m of msg.messages || []) {
        await handleIncoming(m);
      }
      notify({ type: 'refresh-chat-list' });
    } else if (msg.type === 'incoming') {
      await handleIncoming(msg);
      notify({ type: 'refresh-chat-list' });
    } else if (msg.type === 'group_invite') {
      await handleGroupInvite(msg);
      notify({ type: 'refresh-chat-list' });
    } else if (msg.type === 'incoming_group') {
      await handleIncomingGroup(msg);
      notify({ type: 'refresh-chat-list' });
    }
  };

  state.ws.onclose = () => {
    setTimeout(connectWS, 3000);
  };
}

export async function registerWS() {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN || !state.currentUsername) return;
  const pubkey = state.keys ? await exportPubkeyToBase64(state.keys.publicKey) : '';
  state.ws.send(JSON.stringify({ type: 'register', username: state.currentUsername, pubkey }));
}

async function handleIncoming(msg) {
  if (msg.type === 'group_invite') {
    await handleGroupInvite(msg);
    return;
  }
  if (msg.type === 'incoming_group') {
    await handleIncomingGroup(msg);
    return;
  }
  if (msg.from === state.currentUsername) return;
  let text = '[encrypted]';
  try {
    const senderPubkeyB64 = await api.getRecipientPubkey(msg.from);
    const senderPub = await importPubkeyFromBase64(senderPubkeyB64);
    if (senderPub && state.keys) {
      const sharedKey = await deriveSharedKey(state.keys.privateKey, senderPub);
      text = await decrypt(msg.payload, msg.nonce, sharedKey);
    }
  } catch (e) {
    console.error(e);
  }
  const m = {
    id: msg.id || 'msg-' + Date.now(),
    from: msg.from,
    text,
    ts: msg.ts || Date.now(),
    peer: msg.from,
  };
  await db.saveMessage(m);
  const showInCurrentView = msg.from === state.currentRecipient;
  notify({ type: 'incoming-message', message: m, showInCurrentView, isNoteToSelf: m.peer === state.currentUsername });
  if (msg.from !== state.currentRecipient || (typeof document !== 'undefined' && document.hidden)) {
    maybeNotify(msg.from, text);
  }
  if (msg.id && state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: 'delivered', ids: [msg.id] }));
  }
}

async function handleGroupInvite(msg) {
  if (!state.keys || !msg.from || !msg.payload || !msg.nonce) return;
  try {
    const senderPubkeyB64 = await api.getRecipientPubkey(msg.from);
    const senderPub = await importPubkeyFromBase64(senderPubkeyB64);
    if (!senderPub) return;
    const sharedKey = await deriveSharedKey(state.keys.privateKey, senderPub);
    const plaintext = await decrypt(msg.payload, msg.nonce, sharedKey);
    const bundle = JSON.parse(plaintext);
    const groupId = bundle.groupId;
    if (!groupId) return;
    const existing = await db.getGroup(groupId);
    if (bundle.members && bundle.name) {
      await db.savePendingGroupInvite({
        id: groupId,
        from: msg.from,
        name: bundle.name,
        members: bundle.members,
        creator: bundle.creator || msg.from,
        senderKeys: bundle.senderKeys || {},
        ts: Date.now(),
      });
      maybeNotify(msg.from, 'Group invite: ' + bundle.name);
    } else if (existing && bundle.senderKeys) {
      existing.senderKeys = existing.senderKeys || {};
      Object.assign(existing.senderKeys, bundle.senderKeys);
      await db.saveGroup(existing);
    }
  } catch (e) {
    console.error('Group invite decrypt failed', e);
  }
}

async function handleIncomingGroup(msg) {
  const groupId = msg.groupId;
  if (!groupId || !msg.from || !msg.payload || !msg.nonce) return;
  const group = await db.getGroup(groupId);
  if (!group || !group.senderKeys || !group.senderKeys[msg.from]) return;
  let text = '[encrypted]';
  try {
    const senderKey = await groups.importSenderKeyFromBase64(group.senderKeys[msg.from]);
    text = await decrypt(msg.payload, msg.nonce, senderKey);
  } catch (e) {
    console.error('Group message decrypt failed', e);
  }
  const peer = peerFromGroupId(groupId);
  const m = {
    id: msg.id || 'msg-' + Date.now(),
    from: msg.from,
    text,
    ts: msg.ts || Date.now(),
    peer,
  };
  await db.saveMessage(m);
  const showInCurrentView = peer === state.currentRecipient;
  notify({ type: 'incoming-message', message: m, showInCurrentView, isNoteToSelf: false });
  if (peer !== state.currentRecipient || (typeof document !== 'undefined' && document.hidden)) {
    maybeNotify(msg.from + ' (group)', text);
  }
  if (msg.id && state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: 'delivered', ids: [msg.id] }));
  }
}

/**
 * Send a message. Caller is responsible for clearing input and re-rendering.
 * @param {string} text
 * @returns {Promise<{ message: object, refreshChatList: boolean } | null>}
 */
export async function sendMessage(text) {
  const currentRecipient = state.currentRecipient;
  const currentUsername = state.currentUsername;
  const keys = state.keys;
  const ws = state.ws;

  if (!text || !text.trim() || !currentRecipient || !keys) {
    return null;
  }

  const isSelf = currentRecipient === currentUsername;
  const isGroup = groups.isGroupPeer(currentRecipient);

  const m = {
    id: 'local-' + Date.now(),
    from: currentUsername,
    text: text.trim(),
    ts: Date.now(),
    peer: currentRecipient,
  };

  if (isSelf) {
    await db.saveMessage(m);
    return { message: m, isNoteToSelf: true, refreshChatList: true };
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return null;
  }

  if (isGroup) {
    const groupId = groups.groupPeerId(currentRecipient);
    let group = await db.getGroup(groupId);
    if (!group) {
      throw new Error('Group not found');
    }
    let senderKey = null;
    if (group.mySenderKeyB64) {
      senderKey = await groups.importSenderKeyFromBase64(group.mySenderKeyB64);
    } else {
      const { key, raw } = await groups.generateSenderKeyRaw();
      senderKey = key;
      group.mySenderKeyB64 = arrayBufferToBase64(raw);
      group.senderKeys = group.senderKeys || {};
      group.senderKeys[currentUsername] = group.mySenderKeyB64;
      await db.saveGroup(group);
      const failedMembers = [];
      for (const member of group.members) {
        if (member === currentUsername) continue;
        try {
          const pubkeyB64 = await api.getRecipientPubkey(member);
          const pub = await importPubkeyFromBase64(pubkeyB64);
          const sharedKey = await deriveSharedKey(keys.privateKey, pub);
          const bundle = { groupId, senderKeys: { [currentUsername]: group.mySenderKeyB64 } };
          const plaintext = JSON.stringify(bundle);
          const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
          const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
          const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
          ws.send(JSON.stringify({ type: 'group_invite', to: member, groupId, payload, nonce }));
        } catch (e) {
          console.error('Failed to send sender key to ' + member, e);
          failedMembers.push(member);
        }
      }
      if (failedMembers.length > 0) {
        throw new Error('Message will be sent, but these members could not receive your key: ' + failedMembers.join(', '));
      }
    }
    const { ciphertext, iv } = await encrypt(m.text, senderKey);
    const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
    const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
    ws.send(JSON.stringify({ type: 'group_send', groupId, payload, nonce }));
    await db.saveMessage(m);
    return { message: m, isNoteToSelf: false, refreshChatList: true };
  }

  const recipientPubkeyB64 = await api.getRecipientPubkey(currentRecipient);
  const recipientPub = await importPubkeyFromBase64(recipientPubkeyB64);
  if (!recipientPub) throw new Error('Could not load recipient key');
  const sharedKey = await deriveSharedKey(keys.privateKey, recipientPub);
  const { ciphertext, iv } = await encrypt(m.text, sharedKey);
  const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
  const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
  ws.send(JSON.stringify({ type: 'send', to: currentRecipient, payload, nonce }));
  await db.saveMessage(m);
  return { message: m, isNoteToSelf: false, refreshChatList: true };
}
