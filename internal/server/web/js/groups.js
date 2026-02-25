// War Chat - group logic (create, invite, add member, leave, accept/decline)

import { state } from './state.js';
import { GROUP_PEER_PREFIX } from './config.js';
import * as db from './db.js';
import {
  encrypt,
  deriveSharedKey,
  importPubkeyFromBase64,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './crypto.js';
import * as api from './api.js';

export function isGroupPeer(peer) {
  return typeof peer === 'string' && peer.startsWith(GROUP_PEER_PREFIX);
}

export function groupPeerId(peer) {
  return isGroupPeer(peer) ? peer.slice(GROUP_PEER_PREFIX.length) : null;
}

export function peerFromGroupId(groupId) {
  return GROUP_PEER_PREFIX + groupId;
}

export async function generateSenderKeyRaw() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { key, raw };
}

export async function importSenderKeyFromBase64(b64) {
  const raw = base64ToArrayBuffer(b64);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Create a group and send invites. Caller should close modal and navigate.
 * @param {string} groupName
 * @param {string[]} memberUsernames - including current user (state.currentUsername)
 */
export async function createGroup(groupName, memberUsernames) {
  const keys = state.keys;
  const currentUsername = state.currentUsername;
  const ws = state.ws;
  if (!keys || !currentUsername || !ws || ws.readyState !== WebSocket.OPEN) {
    throw new Error('Not connected. Try again.');
  }
  if (memberUsernames.length < 2) {
    throw new Error('Add at least one member');
  }
  const groupId = crypto.randomUUID();
  ws.send(JSON.stringify({ type: 'create_group', groupId, name: groupName, members: memberUsernames }));

  const { key: mySenderKey, raw: mySenderKeyRaw } = await generateSenderKeyRaw();
  const mySenderKeyB64 = arrayBufferToBase64(mySenderKeyRaw);

  for (const member of memberUsernames) {
    if (member === currentUsername) continue;
    try {
      const pubkeyB64 = await api.getRecipientPubkey(member);
      const pub = await importPubkeyFromBase64(pubkeyB64);
      const sharedKey = await deriveSharedKey(keys.privateKey, pub);
      const bundle = {
        groupId,
        name: groupName,
        members: memberUsernames,
        creator: currentUsername,
        senderKeys: { [currentUsername]: mySenderKeyB64 },
      };
      const plaintext = JSON.stringify(bundle);
      const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
      const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
      const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
      ws.send(JSON.stringify({ type: 'group_invite', to: member, groupId, payload, nonce }));
    } catch (e) {
      console.error('Failed to send invite to ' + member, e);
      throw new Error(`"${member}" could not be invited (user not found). They must register first.`);
    }
  }

  await db.saveGroup({
    id: groupId,
    name: groupName,
    members: memberUsernames,
    createdBy: currentUsername,
    createdAt: Date.now(),
    mySenderKeyB64,
    senderKeys: {},
  });

  return { groupId, groupName };
}

/**
 * Add one member to the current group. Caller should close modal and re-render.
 * @param {string} newMemberUsername
 */
export async function addMemberToGroup(newMemberUsername) {
  const currentRecipient = state.currentRecipient;
  if (!isGroupPeer(currentRecipient)) throw new Error('Not a group');
  const groupId = groupPeerId(currentRecipient);
  const group = await db.getGroup(groupId);
  const ws = state.ws;
  const keys = state.keys;
  if (!group || !ws || ws.readyState !== WebSocket.OPEN || !keys) {
    throw new Error('Not connected or group not found');
  }
  const newMembers = [...group.members, newMemberUsername];
  ws.send(JSON.stringify({ type: 'update_group', groupId, members: newMembers }));

  const senderKeysBundle = { ...(group.senderKeys || {}) };
  if (group.mySenderKeyB64) {
    senderKeysBundle[state.currentUsername] = group.mySenderKeyB64;
  }

  try {
    const pubkeyB64 = await api.getRecipientPubkey(newMemberUsername);
    const pub = await importPubkeyFromBase64(pubkeyB64);
    const sharedKey = await deriveSharedKey(keys.privateKey, pub);
    const bundle = {
      groupId,
      name: group.name,
      members: newMembers,
      creator: group.createdBy,
      senderKeys: senderKeysBundle,
    };
    const plaintext = JSON.stringify(bundle);
    const { ciphertext, iv } = await encrypt(plaintext, sharedKey);
    const payload = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertext)));
    const nonce = btoa(String.fromCharCode.apply(null, new Uint8Array(iv)));
    ws.send(JSON.stringify({ type: 'group_invite', to: newMemberUsername, groupId, payload, nonce }));
  } catch (e) {
    console.error('Failed to send invite to ' + newMemberUsername, e);
  }

  group.members = newMembers;
  await db.saveGroup(group);
}

/**
 * Leave current group. Caller should navigate to chats.
 */
export async function leaveGroup() {
  const currentRecipient = state.currentRecipient;
  if (!isGroupPeer(currentRecipient)) return;
  const groupId = groupPeerId(currentRecipient);
  const group = await db.getGroup(groupId);
  const ws = state.ws;
  if (!group || !ws || ws.readyState !== WebSocket.OPEN) return;
  const newMembers = group.members.filter((m) => m !== state.currentUsername);
  ws.send(JSON.stringify({ type: 'update_group', groupId, members: newMembers }));
  await db.deleteGroup(groupId);
}

/**
 * Accept a group invite. Caller should re-render and navigate to the group chat.
 * @param {object} inv - { id, name, members, creator, senderKeys, from, ts }
 */
export async function acceptGroupInvite(inv) {
  await db.saveGroup({
    id: inv.id,
    name: inv.name,
    members: inv.members,
    createdBy: inv.creator,
    createdAt: inv.ts || Date.now(),
    mySenderKeyB64: null,
    senderKeys: inv.senderKeys || {},
  });
  await db.deletePendingGroupInvite(inv.id);
  const peer = peerFromGroupId(inv.id);
  try {
    await db.saveMessage({
      id: 'sys-join-' + Date.now(),
      from: '_system',
      text: 'You joined the group (invited by ' + inv.from + ').',
      ts: Date.now(),
      peer,
    });
  } catch (e) {
    console.warn('Could not save system message:', e);
  }
  return inv.id;
}

/**
 * Decline a group invite.
 * @param {string} groupId
 */
export async function declineGroupInvite(groupId) {
  await db.deletePendingGroupInvite(groupId);
}
