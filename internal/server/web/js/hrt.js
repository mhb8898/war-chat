// War Chat - HRT (dumb hub) WebSocket: connect, join room, peer events, send/recv frames
//
// Flow is symmetric: there is no "incoming call". Both sides start a video chat with the other.
// - Alice clicks "Video chat" with Bob -> navigates to #video/bob, connects, joins room "alice:bob".
// - Bob clicks "Video chat" with Alice -> navigates to #video/alice, connects, joins same room "alice:bob".
// - Hub sends peer_joined to each when the other is in the room; media then flows both ways.

import { state } from './state.js';
import { navigate } from './router.js';

let hrtWs = null;
let currentPeer = null;
let userEndedCall = false;
let reconnectTimeoutId = null;
let reconnectBackoffMs = 1000;
const RECONNECT_BACKOFF_MAX_MS = 30000;
let onFrameCallback = null;
let onStatusCallback = null;
let onPeerJoinedCallback = null;
let onPeerLeftCallback = null;
let onConnectionClosedCallback = null;
let onEndCallCallback = null;

export function setOnFrame(cb) {
  onFrameCallback = cb;
}
export function setOnEndCall(cb) {
  onEndCallCallback = cb;
}

export function setOnStatus(cb) {
  onStatusCallback = cb;
}

export function setOnPeerJoined(cb) {
  onPeerJoinedCallback = cb;
}

export function setOnPeerLeft(cb) {
  onPeerLeftCallback = cb;
}

export function setOnConnectionClosed(cb) {
  onConnectionClosedCallback = cb;
}

function status(msg) {
  if (onStatusCallback) onStatusCallback(msg);
}

function getRoomId(peer) {
  const me = state.currentUsername || '';
  return [me, peer].sort().join(':');
}

function clearReconnectTimer() {
  if (reconnectTimeoutId != null) {
    clearTimeout(reconnectTimeoutId);
    reconnectTimeoutId = null;
  }
  reconnectBackoffMs = 1000;
}

function scheduleReconnect() {
  if (userEndedCall || !currentPeer) return;
  clearReconnectTimer();
  status('Connection lost. Reconnecting…');
  const delay = reconnectBackoffMs;
  reconnectBackoffMs = Math.min(reconnectBackoffMs * 2, RECONNECT_BACKOFF_MAX_MS);
  reconnectTimeoutId = setTimeout(() => {
    reconnectTimeoutId = null;
    connect();
  }, delay);
}

function connect() {
  if (userEndedCall || !currentPeer) return;
  const roomId = getRoomId(currentPeer);
  const proto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = typeof window !== 'undefined' ? window.location.host : '';

  if (hrtWs && hrtWs.readyState === WebSocket.OPEN) return;
  if (hrtWs) {
    hrtWs.onclose = null;
    hrtWs.onerror = null;
    hrtWs.close();
    hrtWs = null;
  }

  status(reconnectTimeoutId == null ? 'Connecting…' : 'Reconnecting…');
  hrtWs = new WebSocket(`${proto}//${host}/hrt/v1`);

  hrtWs.onopen = () => {
    hrtWs.send(JSON.stringify({
      type: 'join',
      roomId,
      username: state.currentUsername,
    }));
    clearReconnectTimer();
    status('Waiting for peer…');
  };

  hrtWs.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      if (onFrameCallback) {
        try {
          const view = new DataView(e.data);
          if (view.byteLength < 7) return;
          const streamType = view.getUint8(0);
          const flags = view.getUint8(1);
          const fromLen = view.getUint8(2);
          if (3 + fromLen + 4 > view.byteLength) return;
          const fromBytes = new Uint8Array(e.data, 3, fromLen);
          const from = new TextDecoder().decode(fromBytes);
          const payloadLen = view.getUint32(3 + fromLen, true);
          if (3 + fromLen + 4 + payloadLen > view.byteLength) return;
          const payload = e.data.slice(3 + fromLen + 4, 3 + fromLen + 4 + payloadLen);
          const streamNames = ['video', 'audio', 'control'];
          const stream = streamNames[streamType] ?? 'data';
          onFrameCallback({
            from,
            to: currentPeer,
            stream,
            isKeyframe: (flags & 1) !== 0,
            payload,
          });
        } catch (_) {}
      }
      return;
    }
    try {
      const msg = JSON.parse(e.data);
      switch (msg.type) {
        case 'joined':
          status(msg.peers && msg.peers.length > 0 ? 'Connected' : 'Waiting for peer…');
          if (msg.peers && msg.peers.length > 0 && onPeerJoinedCallback) {
            onPeerJoinedCallback(msg.peers[0]);
          }
          break;
        case 'peer_joined':
          status('Connected');
          if (onPeerJoinedCallback) onPeerJoinedCallback(msg.username);
          break;
        case 'peer_left':
          status('Peer left');
          if (onPeerLeftCallback) onPeerLeftCallback(msg.username);
          break;
        case 'frame':
          if (onFrameCallback) {
            onFrameCallback({
              from: msg.from,
              to: msg.to,
              stream: msg.stream,
              isKeyframe: msg.isKeyframe,
              payload: msg.payload,
            });
          }
          break;
        default:
          break;
      }
    } catch (_) {}
  };

  hrtWs.onclose = () => {
    hrtWs = null;
    if (userEndedCall || !currentPeer) {
      status('Disconnected');
      if (onPeerLeftCallback) onPeerLeftCallback(null);
      return;
    }
    if (onConnectionClosedCallback) {
      try { onConnectionClosedCallback(); } catch (_) {}
    }
    scheduleReconnect();
  };

  hrtWs.onerror = () => {
    if (userEndedCall || !currentPeer) return;
    status('Connection error');
  };
}

/**
 * Start a video call with peer. Connects to /hrt/v1, joins room, notifies when peer joins/leaves.
 * @param {string} peer - Other username (1:1)
 */
export function startVideoCall(peer) {
  if (hrtWs && hrtWs.readyState === WebSocket.OPEN) {
    endVideoCall();
  }

  userEndedCall = false;
  currentPeer = peer;
  connect();
}

const STREAM_VIDEO = 0;
const STREAM_AUDIO = 1;
const STREAM_CONTROL = 2;

/**
 * Send a frame to the hub. Payload can be string (e.g. base64) or any JSON-serializable value.
 */
export function sendFrame(to, stream, payload, isKeyframe = false) {
  if (!hrtWs || hrtWs.readyState !== WebSocket.OPEN) return;
  hrtWs.send(JSON.stringify({
    to,
    stream: stream || 'data',
    isKeyframe: !!isKeyframe,
    payload,
  }));
}

/**
 * Send a binary frame (video/audio) to reduce bandwidth. streamType: 0=video, 1=audio.
 * payload is ArrayBuffer or Uint8Array.
 */
export function sendFrameBinary(to, streamType, payload, isKeyframe = false) {
  if (!hrtWs || hrtWs.readyState !== WebSocket.OPEN) return;
  const toBytes = new TextEncoder().encode(to);
  if (toBytes.length > 255) return;
  const payloadArray = payload instanceof ArrayBuffer ? new Uint8Array(payload) : payload;
  const payloadLen = payloadArray.byteLength;
  const total = 7 + toBytes.length + payloadLen;
  const buf = new ArrayBuffer(total);
  const view = new DataView(buf);
  view.setUint8(0, streamType);
  view.setUint8(1, isKeyframe ? 1 : 0);
  view.setUint8(2, toBytes.length);
  new Uint8Array(buf).set(toBytes, 3);
  view.setUint32(3 + toBytes.length, payloadLen, true);
  new Uint8Array(buf).set(payloadArray, 7 + toBytes.length);
  hrtWs.send(buf);
}

/** Get current peer username (other side of the call). */
export function getCurrentPeer() {
  return currentPeer;
}

/** Whether HRT is connected and in a call. */
export function isInCall() {
  return hrtWs != null && hrtWs.readyState === WebSocket.OPEN;
}

/** End the video call, close connection, navigate back to chats. */
export function endVideoCall() {
  userEndedCall = true;
  clearReconnectTimer();
  if (onEndCallCallback) {
    try { onEndCallCallback(); } catch (_) {}
    onEndCallCallback = null;
  }
  if (hrtWs) {
    hrtWs.onclose = null;
    hrtWs.onerror = null;
    hrtWs.close();
    hrtWs = null;
  }
  currentPeer = null;
  status('Ended');
  navigate('chats');
}
