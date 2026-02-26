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
let onFrameCallback = null;
let onStatusCallback = null;
let onPeerJoinedCallback = null;
let onPeerLeftCallback = null;
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

function status(msg) {
  if (onStatusCallback) onStatusCallback(msg);
}

function getRoomId(peer) {
  const me = state.currentUsername || '';
  return [me, peer].sort().join(':');
}

/**
 * Start a video call with peer. Connects to /hrt/v1, joins room, notifies when peer joins/leaves.
 * @param {string} peer - Other username (1:1)
 */
export function startVideoCall(peer) {
  if (hrtWs && hrtWs.readyState === WebSocket.OPEN) {
    endVideoCall();
  }

  currentPeer = peer;
  const roomId = getRoomId(peer);
  const proto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = typeof window !== 'undefined' ? window.location.host : '';

  status('Connecting…');
  hrtWs = new WebSocket(`${proto}//${host}/hrt/v1`);

  hrtWs.onopen = () => {
    hrtWs.send(JSON.stringify({
      type: 'join',
      roomId,
      username: state.currentUsername,
    }));
    status('Waiting for peer…');
  };

  hrtWs.onmessage = (e) => {
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
    status('Disconnected');
    if (onPeerLeftCallback) onPeerLeftCallback(null);
  };

  hrtWs.onerror = () => {
    status('Connection error');
  };
}

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
  if (onEndCallCallback) {
    try { onEndCallCallback(); } catch (_) {}
    onEndCallCallback = null;
  }
  if (hrtWs) {
    hrtWs.close();
    hrtWs = null;
  }
  currentPeer = null;
  status('Ended');
  navigate('chats');
}
