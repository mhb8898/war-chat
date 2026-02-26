// War Chat - HRT media: getUserMedia, WebCodecs encode/decode, render to canvas.
// Low latency: 30fps, realtime encoder, H.264 with Annex B (no description needed).

import * as hrt from './hrt.js';

const VIDEO_WIDTH = 640;
const VIDEO_HEIGHT = 360;
const VIDEO_FPS = 30;
const KEYFRAME_INTERVAL = 30; // keyframe every 1s at 30fps
const VIDEO_BITRATE = 400_000;

let localStream = null;
let videoEncoder = null;
let videoDecoder = null;
let encodeFrameCount = 0;
let requestKeyframe = false;
let peerUsername = null;
let rafId = null;
let decoderConfigured = false;
let decodeTimestamp = 0;
/** Codec used for encode (e.g. 'vp8' or 'avc1.42E01E'); decoder must match. */
let selectedCodec = 'vp8';
/** True until we've successfully decoded a key frame (decoder requires key after configure). */
let decoderNeedsKeyframe = true;
let lastKeyframeRequestTs = 0;
/** Codec the remote peer is using (received via control); decoder must use this, not selectedCodec. */
let remoteCodec = null;

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function getCanvasContext() {
  const canvas = document.getElementById('videoRemoteCanvas');
  if (!canvas) return null;
  canvas.width = VIDEO_WIDTH;
  canvas.height = VIDEO_HEIGHT;
  return canvas.getContext('2d');
}

function drawFrame(frame) {
  const ctx = getCanvasContext();
  if (!ctx || !frame) return;
  try {
    ctx.drawImage(frame, 0, 0, VIDEO_WIDTH, VIDEO_HEIGHT);
  } finally {
    frame.close();
  }
}

function setupDecoder() {
  if (videoDecoder) return;
  if (typeof VideoDecoder === 'undefined') return;

  videoDecoder = new VideoDecoder({
    output: (frame) => {
      drawFrame(frame);
    },
    error: (e) => {
      console.warn('VideoDecoder error:', e);
      videoDecoder = null;
      decoderConfigured = false;
    },
  });
}

function decodeIncoming(data, type) {
  if (typeof VideoDecoder === 'undefined' || typeof EncodedVideoChunk === 'undefined') return;
  setupDecoder();

  const buf = typeof data === 'string' ? base64ToArrayBuffer(data) : data;
  decodeTimestamp += 1000;

  if (!decoderConfigured) {
    if (!remoteCodec) return;
    const codecForDecode = remoteCodec;
    const baseConfig = {
      codec: codecForDecode,
      codedWidth: VIDEO_WIDTH,
      codedHeight: VIDEO_HEIGHT,
    };
    try {
      videoDecoder.configure(baseConfig);
      decoderConfigured = true;
      decoderNeedsKeyframe = true;
    } catch (err) {
      console.warn('VideoDecoder configure failed:', err);
      videoDecoder = null;
      decoderConfigured = false;
      return;
    }
  }

  if (videoDecoder && videoDecoder.state === 'closed') {
    videoDecoder = null;
    decoderConfigured = false;
    return;
  }

  if (decoderNeedsKeyframe && type !== 'key') {
    const now = performance.now();
    if (peerUsername && now - lastKeyframeRequestTs > 500) {
      lastKeyframeRequestTs = now;
      hrt.sendFrame(peerUsername, 'control', { t: 'keyframe' });
    }
    return;
  }

  function tryDecode(chunkType) {
    const chunk = new EncodedVideoChunk({
      type: chunkType,
      timestamp: decodeTimestamp,
      data: buf,
    });
    videoDecoder.decode(chunk);
  }

  try {
    const chunkType = type === 'key' ? 'key' : 'delta';
    tryDecode(chunkType);
    if (chunkType === 'key') decoderNeedsKeyframe = false;
  } catch (e) {
    const needKey = e?.message?.includes('key frame is required') ||
      e?.message?.includes("wasn't a key frame") ||
      e?.message?.includes('marked as type');
    if (needKey) decoderNeedsKeyframe = true;
    if (type === 'key') {
      const now = performance.now();
      if (peerUsername && now - lastKeyframeRequestTs > 500) {
        lastKeyframeRequestTs = now;
        hrt.sendFrame(peerUsername, 'control', { t: 'keyframe' });
      }
    }
    console.warn('Decode error:', e);
  }
}

function handleFrame(msg) {
  if (msg.stream === 'video' && msg.payload != null) {
    decodeIncoming(msg.payload, msg.isKeyframe ? 'key' : 'delta');
  }
  if (msg.stream === 'control' && msg.payload && typeof msg.payload === 'object') {
    if (msg.payload.t === 'keyframe') requestKeyframe = true;
    if (msg.payload.t === 'codec' && msg.payload.codec) {
      remoteCodec = msg.payload.codec;
      if (decoderConfigured && videoDecoder) {
        try { videoDecoder.close(); } catch (_) {}
        videoDecoder = null;
        decoderConfigured = false;
      }
    }
  }
}

function encodeAndSend(videoEl) {
  if (!videoEncoder || !peerUsername || videoEl.readyState < 2) return;

  const forceKeyframe = requestKeyframe || encodeFrameCount < 3 || (encodeFrameCount % KEYFRAME_INTERVAL === 0);
  if (requestKeyframe) requestKeyframe = false;

  let frame;
  try {
    frame = new VideoFrame(videoEl, { timestamp: performance.now() * 1000 });
    videoEncoder.encode(frame, { keyFrame: forceKeyframe }).then(
      () => { frame.close(); },
      () => { try { frame.close(); } catch (_) {} }
    );
    encodeFrameCount++;
  } catch (_) {
    if (frame) try { frame.close(); } catch (_) {}
  }
}

function startEncodeLoop(videoEl) {
  const intervalMs = Math.round(1000 / VIDEO_FPS);
  rafId = setInterval(() => {
    encodeAndSend(videoEl);
  }, intervalMs);
}

function stopEncodeLoop() {
  if (rafId != null) {
    clearInterval(rafId);
    rafId = null;
  }
  encodeFrameCount = 0;
  requestKeyframe = false;
}

/**
 * Start local media (video), attach to preview, encode and send to peer via HRT.
 * Call when video view is shown and HRT has joined. Registers with hrt for frames and hangup.
 */
export function startLocalMedia(peer) {
  peerUsername = peer;

  const statusEl = document.getElementById('videoStatus');
  const localPreview = document.getElementById('videoLocalPreview');
  const btnMute = document.getElementById('videoBtnMute');
  const btnCamera = document.getElementById('videoBtnCamera');
  const btnHangup = document.getElementById('videoBtnHangup');

  if (!localPreview) return;

  const updateStatus = (text) => {
    if (statusEl) statusEl.textContent = text;
  };

  hrt.setOnStatus(updateStatus);
  hrt.setOnFrame(handleFrame);
  async function maybeStartEncoder() {
    if (!peerUsername || !localStream || videoEncoder) return;
    if (typeof VideoEncoder === 'undefined') {
      updateStatus('Connected (video encode not supported in this browser)');
      return;
    }
    const config = {
      width: VIDEO_WIDTH,
      height: VIDEO_HEIGHT,
      bitrate: VIDEO_BITRATE,
      framerate: VIDEO_FPS,
      codec: null, // set per tryCodec
    };
    const tryCodec = async (codec) => {
      const cfg = { ...config, codec };
      const supported = await VideoEncoder.isConfigSupported(cfg);
      if (supported?.supported) return codec;
      return null;
    };
    // Prefer H.264 on Mac (often HW-accelerated); fallback to VP8
    selectedCodec = (await tryCodec('avc1.42E01E')) || (await tryCodec('vp8')) || null;
    if (!selectedCodec) {
      updateStatus('No supported video codec (H.264/VP8 required)');
      return;
    }
    try {
      videoEncoder = new VideoEncoder({
        output: (chunk) => {
          let buf;
          if (chunk.byteLength > 0 && typeof chunk.copyTo === 'function') {
            buf = new ArrayBuffer(chunk.byteLength);
            chunk.copyTo(buf);
          } else {
            buf = new ArrayBuffer(0);
          }
          const b64 = arrayBufferToBase64(buf);
          hrt.sendFrame(peerUsername, 'video', b64, chunk.type === 'key');
        },
        error: (e) => console.warn('VideoEncoder error:', e),
      });
      const encoderConfig = {
        width: VIDEO_WIDTH,
        height: VIDEO_HEIGHT,
        bitrate: VIDEO_BITRATE,
        framerate: VIDEO_FPS,
        codec: selectedCodec,
        latencyMode: 'realtime', // minimizes encode latency (no B-frames, no lookahead)
      };
      if (selectedCodec.startsWith('avc1.') || selectedCodec.startsWith('avc3.')) {
        encoderConfig.avc = { format: 'annexb' };
      }
      try {
        videoEncoder.configure(encoderConfig);
      } catch (_) {
        delete encoderConfig.latencyMode;
        if (encoderConfig.avc) delete encoderConfig.avc;
        videoEncoder.configure(encoderConfig);
      }
      hrt.sendFrame(peerUsername, 'control', { t: 'codec', codec: selectedCodec });
      startEncodeLoop(localPreview);
      updateStatus('Connected');
    } catch (e) {
      updateStatus('Video encode not supported: ' + (e?.message || 'WebCodecs required'));
    }
  }

  hrt.setOnPeerJoined((joinedPeer) => {
    peerUsername = joinedPeer;
    maybeStartEncoder();
  });
  hrt.setOnPeerLeft(() => {
    peerUsername = null;
    remoteCodec = null;
    stopEncodeLoop();
    if (videoEncoder) {
      try { videoEncoder.close(); } catch (_) {}
      videoEncoder = null;
    }
    updateStatus('Peer left');
  });
  hrt.setOnEndCall(stopLocalMedia);

  if (btnHangup) {
    btnHangup.onclick = () => hrt.endVideoCall();
  }

  let videoEnabled = true;
  if (btnCamera) {
    btnCamera.onclick = () => {
      videoEnabled = !videoEnabled;
      if (localStream) {
        localStream.getVideoTracks().forEach((t) => { t.enabled = videoEnabled; });
      }
      btnCamera.textContent = videoEnabled ? 'Camera' : 'Camera off';
    };
  }
  if (btnMute) {
    btnMute.onclick = () => {
      if (localStream) {
        localStream.getAudioTracks().forEach((t) => { t.enabled = !t.enabled; });
      }
    };
  }

  navigator.mediaDevices.getUserMedia({ video: { width: VIDEO_WIDTH, height: VIDEO_HEIGHT, frameRate: { max: VIDEO_FPS } }, audio: true })
    .then((stream) => {
      localStream = stream;
      localPreview.srcObject = stream;
      updateStatus('Waiting for peer…');
      maybeStartEncoder();
    })
    .catch((err) => {
      updateStatus('Camera/mic error: ' + (err?.message || 'Permission denied'));
    });
}

/**
 * Stop local media, release tracks and encoders/decoders.
 */
export function stopLocalMedia() {
  stopEncodeLoop();
  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  const localPreview = document.getElementById('videoLocalPreview');
  if (localPreview) localPreview.srcObject = null;
  if (videoEncoder) {
    try { videoEncoder.close(); } catch (_) {}
    videoEncoder = null;
  }
  if (videoDecoder) {
    try { videoDecoder.close(); } catch (_) {}
    videoDecoder = null;
  }
  decoderConfigured = false;
  decoderNeedsKeyframe = true;
  lastKeyframeRequestTs = 0;
  remoteCodec = null;
  peerUsername = null;
  decodeTimestamp = 0;

  const canvas = document.getElementById('videoRemoteCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
  }
}
