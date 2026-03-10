// War Chat - Meeting room: create, lobby (guest), admit panel (owner)

import { state } from './state.js';
import { API_BASE } from './config.js';

// --- API helpers ---

export async function createMeetingRoom() {
  const r = await fetch(`${API_BASE}/rooms`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ createdBy: state.currentUsername }),
  });
  if (!r.ok) throw new Error('Failed to create room');
  return r.json();
}

export async function getMeetingRoom(token) {
  const r = await fetch(`${API_BASE}/rooms/${token}`);
  if (!r.ok) return null;
  return r.json();
}

export async function sendKnock(token, displayName) {
  const r = await fetch(`${API_BASE}/rooms/${token}/knock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ displayName }),
  });
  if (!r.ok) throw new Error('Failed to knock');
  return r.json();
}

export async function pollKnockStatus(token, knockId) {
  const r = await fetch(`${API_BASE}/rooms/${token}/knock/${knockId}`);
  if (!r.ok) return null;
  return r.json();
}

export async function listPendingKnocks(token, ownerUsername) {
  const r = await fetch(`${API_BASE}/rooms/${token}/pending?ownerUsername=${encodeURIComponent(ownerUsername)}`);
  if (!r.ok) return [];
  return r.json();
}

export async function admitKnock(token, knockId, ownerUsername) {
  const r = await fetch(`${API_BASE}/rooms/${token}/admit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ knockId, ownerUsername }),
  });
  return r.ok;
}

export async function denyKnock(token, knockId, ownerUsername) {
  const r = await fetch(`${API_BASE}/rooms/${token}/deny`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ knockId, ownerUsername }),
  });
  return r.ok;
}

// --- New meeting modal ---

export async function showNewMeetingModal() {
  const modal = document.getElementById('newMeetingModal');
  const linkInput = document.getElementById('meetingLinkInput');
  const btnStart = document.getElementById('btnStartMeeting');
  const btnCopy = document.getElementById('btnCopyMeetingLink');
  if (!modal) return;

  if (linkInput) linkInput.value = 'Creating…';
  if (btnStart) btnStart.disabled = true;
  modal.setAttribute('open', '');

  let token = null;
  try {
    const data = await createMeetingRoom();
    token = data.token;
    const link = `${window.location.origin}/r/${token}`;
    if (linkInput) linkInput.value = link;
    if (btnStart) btnStart.disabled = false;
  } catch (e) {
    if (linkInput) linkInput.value = 'Error creating room';
    return;
  }

  if (btnCopy) {
    btnCopy.onclick = () => {
      navigator.clipboard.writeText(linkInput ? linkInput.value : '').catch(() => {});
    };
  }

  if (btnStart) {
    btnStart.onclick = () => {
      modal.removeAttribute('open');
      window.location.hash = `#room/${token}`;
    };
  }

  if (modal.onclick === null || !modal._meetingClickBound) {
    modal._meetingClickBound = true;
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.removeAttribute('open');
    });
  }
}

// --- Room view (owner or authenticated user) ---

export async function startRoomView(token) {
  const room = await getMeetingRoom(token);
  if (!room) {
    const statusEl = document.getElementById('videoStatus');
    if (statusEl) statusEl.textContent = 'Meeting room not found or expired.';
    return;
  }

  const [hrtMod, mediaMod] = await Promise.all([
    import('./hrt.js'),
    import('./hrt-media.js'),
  ]);
  hrtMod.startVideoCallWithRoomId(token);
  mediaMod.startLocalMedia(token);

  if (room.createdBy === state.currentUsername) {
    startAdmitPolling(token);
    const panel = document.getElementById('admitPanel');
    if (panel) panel.style.display = '';
  }
}

// --- Admit polling (owner) ---

let pendingPollId = null;

function startAdmitPolling(token) {
  const panel = document.getElementById('admitPanel');
  if (panel) panel.style.display = '';

  async function poll() {
    if (pendingPollId === null) return; // stopped
    const knocks = await listPendingKnocks(token, state.currentUsername).catch(() => []);
    const list = document.getElementById('admitList');
    if (list) {
      while (list.firstChild) list.removeChild(list.firstChild);
      for (const k of (knocks || [])) {
        const row = document.createElement('div');
        row.className = 'admit-row';

        const span = document.createElement('span');
        span.textContent = k.displayName + ' wants to join';

        const admitBtn = document.createElement('button');
        admitBtn.textContent = 'Admit';
        admitBtn.onclick = () => admitKnock(token, k.knockId, state.currentUsername).then(schedulePoll);

        const denyBtn = document.createElement('button');
        denyBtn.textContent = 'Deny';
        denyBtn.onclick = () => denyKnock(token, k.knockId, state.currentUsername).then(schedulePoll);

        row.append(span, admitBtn, denyBtn);
        list.appendChild(row);
      }
    }
    schedulePoll();
  }

  function schedulePoll() {
    if (pendingPollId !== null) clearTimeout(pendingPollId);
    pendingPollId = setTimeout(poll, 3000);
  }

  pendingPollId = 1; // mark as active before first call
  poll();
}

export function stopAdmitPolling() {
  if (pendingPollId != null) {
    clearTimeout(pendingPollId);
    pendingPollId = null;
  }
  const panel = document.getElementById('admitPanel');
  if (panel) panel.style.display = 'none';
}

// --- Lobby view (unauthenticated guest) ---

let knockPollId = null;

export async function startLobbyView(token) {
  const statusEl = document.getElementById('lobbyStatus');
  const lobbyForm = document.getElementById('lobbyForm');
  const nameInput = document.getElementById('lobbyName');
  const joinBtn = document.getElementById('btnLobbyJoin');
  const accountLink = document.querySelector('#view-lobby a[href="#setup"]');

  const room = await getMeetingRoom(token);
  if (!room) {
    if (statusEl) statusEl.textContent = 'This meeting link has expired or does not exist.';
    if (lobbyForm) lobbyForm.style.display = 'none';
    return;
  }

  if (accountLink) {
    accountLink.onclick = (e) => {
      e.preventDefault();
      sessionStorage.setItem('war-chat-room-redirect', token);
      window.location.hash = '#setup';
    };
  }

  if (joinBtn) {
    joinBtn.onclick = async () => {
      const displayName = nameInput ? nameInput.value.trim() : '';
      if (!displayName) {
        if (statusEl) statusEl.textContent = 'Please enter your name.';
        return;
      }
      if (lobbyForm) lobbyForm.style.display = 'none';
      if (statusEl) statusEl.textContent = 'Waiting for host to admit you…';

      let knockData;
      try {
        knockData = await sendKnock(token, displayName);
      } catch (e) {
        if (statusEl) statusEl.textContent = 'Failed to join. Please try again.';
        if (lobbyForm) lobbyForm.style.display = '';
        return;
      }

      const knockId = knockData.knockId;
      startKnockPolling(token, knockId, displayName);
    };
  }
}

function startKnockPolling(token, knockId, displayName) {
  const statusEl = document.getElementById('lobbyStatus');
  const lobbyForm = document.getElementById('lobbyForm');

  async function poll() {
    const data = await pollKnockStatus(token, knockId).catch(() => null);
    if (!data) {
      if (knockPollId !== null) {
        knockPollId = setTimeout(poll, 3000);
      }
      return;
    }
    if (data.status === 'admitted') {
      knockPollId = null;
      const [hrtMod, mediaMod, appMod] = await Promise.all([
        import('./hrt.js'),
        import('./hrt-media.js'),
        import('./app.js'),
      ]);
      hrtMod.startVideoCallAsGuest(token, knockId, displayName);
      mediaMod.startLocalMedia(token);
      appMod.showView('room', token);
    } else if (data.status === 'denied') {
      knockPollId = null;
      if (statusEl) statusEl.textContent = 'The host declined your request.';
      if (lobbyForm) lobbyForm.style.display = '';
    } else {
      if (knockPollId !== null) {
        knockPollId = setTimeout(poll, 3000);
      }
    }
  }

  knockPollId = 1; // mark active
  poll();
}

export function stopKnockPolling() {
  if (knockPollId != null) {
    clearTimeout(knockPollId);
    knockPollId = null;
  }
}
