// War Chat - unit tests for renderGroupInvites (empty list clears DOM)
// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as db from './db.js';
import { renderGroupInvites } from './app.js';

vi.mock('./db.js', () => ({
  getPendingGroupInvites: vi.fn(),
  getConversations: vi.fn(() => Promise.resolve([])),
  getGroup: vi.fn(() => Promise.resolve(null)),
  saveGroup: vi.fn(() => Promise.resolve()),
  deletePendingGroupInvite: vi.fn(() => Promise.resolve()),
  saveMessage: vi.fn(() => Promise.resolve()),
  openDB: vi.fn(() => Promise.resolve()),
  getSession: vi.fn(() => Promise.resolve(null)),
  getMessages: vi.fn(() => Promise.resolve([])),
  getAllGroups: vi.fn(() => Promise.resolve([])),
}));

describe('renderGroupInvites', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = `
      <div id="group-invites-section" class="">
        <ul id="group-invites-list">
          <li>old invite row</li>
        </ul>
      </div>
    `;
  });

  it('clears list and hides section when there are no invites', async () => {
    db.getPendingGroupInvites.mockResolvedValue([]);
    await renderGroupInvites();
    const section = document.getElementById('group-invites-section');
    const listEl = document.getElementById('group-invites-list');
    expect(section).toBeTruthy();
    expect(section.classList.contains('hidden')).toBe(true);
    expect(listEl.innerHTML).toBe('');
    expect(listEl.querySelectorAll('li')).toHaveLength(0);
  });

  it('shows section and populates list when invites exist', async () => {
    db.getPendingGroupInvites.mockResolvedValue([
      { id: 'g1', from: 'alice', name: 'Group 1', members: [], creator: 'alice', senderKeys: {}, ts: 1 },
    ]);
    await renderGroupInvites();
    const section = document.getElementById('group-invites-section');
    const listEl = document.getElementById('group-invites-list');
    expect(section.classList.contains('hidden')).toBe(false);
    expect(listEl.querySelectorAll('li.group-invite-row')).toHaveLength(1);
    expect(listEl.textContent).toContain('alice');
    expect(listEl.textContent).toContain('Group 1');
  });
});
