// War Chat - unit tests for group accept/decline
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as db from './db.js';
import { acceptGroupInvite, declineGroupInvite } from './groups.js';

vi.mock('./db.js', () => ({
  saveGroup: vi.fn(() => Promise.resolve()),
  deletePendingGroupInvite: vi.fn(() => Promise.resolve()),
  saveMessage: vi.fn(() => Promise.resolve()),
}));

describe('groups', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('acceptGroupInvite', () => {
    it('saves group, deletes pending invite, saves system message, returns group id', async () => {
      const inv = {
        id: 'group-uuid-123',
        name: 'Test Group',
        members: ['alice', 'bob'],
        creator: 'alice',
        senderKeys: {},
        from: 'alice',
        ts: 1000,
      };
      const id = await acceptGroupInvite(inv);
      expect(id).toBe('group-uuid-123');
      expect(db.saveGroup).toHaveBeenCalledTimes(1);
      expect(db.saveGroup).toHaveBeenCalledWith(
        expect.objectContaining({
          id: inv.id,
          name: inv.name,
          members: inv.members,
          createdBy: inv.creator,
          mySenderKeyB64: null,
          senderKeys: {},
        })
      );
      expect(db.deletePendingGroupInvite).toHaveBeenCalledTimes(1);
      expect(db.deletePendingGroupInvite).toHaveBeenCalledWith(inv.id);
      expect(db.saveMessage).toHaveBeenCalledTimes(1);
      expect(db.saveMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          from: '_system',
          peer: 'group:group-uuid-123',
        })
      );
      const saveMessageArg = db.saveMessage.mock.calls[0][0];
      expect(saveMessageArg.text).toContain('You joined the group');
      expect(saveMessageArg.text).toContain('alice');
    });

    it('uses inv.ts for createdAt when provided', async () => {
      const inv = {
        id: 'g2',
        name: 'G2',
        members: ['a'],
        creator: 'a',
        from: 'b',
        ts: 9999,
      };
      await acceptGroupInvite(inv);
      expect(db.saveGroup).toHaveBeenCalledWith(
        expect.objectContaining({ createdAt: 9999 })
      );
    });
  });

  describe('declineGroupInvite', () => {
    it('deletes pending group invite by id', async () => {
      await declineGroupInvite('group-decline-id');
      expect(db.deletePendingGroupInvite).toHaveBeenCalledTimes(1);
      expect(db.deletePendingGroupInvite).toHaveBeenCalledWith('group-decline-id');
      expect(db.saveGroup).not.toHaveBeenCalled();
      expect(db.saveMessage).not.toHaveBeenCalled();
    });
  });
});
