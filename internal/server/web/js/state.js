// War Chat - shared mutable application state

/**
 * Single source of truth for app state. Modules read/write this object.
 * - db: IndexedDB database instance (set by db.openDB)
 * - keys: { privateKey, publicKey } (set by auth)
 * - ws: WebSocket instance (set by ws.connectWS)
 * - currentUsername: string | null
 * - currentRecipient: string | null (peer or group:groupId)
 * - pubkeyCache: { [username]: pubkeyB64 }
 * - pendingPasskeyCredentialId: string | null (during passkey registration)
 */
export const state = {
  db: null,
  keys: null,
  ws: null,
  currentUsername: null,
  currentRecipient: null,
  pubkeyCache: {},
  pendingPasskeyCredentialId: null,
  requireInvite: false,
};

export function getState() {
  return state;
}
