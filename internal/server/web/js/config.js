// War Chat - configuration constants

export const API_BASE = typeof window !== 'undefined' ? window.location.origin : '';

export const DB_NAME = 'war-chat';
export const DB_VERSION = 7;
export const STORE_MSGS = 'messages';
export const STORE_KEYS = 'keys';
export const STORE_KEYPAIRS = 'keypairs';
export const STORE_PASSKEY_CREDS = 'passkey_credentials';
export const STORE_GROUPS = 'groups';
export const STORE_PENDING_GROUP_INVITES = 'pending_group_invites';

export const SESSION_USER = 'war-chat-username';
export const SESSION_MNEMONIC = 'war-chat-mnemonic';
export const SESSION_SEED = 'war-chat-seed';
export const STORAGE_USER = 'war-chat-username';
export const PASSKEY_SESSION = 'war-chat-passkey-session';

export const GROUP_PEER_PREFIX = 'group:';
