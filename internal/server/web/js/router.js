// War Chat - hash-based routing

export function getRoute() {
  const hash = typeof window !== 'undefined' ? window.location.hash.slice(1) || 'chats' : 'chats';
  const firstSlash = hash.indexOf('/');
  const view = firstSlash === -1 ? (hash || 'chats') : hash.slice(0, firstSlash) || 'chats';
  const param = firstSlash === -1 ? null : hash.slice(firstSlash + 1) || null;
  return { view, param };
}

export function navigate(view, param) {
  if (typeof window === 'undefined') return;
  const hash = param ? `#${view}/${param}` : `#${view}`;
  window.location.hash = hash;
}
