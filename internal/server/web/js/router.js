// War Chat - hash-based routing

export function getRoute() {
  const hash = typeof window !== 'undefined' ? window.location.hash.slice(1) || 'chats' : 'chats';
  const [view, param] = hash.split('/');
  return { view: view || 'chats', param: param || null };
}

export function navigate(view, param) {
  if (typeof window === 'undefined') return;
  const hash = param ? `#${view}/${param}` : `#${view}`;
  window.location.hash = hash;
}
