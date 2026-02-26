// War Chat - reusable dropdown menu (Telegram-style text options)

/**
 * Show a dropdown menu anchored to an element.
 * @param {HTMLElement} anchor - Element to position the menu below/near
 * @param {{ label: string, action: string }[]} items - Menu items
 * @param {(action: string) => void} onSelect - Called when an item is chosen; menu closes first
 */
export function showMenu(anchor, items, onSelect) {
  if (!anchor || !items?.length) return;
  const existing = document.getElementById('wc-menu-dropdown');
  if (existing) existing.remove();

  const menu = document.createElement('div');
  menu.id = 'wc-menu-dropdown';
  menu.className = 'wc-menu-dropdown';
  menu.style.position = 'fixed';
  menu.style.zIndex = '10000';
  const list = document.createElement('div');
  list.className = 'wc-menu-list';
  items.forEach(({ label, action }) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'wc-menu-item';
    btn.textContent = label;
    btn.dataset.action = action;
    list.appendChild(btn);
  });
  menu.appendChild(list);

  function close() {
    menu.remove();
    document.removeEventListener('click', handleOutside);
    document.removeEventListener('keydown', handleEscape);
  }

  function choose(action) {
    close();
    onSelect(action);
  }

  list.addEventListener('click', (e) => {
    const btn = e.target.closest('.wc-menu-item');
    if (btn && btn.dataset.action) choose(btn.dataset.action);
  });

  function handleOutside(e) {
    if (!menu.contains(e.target) && e.target !== anchor) close();
  }
  function handleEscape(e) {
    if (e.key === 'Escape') close();
  }

  document.body.appendChild(menu);
  const rect = anchor.getBoundingClientRect();
  const menuRect = menu.getBoundingClientRect();
  const rightAlign = rect.right - menuRect.width;
  let left = rect.right - menuRect.width;
  if (left < 8) left = 8;
  if (left + menuRect.width > window.innerWidth - 8) left = window.innerWidth - menuRect.width - 8;
  menu.style.left = left + 'px';
  menu.style.top = (rect.bottom + 4) + 'px';
  document.addEventListener('click', handleOutside, { capture: true });
  document.addEventListener('keydown', handleEscape);
  requestAnimationFrame(() => list.querySelector('.wc-menu-item')?.focus());
}
