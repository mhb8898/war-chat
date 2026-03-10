// War Chat - dark/light theme toggle

const STORAGE_KEY = 'war-chat-theme';

const SVG_SUN = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="3.25" stroke="currentColor" stroke-width="1.5"/><path d="M9 1.5V3M9 15v1.5M1.5 9H3M15 9h1.5M3.4 3.4l1.06 1.06M13.54 13.54l1.06 1.06M3.4 14.6l1.06-1.06M13.54 4.46l1.06-1.06" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`;
const SVG_MOON = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M15 11.5A7 7 0 0 1 6.5 3a7 7 0 1 0 8.5 8.5z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function systemTheme() {
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function currentTheme() {
  return document.documentElement.getAttribute('data-theme') || systemTheme();
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('btnThemeToggle');
  if (!btn) return;
  // Show the icon for the opposite (what you'll switch to)
  btn.innerHTML = theme === 'dark' ? SVG_SUN : SVG_MOON;
  btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
}

export function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  localStorage.setItem(STORAGE_KEY, next);
  applyTheme(next);
}

export function initTheme() {
  // data-theme was already set by inline script; just sync the button icon
  applyTheme(currentTheme());

  const btn = document.getElementById('btnThemeToggle');
  if (btn) btn.addEventListener('click', toggleTheme);

  // Follow system if user hasn't manually picked
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem(STORAGE_KEY)) applyTheme(e.matches ? 'light' : 'dark');
  });
}
