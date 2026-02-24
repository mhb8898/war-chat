// War Chat - UI and string utilities

export function escapeHtml(s) {
  if (s == null) return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function formatMessage(text) {
  if (!text || typeof text !== 'string') return '';
  const escaped = escapeHtml(text);
  const parts = escaped.split('```');
  let result = '';
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 1) {
      result += '<pre class="msg-code"><code>' + parts[i] + '</code></pre>';
    } else {
      result += parts[i].replace(/\n/g, '<br>');
    }
  }
  return result;
}

export function formatTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function generateMnemonic() {
  const words = (typeof window !== 'undefined' && window.WORDLISTS && window.WORDLISTS['english']) ? window.WORDLISTS['english'] : [];
  if (words.length === 0) throw new Error('Wordlist not loaded');
  return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
}
