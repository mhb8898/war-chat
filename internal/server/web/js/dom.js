// War Chat - centralized DOM resolution (main-scoped or document)

/**
 * Resolve an element by ID: look inside war-chat-main if present, else document.
 * Use for elements that may live inside the main layout (e.g. #messages, #chat-pane).
 * @param {string} id - Element id without the # prefix
 * @returns {Element | null}
 */
export function resolveInMain(id) {
  if (typeof document === 'undefined') return null;
  const main = document.querySelector('war-chat-main');
  if (main) {
    const el = main.querySelector('#' + id);
    if (el) return el;
  }
  return document.getElementById(id);
}
