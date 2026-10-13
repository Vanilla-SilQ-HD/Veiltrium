// One short status message at a time ("Copied", "anna revoked").
export const toast = $state({ text: '' });
let timer;

export function flash(text) {
  toast.text = text;
  clearTimeout(timer);
  timer = setTimeout(() => (toast.text = ''), 1800);
}
