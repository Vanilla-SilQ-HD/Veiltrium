// Interface texts: one JSON file per language (locales/<lang>.json). English is complete;
// another language falls back to English for any key it does not have.
import en from '../locales/en.json';
import ru from '../locales/ru.json';

const dictionaries = { en, ru };
export const languages = Object.keys(dictionaries);

function stored() {
  try { return localStorage.getItem('vt-lang'); } catch { return null; }
}
function initial() {
  const s = stored();
  if (s && dictionaries[s]) return s;
  return /^ru\b/i.test(navigator.language || '') ? 'ru' : 'en';
}

const state = $state({ lang: initial() });
document.documentElement.lang = state.lang;

export const lang = () => state.lang;

export function setLanguage(code) {
  if (!dictionaries[code]) return;
  state.lang = code;
  document.documentElement.lang = code;
  try { localStorage.setItem('vt-lang', code); } catch { /* private window */ }
}

// BCP 47 tag for toLocale* calls
export const locale = () => (state.lang === 'ru' ? 'ru-RU' : 'en-GB');

export function t(key, vars = {}) {
  const d = dictionaries[state.lang];
  let k = key;
  // plural forms: key.one / key.few / key.many / key.other, chosen by {n}
  if (typeof vars.n === 'number') {
    const form = new Intl.PluralRules(state.lang).select(vars.n);
    k = [`${key}.${form}`, `${key}.other`].find((x) => x in d || x in en) ?? key;
  }
  const text = d[k] ?? en[k] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, v) => (vars[v] ?? '').toString());
}
