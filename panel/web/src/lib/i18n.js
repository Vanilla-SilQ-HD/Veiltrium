// Interface texts: one JSON file per language (locales/<lang>.json). English is complete;
// another language falls back to English for any key it does not have yet.
import en from '../locales/en.json';

const dictionaries = { en };
let lang = 'en';

export function setLanguage(code) {
  if (dictionaries[code]) lang = code;
}

export function t(key, vars = {}) {
  const text = dictionaries[lang]?.[key] ?? dictionaries.en[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? '').toString());
}
