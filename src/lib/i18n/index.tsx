'use client';

/**
 * VulnCheck Local — lightweight i18n (EN / ES)
 * --------------------------------------------
 * No external i18n dependency on purpose: a tiny external store with
 * useSyncExternalStore keeps the bundle light and avoids provider trees.
 *
 * - Dictionaries live in ./en/<namespace>.ts and ./es/<namespace>.ts
 *   (plain Record<string,string>, flattened with "<namespace>.<key>" keys).
 * - Locale persists in localStorage under 'vc_locale'.
 * - Server snapshot is always 'en' → no hydration mismatch; the saved
 *   preference (or browser language) is applied right after mount via
 *   initLocaleFromStorage().
 * - Non-React modules (e.g. zustand store toasts) use getT()/getLocale().
 */

import { useSyncExternalStore } from 'react';
import { enDict, esDict } from './dictionaries';

export type Locale = 'en' | 'es';
export type TranslateFn = (key: string, vars?: Record<string, string | number>) => string;

const DICTS: Record<Locale, Record<string, string>> = { en: enDict, es: esDict };
const STORAGE_KEY = 'vc_locale';

let current: Locale = 'en';
const listeners = new Set<() => void>();

function emit(): void {
  listeners.forEach((l) => l());
}

export function getLocale(): Locale {
  return current;
}

export function isSupportedLocale(v: unknown): v is Locale {
  return v === 'en' || v === 'es';
}

export function setLocale(next: Locale): void {
  if (next === current) return;
  current = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    /* storage unavailable (private mode) — keep in-memory only */
  }
  emit();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function translate(
  locale: Locale,
  key: string,
  vars?: Record<string, string | number>,
): string {
  let s: string = DICTS[locale][key] ?? DICTS.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.split(`{${k}}`).join(String(v));
    }
  }
  return s;
}

/** For code outside React (zustand store, helpers): always current locale. */
export function getT(): TranslateFn {
  const l = current;
  return (key, vars) => translate(l, key, vars);
}

/** React hook — server snapshot is 'en' so SSR output is deterministic. */
export function useI18n(): { locale: Locale; setLocale: (l: Locale) => void; t: TranslateFn } {
  const locale = useSyncExternalStore(
    subscribe,
    () => current,
    () => 'en' as Locale,
  );
  return { locale, setLocale, t: (key, vars) => translate(locale, key, vars) };
}

/** Call once after mount (DashboardShell) to apply saved/browser preference. */
export function initLocaleFromStorage(): void {
  if (typeof window === 'undefined') return;
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (isSupportedLocale(saved)) {
      if (saved !== current) setLocale(saved);
      return;
    }
  } catch {
    /* ignore */
  }
  const nav = typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('es') ? 'es' : 'en';
  if (nav !== current) setLocale(nav);
}

export const AVAILABLE_LOCALES: { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' },
];
