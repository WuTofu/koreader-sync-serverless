import en from "./en";
import ja from "./ja";
import type { LocaleMessages } from "./types";
import zh from "./zh";

export type Locale = "zh" | "en" | "ja";

const locales: Record<Locale, LocaleMessages> = {
  zh,
  en,
  ja,
};

export function pickLocale(acceptLanguageHeader?: string | null): Locale {
  const supported = new Set<Locale>(["en", "zh", "ja"]);
  const header = (acceptLanguageHeader || "").trim();
  if (!header) return "en";

  const ranked = header
    .split(",")
    .map((entry) => {
      const [tag, ...params] = entry.trim().split(";");
      const qParam = params.find((p) => p.trim().toLowerCase().startsWith("q="));
      const q = qParam ? parseFloat(qParam.trim().slice(2)) : 1;
      const primary = (tag || "").trim().toLowerCase().split("-")[0];
      return { primary, q };
    })
    .filter(({ q }) => Number.isFinite(q) && q > 0)
    .sort((a, b) => b.q - a.q);

  for (const { primary } of ranked) {
    if (supported.has(primary as Locale)) return primary as Locale;
  }
  return "en";
}

export function getMessages(locale: Locale): LocaleMessages {
  return locales[locale] ?? locales.en;
}
