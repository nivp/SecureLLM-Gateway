import type { ChatMessage, RedactionToken } from "../types.js";

type Category = RedactionToken["category"];

type Pattern = {
  category: Category;
  regex: RegExp;
  isValid?: (value: string) => boolean;
};

const patterns: Pattern[] = [
  { category: "email", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { category: "phone", regex: /(?<!\d)(?:\+972[-\s]?|0)(?:[23489]|5\d|7[234678])[-\s]?\d{3}[-\s]?\d{4}(?!\d)/g },
  { category: "phone", regex: /(?<!\d)\+\d{1,3}[-\s]?(?:\(?\d{1,4}\)?[-\s]?){2,5}\d{2,4}(?!\d)/g },
  { category: "israeli_id", regex: /(?<!\d)\d{5,9}(?!\d)/g, isValid: isValidIsraeliId }
];

function isValidIsraeliId(value: string): boolean {
  const rawDigits = value.replace(/\D/g, "");
  if (!/^\d{5,9}$/.test(rawDigits)) {
    return false;
  }
  if (rawDigits.length === 9) {
    return true;
  }
  const digits = rawDigits.padStart(9, "0");
  const sum = [...digits].reduce((acc, digit, index) => {
    let n = Number(digit) * ((index % 2) + 1);
    if (n > 9) {
      n -= 9;
    }
    return acc + n;
  }, 0);
  return sum % 10 === 0;
}

export function redactText(input: string): { text: string; tokens: RedactionToken[] } {
  let text = input;
  const tokens: RedactionToken[] = [];
  const counters: Record<Category, number> = { email: 0, phone: 0, israeli_id: 0 };

  for (const pattern of patterns) {
    text = text.replace(pattern.regex, (match: string) => {
      if (pattern.isValid && !pattern.isValid(match)) {
        return match;
      }
      counters[pattern.category] += 1;
      const token = `[PII_${pattern.category.toUpperCase()}_${counters[pattern.category]}]`;
      tokens.push({ token, category: pattern.category, value: match });
      return token;
    });
  }

  return { text, tokens };
}

export function redactMessages(messages: ChatMessage[]): { messages: ChatMessage[]; tokens: RedactionToken[] } {
  const tokens: RedactionToken[] = [];
  const redactedMessages = messages.map((message) => {
    const redacted = redactText(message.content);
    tokens.push(...redacted.tokens);
    return { ...message, content: redacted.text };
  });
  return { messages: redactedMessages, tokens };
}
