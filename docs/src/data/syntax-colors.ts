export const syntaxColorNames = [
  'foreground',
  'comment',
  'red',
  'green',
  'yellow',
  'blue',
  'magenta',
  'cyan',
  'orange',
] as const;

export type SyntaxColorName = (typeof syntaxColorNames)[number];

export const syntaxTokenColor: Record<string, SyntaxColorName> = {
  key: 'blue',
  string: 'green',
  comment: 'comment',
  number: 'orange',
  boolean: 'magenta',
  punctuation: 'foreground',
  section: 'magenta',
};
