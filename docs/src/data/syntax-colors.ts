export const syntaxColorHex = {
  foreground: 'd7dee8',
  comment: '6a6f7a',
  red: 'd06f72',
  green: 'b5d0a6',
  yellow: 'd6c57b',
  blue: '9eb6d6',
  magenta: 'd7aff0',
  cyan: '82c7d8',
  orange: 'd8a162',
} as const;

export type SyntaxColorName = keyof typeof syntaxColorHex;

export const syntaxTokenColor: Record<string, SyntaxColorName> = {
  key: 'blue',
  string: 'green',
  comment: 'comment',
  number: 'orange',
  punctuation: 'foreground',
  section: 'magenta',
};

export const syntaxColorCssVariable = Object.fromEntries(
  Object.keys(syntaxColorHex).map((color) => [color, `--syntax-${color}`]),
) as Record<SyntaxColorName, `--syntax-${string}`>;

export const syntaxColorCss = `:root{${Object.entries(syntaxColorHex)
  .map(([color, hex]) => `${syntaxColorCssVariable[color as SyntaxColorName]}:#${hex}`)
  .join(';')}}`;
