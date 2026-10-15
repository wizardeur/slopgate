// Markdown / text hygiene and AI conversational slop detection, applied to the
// whole unified diff text (context lines included).

const SLOP_PHRASES = [
  'as an ai language model',
  'certainly, here is',
  'certainly! here is',
  'here is the updated code',
  'i hope this helps',
  'feel free to ask if you have any questions',
  'let me know if you need any further',
];

function checkHygiene(text) {
  const issues = [];
  if (!text) return issues;

  // Raw non-printable control characters, except U+0004 (EOT) — the gettext
  // plural/msgctxt separator that i18n tooling legitimately embeds (found by
  // dogfooding on a real WP plugin's make-i18n-json.py).
  if (/[\x00-\x03\x05-\x08\x0B\x0C\x0E-\x1F]/.test(text)) {
    issues.push('Found raw non-printable control characters');
  }

  // Shell-escaping artifacts before words/identifiers. Legitimate shapes:
  // valid escape char (\n, \x41...), single-char regex class (\s \d \w),
  // capitalized token (\Admin — PHP namespaces), underscore (\_transient —
  // SQL LIKE escapes, found by dogfooding on a real WP plugin).
  // What remains — a backslash glued to a lowercase word — is the artifact
  // this check hunts.
  const shellEscapes = text.match(/\\[a-zA-Z_0-9]+/g);
  if (shellEscapes) {
    const validEscape = /^\\[nrt0bfvxu_]/i;
    const regexClass = /^\\[a-zA-Z0-9]$/;
    const namespaceish = /^\\[A-Z]/;
    const suspicious = shellEscapes.filter(
      (s) => !validEscape.test(s) && !regexClass.test(s) && !namespaceish.test(s)
    );
    if (suspicious.length > 0) {
      issues.push(`Found shell escaping artifacts: ${suspicious.slice(0, 3).join(', ')}`);
    }
  }

  // Escaped backticks are deliberately not flagged.
  // Removed after external dogfooding: it fired on intentional markdown
  // escaping (CLAUDE.md) and on markdown-generating JS template literals
  // (bin/jsmap) — it cannot distinguish artifact from intent and had
  // negative value on real repositories.

  const lower = text.toLowerCase();
  for (const phrase of SLOP_PHRASES) {
    if (lower.includes(phrase)) {
      issues.push(`Detected robotic conversational slop phrase: "${phrase}"`);
    }
  }

  return issues;
}

// Explicit "do not merge" markers left in the diff.
function findSlopMarkers(diffText) {
  const markers = [];
  for (const marker of [
    'DO_NOT_MERGE_SLOP',
    'TODO: Implement later when AI is smarter',
    '// AI-generated boilerplate copy 1',
  ]) {
    if (diffText.includes(marker)) markers.push(marker);
  }
  return markers;
}

module.exports = { checkHygiene, findSlopMarkers, SLOP_PHRASES };
