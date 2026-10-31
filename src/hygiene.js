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

  // Raw non-printable control characters, except U+0004 (EOT): the gettext
  // plural/msgctxt separator that i18n tooling legitimately embeds (found by
  // dogfooding on a real WP plugin's make-i18n-json.py).
  if (/[\x00-\x03\x05-\x08\x0B\x0C\x0E-\x1F]/.test(text)) {
    issues.push('Found raw non-printable control characters');
  }

  // Shell-escaping artifacts before words/identifiers. Legitimate shapes:
  // valid escape char (\n, \x41...), single-char regex class (\s \d \w),
  // capitalized token (\Admin: PHP namespaces), underscore (\_transient:
  // SQL LIKE escapes, found by dogfooding on a real WP plugin).
  // What remains: a backslash glued to a lowercase word: is the artifact
  // this check hunts.
  //
  // A regex class with a SUFFIX inside a regex literal is legitimate too
  // (card in dsh-org, measured 2026-10-30 on dsh-org PR #565: ONE line of 864
  // added, `!/\dms\b/.test(specA)`, was read as "\dms" and charged the diff
  // the full 40-point hygiene penalty, taking Engineering Score 100 -> 60,
  // exactly its pass threshold). `\d` is a class and `ms` is a literal suffix:
  // well-formed JavaScript. The old predicates both missed it because
  // validEscape is anchored to the whole match and regexClass wants exactly
  // one letter, so a class followed by anything was neither.
  //
  // The narrowing is scoped to regex literals on purpose: `\dms` between two
  // slashes is a regex, while `"C:\Users\wizz"` outside one is still the
  // artifact this rule exists for. Widening the global escape list instead
  // would have been the change that turns this rule into a rubber stamp.
  const shellEscapes = text.match(/\\[a-zA-Z_0-9]+/g);
  if (shellEscapes) {
    const validEscape = /^\\[nrt0bfvxu_]/i;
    const regexClass = /^\\[a-zA-Z0-9]$/;
    const namespaceish = /^\\[A-Z]/;
    // A backslash-class prefix (\d, \s, \w, \b) followed by more characters,
    // accepted only when the sequence sits inside a regex literal.
    const classWithSuffix = /^\\[dswb]/;
    const insideRegexLiteral = (whole, seq) => {
      const at = whole.indexOf(seq);
      if (at < 0) return false;
      const before = whole.slice(0, at);
      // The nearest unescaped slash before the sequence, and the nearest after
      // it: an odd opening slash and a closing slash means the sequence is
      // between them. Good enough for a line-level check, and it is the same
      // level the rest of this function works at.
      const open = before.lastIndexOf('/');
      if (open < 0) return false;
      const escapedOpen = (before.slice(0, open).match(/\\+$/) || [''])[0].length % 2 === 1;
      if (escapedOpen) return false;
      return whole.slice(at + seq.length).includes('/');
    };
    const suspicious = shellEscapes.filter(
      (s) => !validEscape.test(s) && !regexClass.test(s) && !namespaceish.test(s)
        && !(classWithSuffix.test(s) && insideRegexLiteral(text, s))
    );
    if (suspicious.length > 0) {
      issues.push(`Found shell escaping artifacts: ${suspicious.slice(0, 3).join(', ')}`);
    }
  }

  // Escaped backticks are not flagged: a line-level check cannot tell an
  // escaped backtick in prose from one inside a template literal.

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
