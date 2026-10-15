// Unified-diff parser. Produces per-file records with hunk structure, exact
// new-file line numbers for added lines, and pre-joined text blocks for
// multi-line (cross-line) rule scanning.

function parseDiff(diffText) {
  const files = [];
  let current = null;
  let hunk = null;
  let newLine = 0;

  for (const line of diffText.split('\n')) {
    if (line.startsWith('diff --git')) {
      const m = line.match(/diff --git a\/(.+?) b\/(.+)$/);
      current = {
        path: m ? m[2].trim() : 'unknown',
        addedLines: [], // added code, leading '+' stripped (back-compat)
        removedLines: [], // removed code, leading '-' stripped (back-compat)
        hunks: [], // { newStart, added: [{ code, line }], hunkText, addedText }
      };
      files.push(current);
      hunk = null;
      continue;
    }
    if (!current) continue;

    if (line.startsWith('@@')) {
      const m = line.match(/^@@\s*-\d+(?:,\d+)?\s*\+(\d+)/);
      newLine = m ? parseInt(m[1], 10) : 0;
      hunk = { newStart: newLine, added: [], hunkText: '', addedText: '' };
      current.hunks.push(hunk);
      continue;
    }

    if (line.startsWith('---') || line.startsWith('+++')) continue;

    // hunkText stores stripped code (context/added/removed), so file-level
    // rules match real source lines, not diff annotations like `+key: value`.
    if (hunk) hunk.hunkText += line.replace(/^[ +-]/, '').replace(/^-(.*)$/, '$1') + '\n';

    if (line.startsWith('+')) {
      const code = line.slice(1);
      current.addedLines.push(code);
      if (hunk) {
        hunk.added.push({ code, line: newLine });
        hunk.addedText += code + '\n';
      }
      newLine++;
    } else if (line.startsWith('-')) {
      current.removedLines.push(line.slice(1));
      // removed lines do not advance the new-file counter
    } else if (line.startsWith(' ') || line === '') {
      newLine++;
    }
  }

  return files;
}

function isTestFile(filePath) {
  // Segment-boundary matching: a bare /test|spec/ substring would exempt
  // src/latest.js, attestation.ts, contest.py etc. from security shields.
  return (
    /(?:^|[/_.-])(?:tests?|__tests__|specs?|e2e|benchmarks?)(?:[/_.-]|$)/i.test(filePath) ||
    /[._-]test\.go$/i.test(filePath) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/i.test(filePath)
  );
}

// Files that are noise for code rules: lockfiles, minified bundles, vendored
// code. A 40k-line lockfile otherwise buries real findings and burns scan time.
const GENERATED_FILE =
  /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|go\.sum|bun\.lockb)$|\.min\.[cm]?js$|(?:^|\/)(?:node_modules|vendor|third_party)\//i;

module.exports = { parseDiff, isTestFile, GENERATED_FILE };
