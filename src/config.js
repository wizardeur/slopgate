// Repository config: .slopgate.json at the repo root (or a path passed via
// --config / the config_path action input). Zero dependencies: globs are
// converted to regexes locally.
//
// {
//   "disable": ["SG-SEC-012"],          // rule IDs to skip entirely
//   "ignorePaths": ["fixtures/**"],     // globs; matching files are not scanned
//   "minBlockSeverity": "HIGH",         // findings below this severity are advisory
//   "requireShaPins": true              // SG-SEC-011: also flag action refs that
//                                       // are not a full 40-char commit SHA
// }

const fs = require('fs');

// LOW exists so analyzers can emit an advisory-only severity: a finding at
// LOW never blocks under the default floor (MEDIUM), and a repository can
// still set minBlockSeverity to LOW to demand blocking on everything.
const SEVERITY_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
const DEFAULTS = Object.freeze({
  disable: [],
  ignorePaths: [],
  minBlockSeverity: 'MEDIUM', // findings at or above MEDIUM block by default
  // Off by default: flagging every mutable tag is a policy choice, not a
  // defect, and turning it on would red every consumer repo on a patch
  // release. With it on, SG-SEC-011 requires a full commit SHA.
  requireShaPins: false,
});

function globToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    '^' + escaped.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*') + '$',
    'i'
  );
}

function loadConfig(repoRoot = process.cwd(), explicitPath = null) {
  const candidates = explicitPath
    ? [explicitPath]
    : [`${repoRoot}/.slopgate.json`];
  for (const file of candidates) {
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf-8'));
      const az = raw.analyzers || {};
      const cfg = {
        disable: Array.isArray(raw.disable) ? raw.disable.map(String) : [],
        ignorePaths: Array.isArray(raw.ignorePaths) ? raw.ignorePaths.map(globToRegex) : [],
        minBlockSeverity: SEVERITY_RANK[raw.minBlockSeverity] ? raw.minBlockSeverity : DEFAULTS.minBlockSeverity,
        requireShaPins: raw.requireShaPins === true,
        analyzers: {
          pythonAst: az.pythonAst !== false,
          jsAst: az.jsAst !== false,
          importGraph: az.importGraph !== false,
          entrypoints: Array.isArray(az.entrypoints) ? az.entrypoints.map(globToRegex) : [],
          external: Array.isArray(az.external) ? az.external : [],
        },
      };
      return { ...cfg, source: file };
    } catch (err) {
      if (err instanceof SyntaxError) {
        console.warn(`[slopgate] Invalid JSON in ${file}, ignoring config: ${err.message}`);
      }
      // missing file / unreadable -> try next candidate
    }
  }
  return { ...DEFAULTS, ignorePaths: [], analyzers: { pythonAst: true, importGraph: true, entrypoints: [], external: [] }, source: null };
}

module.exports = { loadConfig, globToRegex, SEVERITY_RANK, DEFAULTS };
