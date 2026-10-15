// Repository config: .slopgate.json at the repo root (or a path passed via
// --config / the config_path action input). Zero dependencies: globs are
// converted to regexes locally.
//
// {
//   "disable": ["SG-SEC-012"],          // rule IDs to skip entirely
//   "ignorePaths": ["fixtures/**"],     // globs; matching files are not scanned
//   "minBlockSeverity": "HIGH"          // findings below this severity are advisory
// }

const fs = require('fs');

const SEVERITY_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
const DEFAULTS = Object.freeze({
  disable: [],
  ignorePaths: [],
  minBlockSeverity: 'MEDIUM', // findings at or above MEDIUM block by default
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
