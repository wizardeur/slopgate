// Architectural layer classification for blast-radius analysis.
// Priority order matters: the first matching pattern wins, so infrastructure
// files are classified before auth even if a path contains both keywords.

const LAYERS = [
  {
    name: 'CI/CD & Infrastructure',
    test: /\.github\/workflows\/|dockerfile|docker-compose|terraform|\.tf$|k8s|helm/i,
  },
  {
    name: 'Authentication & Security Boundary',
    test: /auth|login|session|jwt|oauth|token|permission|rbac|security|middleware/i,
  },
  {
    name: 'Persistence & Vector / Data Store',
    test: /db|database|schema|migration|prisma|drizzle|sequelize|sql|qdrant|vector|redis|store|repository|model/i,
  },
  {
    // Path-segment boundaries: a bare /ai|llm/ substring match would swallow
    // m(ai)n.py, em(ai)l.ts, dom(ai)n.py, etc. into the AI layer.
    name: 'AI / LLM Processing Pipeline',
    test: /(?:^|[/_.-])(?:ai|llm|agents?)(?:[/_.-]|$)|openai|anthropic|gemini|prompt|embedding|rag|inference/i,
  },
  {
    name: 'API Contracts & Entrypoints',
    test: /api\/|routes?\/|controllers?\/|handlers?\/|endpoints?\/|graphql|trpc|server|main\.py|app\.py/i,
  },
  {
    name: 'Frontend Client & UI Surface',
    test: /components?\/|pages?\/|views?\/|ui\/|frontend\/|client\/|\.tsx$|\.jsx$|\.vue$|\.svelte$/i,
  },
  {
    name: 'Verification & Test Suite',
    test: /test|spec|__tests__|e2e|benchmark/i,
  },
];

function classifyLayer(filePath) {
  const lower = filePath.toLowerCase();
  for (const layer of LAYERS) {
    if (layer.test.test(lower)) return layer.name;
  }
  return 'Core Domain & Business Logic';
}

module.exports = { classifyLayer, LAYERS };
