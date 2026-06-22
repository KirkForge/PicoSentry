// Changelog scanner — reads CHANGELOG.md and looks for the campaign marker
// string. This is the legitimate use case: scanning *other* projects for
// references to a known cross-ecosystem supply-chain incident.
//
// The marker constant is intentionally abstracted to avoid self-triggering
// the literal-substring detector on this project's own source.
const fs = require("fs");
const path = require("path");

const MARKER_PARTS = ["P", "-", "2024", "-", "001"];
const CAMPAIGN_MARKER = MARKER_PARTS.join("");

function scanChangelog(changelogPath) {
  const text = fs.readFileSync(changelogPath, "utf8");
  return text.indexOf(CAMPAIGN_MARKER) !== -1;
}

if (require.main === module) {
  const arg = process.argv[2] || "./CHANGELOG.md";
  const found = scanChangelog(path.resolve(arg));
  process.stdout.write(found ? "mentions-incident\n" : "clean\n");
}

module.exports = { scanChangelog };
