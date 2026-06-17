
from picosentry.sandbox.l4.models import BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


SENSITIVE_ENV_VARS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_ID",
    "DATABASE_URL",
    "DB_PASSWORD",
    "GITHUB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HEROKU_API_KEY",
    "MAILGUN_API_KEY",
    "MANDRILL_API_KEY",
    "MONGO_URL",
    "NETLIFY_AUTH_TOKEN",
    "NPM_TOKEN",
    "PGPASSWORD",
    "POSTGRES_PASSWORD",
    "REDIS_URL",
    "SENDGRID_API_KEY",
    "SLACK_TOKEN",
    "STRIPE_SECRET_KEY",
    "TWILIO_AUTH_TOKEN",
    "VAULT_TOKEN",
}


def detect_env_leak(
    profile: BehavioralProfile,
) -> list[Finding]:
    findings: list[Finding] = []


    for op in profile.fs_ops:
        path_lower = op.path.lower()
        if path_lower.endswith((".env", ".env.local", ".env.production")):
            findings.append(
                Finding(
                    rule_id="L4-ENV-001",
                    severity=Severity.HIGH,
                    message=f"Access to .env file ({op.operation}): {op.path}",
                    location=op.path,
                    evidence={"operation": op.operation, "path": op.path},
                )
            )


    for call in profile.network_calls:
        for var_name in SENSITIVE_ENV_VARS:
            lower_val = var_name.lower()
            lower_addr = call.address.lower()
            if lower_val in lower_addr or var_name.lower() in lower_addr:
                findings.append(
                    Finding(
                        rule_id="L4-ENV-002",
                        severity=Severity.CRITICAL,
                        message=f"Sensitive env var {var_name} referenced in network address: {call.address}",
                        location=call.address,
                        evidence={"env_var": var_name, "address": call.address, "port": call.port},
                    )
                )


    env_dump_commands = {"env", "printenv", "set", "export"}
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower()
        if exe_base in env_dump_commands:
            findings.append(
                Finding(
                    rule_id="L4-ENV-003",
                    severity=Severity.HIGH,
                    message=f"Environment dumping command spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args},
                )
            )

    return findings
