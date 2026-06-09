import re
from dataclasses import dataclass


@dataclass
class Pattern:
    name: str
    regex: str
    severity: str  # critical, high, medium, low
    description: str


PATTERNS = [
    # AWS
    Pattern(
        name="AWS Access Key ID",
        regex=r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        severity="critical",
        description="Amazon Web Services Access Key ID",
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\s\"']*[:=][\s\"']*([A-Za-z0-9/+=]{40})",
        severity="critical",
        description="Amazon Web Services Secret Access Key",
    ),
    # GitHub
    Pattern(
        name="GitHub Personal Access Token (classic)",
        regex=r"ghp_[a-zA-Z0-9]{36}",
        severity="critical",
        description="GitHub classic personal access token",
    ),
    Pattern(
        name="GitHub Fine-Grained Token",
        regex=r"github_pat_[a-zA-Z0-9_]{82}",
        severity="critical",
        description="GitHub fine-grained personal access token",
    ),
    Pattern(
        name="GitHub OAuth Token",
        regex=r"gho_[a-zA-Z0-9]{36}",
        severity="critical",
        description="GitHub OAuth access token",
    ),
    Pattern(
        name="GitHub App Token",
        regex=r"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
        severity="high",
        description="GitHub App installation or user token",
    ),
    # Stripe
    Pattern(
        name="Stripe Live Secret Key",
        regex=r"sk_live_[0-9a-zA-Z]{24,}",
        severity="critical",
        description="Stripe live secret key",
    ),
    Pattern(
        name="Stripe Live Publishable Key",
        regex=r"pk_live_[0-9a-zA-Z]{24,}",
        severity="high",
        description="Stripe live publishable key",
    ),
    Pattern(
        name="Stripe Test Key",
        regex=r"(?:sk|pk)_test_[0-9a-zA-Z]{24,}",
        severity="medium",
        description="Stripe test API key",
    ),
    # Google
    Pattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="high",
        description="Google API key",
    ),
    Pattern(
        name="Google OAuth Client Secret",
        regex=r"(?i)google[_\-\s]*(?:oauth[_\-\s]*)?client[_\-\s]*secret[\s\"']*[:=][\s\"']*([a-zA-Z0-9\-_]{24,})",
        severity="critical",
        description="Google OAuth client secret",
    ),
    # Slack
    Pattern(
        name="Slack Bot Token",
        regex=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        severity="high",
        description="Slack bot token",
    ),
    Pattern(
        name="Slack User Token",
        regex=r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",
        severity="high",
        description="Slack user token",
    ),
    Pattern(
        name="Slack Webhook URL",
        regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        severity="high",
        description="Slack incoming webhook URL",
    ),
    # Private Keys
    Pattern(
        name="RSA Private Key",
        regex=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="critical",
        description="RSA private key",
    ),
    Pattern(
        name="EC Private Key",
        regex=r"-----BEGIN EC PRIVATE KEY-----",
        severity="critical",
        description="Elliptic curve private key",
    ),
    Pattern(
        name="OpenSSH Private Key",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="critical",
        description="OpenSSH private key",
    ),
    Pattern(
        name="PGP Private Key",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="critical",
        description="PGP private key block",
    ),
    # Tokens / generic
    Pattern(
        name="Bearer Token",
        regex=r"(?i)(?:authorization|auth)[:\s]+bearer\s+([a-zA-Z0-9\-_.~+/]+=*)",
        severity="high",
        description="HTTP Bearer authorization token",
    ),
    Pattern(
        name="JWT Token",
        regex=r"eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9\-_]+",
        severity="medium",
        description="JSON Web Token (JWT)",
    ),
    # Databases
    Pattern(
        name="PostgreSQL Connection String",
        regex=r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+",
        severity="critical",
        description="PostgreSQL connection string with credentials",
    ),
    Pattern(
        name="MySQL Connection String",
        regex=r"mysql://[^:]+:[^@]+@[^\s\"']+",
        severity="critical",
        description="MySQL connection string with credentials",
    ),
    Pattern(
        name="MongoDB Connection String",
        regex=r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",
        severity="critical",
        description="MongoDB connection string with credentials",
    ),
    Pattern(
        name="Redis Connection String",
        regex=r"redis://:[^@]+@[^\s\"']+",
        severity="high",
        description="Redis connection string with password",
    ),
    # Twilio
    Pattern(
        name="Twilio Account SID",
        regex=r"AC[a-f0-9]{32}",
        severity="high",
        description="Twilio account SID",
    ),
    Pattern(
        name="Twilio Auth Token",
        regex=r"(?i)twilio[_\-\s]*auth[_\-\s]*token[\s\"']*[:=][\s\"']*([a-f0-9]{32})",
        severity="critical",
        description="Twilio authentication token",
    ),
    # SendGrid
    Pattern(
        name="SendGrid API Key",
        regex=r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        severity="high",
        description="SendGrid API key",
    ),
    # Mailgun
    Pattern(
        name="Mailgun API Key",
        regex=r"key-[0-9a-zA-Z]{32}",
        severity="high",
        description="Mailgun API key",
    ),
    # Heroku
    Pattern(
        name="Heroku API Key",
        regex=r"(?i)heroku[_\-\s]*api[_\-\s]*key[\s\"']*[:=][\s\"']*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        severity="high",
        description="Heroku API key",
    ),
    # NPM
    Pattern(
        name="NPM Auth Token",
        regex=r"npm_[a-zA-Z0-9]{36}",
        severity="high",
        description="NPM authentication token",
    ),
    # Generic high-entropy secrets
    Pattern(
        name="Generic Secret Assignment",
        regex=r"(?i)(?:secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token|private[_\-]?key|passwd|password)\s*[:=]\s*[\"']([a-zA-Z0-9\-_.~+/]{16,})[\"']",
        severity="medium",
        description="Generic secret or credential assignment",
    ),
    Pattern(
        name="Hardcoded Password",
        regex=r"(?i)password\s*[:=]\s*[\"']([^\"']{6,})[\"']",
        severity="medium",
        description="Hardcoded password value",
    ),
    # .env style
    Pattern(
        name="Env Var with Secret Name",
        regex=r"(?i)^(?:export\s+)?(?:[A-Z_]*(?:SECRET|API_KEY|ACCESS_KEY|AUTH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD)[A-Z_]*)\s*=\s*[\"']?([^\s\"'#]{8,})[\"']?",
        severity="medium",
        description=".env file variable with a secret-like name",
    ),
]

COMPILED_PATTERNS = [
    (p, re.compile(p.regex, re.MULTILINE)) for p in PATTERNS
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
