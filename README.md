# secrets-scanner-CLI
Scans your project for exposed API keys and secrets before you push them anywhere.

## What it catches

- AWS keys, GitHub tokens, Stripe keys, Google API keys, Slack tokens
- Database connection strings that have passwords baked in
- Private keys (RSA, EC, OpenSSH, PGP)
- Hardcoded passwords, JWTs, Bearer tokens
- `.env`-style variable assignments with secret-looking values
- 30+ patterns total across all the major services

Secrets are masked in the output (`AKIA****************`) so you're not just re-exposing them by running the tool.

## Installation

```bash
git clone https://github.com/sof1ax/secrets-scanner-CLI.git
cd secrets-scanner-CLI
pip3 install -e .
```

## Running it

Once installed, point it at any project folder:

```bash
secrets-scanner ~/Desktop/your-project-name
```

Or to scan a specific folder, type the path after `secrets-scanner` like this:

```bash
secrets-scanner ~/Desktop/pixel-social
```

```bash
# scan your current folder
secrets-scanner .

# scan a specific project
secrets-scanner ~/Desktop/my-project

# only show the serious stuff
secrets-scanner . --severity high

# compact table view if you have a lot of findings
secrets-scanner . --format table --no-context

# JSON output if you want to pipe it into something else
secrets-scanner . --format json

# only look at Python and JS files
secrets-scanner . --include-ext .py --include-ext .js

# skip .env files
secrets-scanner . --exclude-ext .env

# don't exit with an error code (useful for non-blocking CI)
secrets-scanner . --exit-zero
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `PATH` | `.` | A folder or single file to scan |
| `--severity`, `-s` | `low` | How serious the findings need to be before they're reported: `critical`, `high`, `medium`, `low` |
| `--format`, `-f` | `pretty` | How results are displayed: `pretty`, `table`, `json` |
| `--no-context` | off | Don't show the surrounding lines of code |
| `--no-gitignore` | off | Scan files that are gitignored too |
| `--include-ext EXT` | all | Only scan this file type (can use multiple times) |
| `--exclude-ext EXT` | none | Skip this file type (can use multiple times) |
| `--exit-zero` | off | Exit cleanly even when secrets are found |

## Output formats

**Pretty** (default): shows the exact line and a bit of context around it.

```
src/config.py:12  CRITICAL  AWS Access Key ID
  Amazon Web Services Access Key ID
  Secret (masked): AKIA****************
      10   # config
      11
  12 > AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
      13
      14   DEBUG = True
```

**Table**: useful when there are a lot of findings and you just want an overview.

```
┌────────────┬──────────────────┬───────────────┬──────┬──────────────────────┐
│ Severity   │ Pattern          │ File          │ Line │ Secret (masked)      │
├────────────┼──────────────────┼───────────────┼──────┼──────────────────────┤
│ CRITICAL   │ AWS Access Key   │ src/config.py │   12 │ AKIA**************** │
└────────────┴──────────────────┴───────────────┴──────┴──────────────────────┘
```

**JSON**: pipe it into another tool or save it as a report.

```json
{
  "summary": {
    "files_scanned": 42,
    "total_findings": 2,
    "by_severity": { "critical": 2 }
  },
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "severity": "critical",
      "pattern": "AWS Access Key ID",
      "secret_masked": "AKIA****************",
      "line_content": "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\""
    }
  ]
}
```

## Using it in CI

The scanner exits with code `1` whenever it finds something, so it'll automatically fail a pipeline step.

**GitHub Actions:**

```yaml
- name: Scan for secrets
  run: |
    pip install secrets-scanner
    secrets-scanner . --severity high --format json
```

**Pre-commit hook** (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
secrets-scanner . --severity high --no-context
```

## Found something? Here's what to do

1. Rotate the credential right away. If it was ever committed, treat it as compromised.
2. Move it to an env var: `.env` file locally with `python-dotenv`, or your platform's secret manager in prod.
3. Add the file to `.gitignore` so it doesn't get committed again.
4. Clean up git history if it was committed. `git filter-repo` or GitHub's built-in secret scanning can help.

## Project layout

```
secrets_scanner/
├── patterns.py   # all the regex patterns
├── scanner.py    # walks files, skips binaries, deduplicates findings
└── cli.py        # the actual CLI (Click + Rich)
```
## License 

MIT
