# Claude Code Protective Hooks

A Claude Code plugin providing PreToolUse security hooks to block dangerous commands and protect sensitive files.

## Features

- **Block Dangerous Commands**: Prevents execution of catastrophic commands like `rm -rf /`, `dd` to disk devices, fork bombs
- **Protect Secrets**: Guards against reading/modifying sensitive files (.env, SSH keys, AWS credentials, etc.)
- **Configurable Safety Levels**: Choose from `critical`, `high`, or `strict` protection levels
- **Smart Decisions**: Critical patterns are blocked; high/strict patterns prompt for confirmation
- **Comprehensive Patterns**: Detects secret exfiltration attempts, dangerous git operations, Kubernetes secrets, Vault access, and more
- **Logging**: All blocked operations are logged to `~/.claude/hooks-logs/`

## Safety Levels

| Level      | Description                                                             |
| ---------- | ----------------------------------------------------------------------- |
| `critical` | **Deny** - Blocks catastrophic operations: rm -rf ~, dd to disk, fork bombs |
| `high`     | **Ask** - Risky operations: force push, git reset --hard, secrets exposure |
| `strict`   | **Ask** - Cautionary operations: any force push, sudo rm, docker prune     |

**Decision Behavior:**
- `critical` patterns → **deny** (blocked immediately, cannot be bypassed even with `dangerously-skip-permissions`)
- `high` and `strict` patterns → **ask** (prompts for user confirmation)

## Installation

### Option 1: Local Installation (Project)

1. Clone the repository:

   ```bash
   git clone https://github.com/adrianR84/claude-code-protective-hooks.git
   cd claude-code-protective-hooks
   ```

2. Add the local marketplace:

   ```
   /plugin marketplace add .
   ```

3. Install the plugin:

   ```
   /plugin install protective-hooks@claude-code-protective-hooks
   ```

### Option 2: From a GitHub Repository

```bash
/plugin marketplace add adrianR84/claude-code-protective-hooks
/plugin install protective-hooks@claude-code-protective-hooks
```

### Option 3: Session-Only (No Install)

```bash
git clone https://github.com/adrianR84/claude-code-protective-hooks.git
cd claude-code-protective-hooks
claude --plugin-dir .
```

## Configuration

The hooks are automatically enabled after installation. To customize:

1. Edit `scripts/pre-tool-use/block-dangerous-commands.js`
2. Edit `scripts/pre-tool-use/protect-secrets.js`

### Safety Level

```javascript
const SAFETY_LEVEL = "strict"; // 'critical' | 'high' | 'strict'
```

## Hooks Overview

### block-dangerous-commands.js (Bash)

Blocks dangerous bash commands before execution:

| Level | Decision | Examples |
|-------|----------|----------|
| critical | deny | `rm -rf /`, `dd to disk`, `mkfs`, fork bombs |
| high | ask | `curl | bash`, force push to main, `git reset --hard`, `chmod 777`, `kubectl get secrets`, `vault read` |
| strict | ask | Any force push, `sudo rm`, `docker prune`, `crontab -l`, `pkill` |

### protect-secrets.js (Read|Edit|Write|Bash)

Protects sensitive files from being read, modified, or exfiltrated:

**File Patterns:**

| Level | Decision | Examples |
|-------|----------|----------|
| critical | deny | `.env`, `.ssh/id_*`, `.aws/credentials`, `.kube/config`, `*.pem`, `*.key` |
| high | ask | `credentials.json`, `secrets.yml`, service accounts, `.netrc`, Terraform state, FileZilla XML |
| strict | ask | `database.yml`, `.gitconfig`, `.ssh/known_hosts`, `mongoid.yml`, `database.env` |

**Bash Patterns (secrets exfiltration):**

| Level | Decision | Examples |
|-------|----------|----------|
| critical | deny | `cat .env`, `cat id_rsa`, `cat .aws/credentials` |
| high | ask | `printenv`, `source .env`, `curl -d @.env`, `scp` secrets, `rsync` secrets, `kubectl get secrets` |
| strict | ask | `grep -r password`, `base64 encoding`, `docker login`, `mysql -p` in cmdline |

## Project Structure

```
protective-hooks/
├── .claude-plugin/
│   ├── plugin.json          # Plugin manifest
│   └── marketplace.json     # Marketplace manifest
├── hooks/
│   └── hooks.json           # Hook configuration
├── scripts/
│   └── pre-tool-use/
│       ├── block-dangerous-commands.js  # Bash danger blocker
│       └── protect-secrets.js            # Secret protection
└── README.md
```

## Requirements

- **Node.js**: 14+ (for running hook scripts)
- **Claude Code**: Latest version with plugin support

## Acknowledgments

These hooks are based on [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks).

## License

MIT
