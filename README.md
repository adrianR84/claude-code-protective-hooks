# Claude Code Protective Hooks

A Claude Code plugin providing PreToolUse security hooks to block dangerous commands and protect sensitive files.

## Features

- **Block Dangerous Commands**: Prevents execution of catastrophic commands like `rm -rf /`, `dd` to disk devices, fork bombs
- **Protect Secrets**: Guards against reading/modifying sensitive files (.env, SSH keys, AWS credentials, etc.)
- **Configurable Safety Levels**: Choose from `critical`, `high`, or `strict` protection levels
- **Comprehensive Patterns**: Detects secret exfiltration attempts, dangerous git operations, and more
- **Logging**: All blocked operations are logged to `~/.claude/hooks-logs/`

## Safety Levels

| Level | Description |
|-------|-------------|
| `critical` | Blocks catastrophic operations: rm -rf ~, dd to disk, fork bombs |
| `high` | Blocks risky operations: force push, git reset --hard, secrets exposure |
| `strict` | Blocks cautionary operations: any force push, sudo rm, docker prune |

## Installation

### Option 1: Local Installation (Testing)

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
   /plugin install protective-hooks@protective-hooks
   ```

### Option 2: From a GitHub Repository

```bash
/plugin marketplace add adrianR84/claude-code-protective-hooks
/plugin install protective-hooks@protective-hooks
```

### Option 3: Session-Only (No Install)

```bash
git clone https://github.com/adrianR84/claude-code-protective-hooks.git
cd claude-code-protective-hooks
claude --plugin-dir .
```

## Configuration

The hooks are automatically enabled after installation. To customize:

1. Edit `scripts/pre-tool-use/block-dangerous-commands.js` to adjust `SAFETY_LEVEL`
2. Edit `scripts/pre-tool-use/protect-secrets.js` to adjust `SAFETY_LEVEL`

```javascript
const SAFETY_LEVEL = 'critical'; // 'critical' | 'high' | 'strict'
```

## Hooks Overview

### block-dangerous-commands.js (Bash)

Blocks dangerous bash commands before execution:

- **Critical**: `rm -rf /`, `dd` to disk, `mkfs`, fork bombs
- **High**: `curl|wget | bash`, force push to main/master, `git reset --hard`, `chmod 777`
- **Strict**: Any force push, `sudo rm`, `docker prune`

### protect-secrets.js (Edit|Write|Bash)

Protects sensitive files from being read, modified, or exfiltrated:

- **Critical**: `.env`, `.ssh/id_*`, `.aws/credentials`, `.kube/config`, `*.pem`, `*.key`
- **High**: `credentials.json`, `secrets.yml`, service account keys, `.netrc`, `docker-config`
- **Strict**: `database.yml`, `.gitconfig`, `.ssh/known_hosts`

Also detects secret exfiltration via:
- `cat .env`, `source .env`
- `curl -d @.env`, `scp` with secrets
- Environment variable dumps (`printenv`)

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
