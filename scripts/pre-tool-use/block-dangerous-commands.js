#!/usr/bin/env node
/**
 * Block Dangerous Commands - PreToolUse Hook for Bash
 * Blocks dangerous patterns before execution. Logs to: ~/.claude/hooks-logs/
 *
 * SAFETY_LEVEL: 'critical' | 'high' | 'strict'
 *   critical - Only catastrophic: rm -rf ~, dd to disk, fork bombs
 *   high     - + risky: force push main, secrets exposure, git reset --hard
 *   strict   - + cautionary: any force push, sudo rm, docker prune
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Bash",
 *       "hooks": [{ "type": "command", "command": "node /path/to/block-dangerous-commands.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');

const SAFETY_LEVEL = 'strict';

const PATTERNS = [
  // CRITICAL - Catastrophic, unrecoverable (always deny)
  {
    level: 'critical', decision: 'deny', patterns: [
      { id: 'rm-home',          regex: /\brm\s+(-.+\s+)*["']?~\/?["']?(\s|$|[;&|])/,             reason: 'rm targeting home directory' },
      { id: 'rm-home-var',      regex: /\brm\s+(-.+\s+)*["']?\$HOME["']?(\s|$|[;&|])/,           reason: 'rm targeting $HOME' },
      { id: 'rm-home-trailing', regex: /\brm\s+.+\s+["']?(~\/?|\$HOME)["']?(\s*$|[;&|])/,        reason: 'rm with trailing ~/ or $HOME' },
      { id: 'rm-root',          regex: /\brm\s+(-.+\s+)*\/(\*|\s|$|[;&|])/,                       reason: 'rm targeting root filesystem' },
      { id: 'rm-system',        regex: /\brm\s+(-.+\s+)*\/(etc|usr|var|bin|sbin|lib|boot|dev|proc|sys)(\/|\s|$)/, reason: 'rm targeting system directory' },
      { id: 'rm-cwd',           regex: /\brm\s+(-.+\s+)*(\.\/?|\*|\.\/\*)(\s|$|[;&|])/,           reason: 'rm deleting current directory contents' },
      { id: 'dd-disk',          regex: /\bdd\b.+of=\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z]|xvd[a-z])/, reason: 'dd writing to disk device' },
      { id: 'mkfs',             regex: /\bmkfs(\.\w+)?\s+\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z])/,  reason: 'mkfs formatting disk' },
      { id: 'fork-bomb',        regex: /:\(\)\s*\{.*:\s*\|\s*:.*&/,                                reason: 'fork bomb detected' },
    ]
  },
  // HIGH - Significant risk, data loss, security (ask)
  {
    level: 'high', decision: 'ask', patterns: [
      { id: 'curl-pipe-sh',   regex: /\b(curl|wget)\b.+\|\s*(ba)?sh\b/,                              reason: 'piping URL to shell (RCE risk)' },
      { id: 'git-force-main', regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b.+\b(main|master)\b/, reason: 'force push to main/master' },
      { id: 'git-reset-hard', regex: /\bgit\s+reset\s+--hard/,                                        reason: 'git reset --hard loses uncommitted work' },
      { id: 'git-clean-f',    regex: /\bgit\s+clean\s+(-\w*f|-f)/,                                    reason: 'git clean -f deletes untracked files' },
      { id: 'chmod-777',      regex: /\bchmod\b.+\b777\b/,                                            reason: 'chmod 777 is a security risk' },
      { id: 'cat-env',        regex: /\b(cat|less|head|tail|more)\s+\.env\b/,                         reason: 'reading .env file exposes secrets' },
      { id: 'cat-secrets',    regex: /\b(cat|less|head|tail|more)\b.+(credentials|secrets?|\.pem|\.key|id_rsa|id_ed25519)/i, reason: 'reading secrets file' },
      { id: 'env-dump',       regex: /\b(printenv|^env)\s*([;&|]|$)/,                                 reason: 'env dump may expose secrets' },
      { id: 'echo-secret',    regex: /\becho\b.+\$\w*(SECRET|KEY|TOKEN|PASSWORD|API_|PRIVATE)/i,     reason: 'echoing secret variable' },
      { id: 'docker-vol-rm',  regex: /\bdocker\s+volume\s+(rm|prune)/,                               reason: 'docker volume deletion loses data' },
      { id: 'rm-ssh',         regex: /\brm\b.+\.ssh\/(id_|authorized_keys|known_hosts)/,              reason: 'deleting SSH keys' },
      { id: 'kubectl-secrets', regex: /\bkubectl\s+(get|describe)\s+.*secrets/i,                      reason: 'reading Kubernetes secrets' },
      { id: 'vault-read',     regex: /\bvault\s+(read|list)\b/,                                        reason: 'accessing Vault secrets' },
      { id: 'docker-exec-sh', regex: /\bdocker\s+exec\b.+\b(sh|bash|\/bin\/)/i,                      reason: 'docker exec shell escape risk' },
      { id: 'heroku-config',  regex: /\bheroku\s+config\b/,                                          reason: 'Heroku config exposes env vars' },
      { id: 'adb-run-as',    regex: /\badb\s+shell\s+.*\brun-as\b/i,                                  reason: 'Android run-as switch context' },
      { id: 'init-system',   regex: /\bsystemctl\s+(start|stop|restart)\b.*\bservice\b/i,                reason: 'systemctl service manipulation' },
    ]
  },
  // STRICT - Cautionary, context-dependent (ask)
  {
    level: 'strict', decision: 'ask', patterns: [
      { id: 'git-force-any',    regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b/,     reason: 'force push (use --force-with-lease)' },
      { id: 'git-checkout-dot', regex: /\bgit\s+checkout\s+\./,                                      reason: 'git checkout . discards changes' },
      { id: 'sudo-rm',          regex: /\bsudo\s+rm\b/,                                               reason: 'sudo rm has elevated privileges' },
      { id: 'docker-prune',     regex: /\bdocker\s+(system|image)\s+prune/,                            reason: 'docker prune removes images' },
      { id: 'crontab-r',        regex: /\bcrontab\s+-r/,                                              reason: 'removes all cron jobs' },
      { id: 'crontab-l',        regex: /\bcrontab\s+-l\b(?!\s+-r)/,                                   reason: 'crontab -l may reveal paths and jobs' },
      { id: 'pkill',            regex: /\bpkill\b/,                                                    reason: 'pkill terminates processes' },
    ]
  },
];

const LEVELS = { critical: 1, high: 2, strict: 3 };
const EMOJIS = { critical: '🚨', high: '⛔', strict: '⚠️' };
const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...data }) + '\n');
  } catch {}
}

function checkCommand(cmd, safetyLevel = SAFETY_LEVEL) {
  const threshold = LEVELS[safetyLevel] || 2;
  for (const group of PATTERNS) {
    if (LEVELS[group.level] <= threshold) {
      for (const p of group.patterns) {
        if (p.regex.test(cmd)) {
          return { blocked: true, pattern: { ...p, level: group.level, decision: group.decision } };
        }
      }
    }
  }
  return { blocked: false, pattern: null };
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name, tool_input, session_id, cwd, permission_mode } = data;
    if (tool_name !== 'Bash') return console.log('{}');

    const cmd = tool_input?.command || '';
    const result = checkCommand(cmd);

    if (result.blocked) {
      const p = result.pattern;
      log({ level: 'BLOCKED', id: p.id, priority: p.level, cmd, session_id, cwd, permission_mode });
      return console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: p.decision,
          permissionDecisionReason: `${EMOJIS[p.level]} [${p.id}] ${p.reason}`
        }
      }));
    }
    console.log('{}');
  } catch (e) {
    log({ level: 'ERROR', error: e.message });
    console.log('{}');
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = { PATTERNS, LEVELS, SAFETY_LEVEL, checkCommand };
}
