#!/usr/bin/env node
/**
 * Protect Secrets - PreToolUse Hook for Read|Edit|Write|Bash
 * Prevents reading, modifying, or exfiltrating sensitive files.
 * Logs to: ~/.claude/hooks-logs/
 *
 * SAFETY_LEVEL: 'critical' | 'high' | 'strict'
 *   critical - SSH keys, AWS creds, .env files only
 *   high     - + secrets files, env dumps, exfiltration attempts
 *   strict   - + database configs, any config that might contain secrets
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Read|Edit|Write|Bash",
 *       "hooks": [{ "type": "command", "command": "node /path/to/protect-secrets.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');

const SAFETY_LEVEL = 'strict';

// Files explicitly safe to access (templates, examples)
const ALLOWLIST = [
  /\.env\.example$/i, /\.env\.sample$/i, /\.env\.template$/i,
  /\.env\.schema$/i, /\.env\.defaults$/i, /env\.example$/i, /example\.env$/i,
];

const SENSITIVE_FILES = [
  // CRITICAL - deny
  {
    level: 'critical', decision: 'deny', patterns: [
      { id: 'env-file',          regex: /(?:^|\/)\.env(?:\.[^/]*)?$/,                reason: '.env file contains secrets' },
      { id: 'envrc',             regex: /(?:^|\/)\.envrc$/,                          reason: '.envrc (direnv) contains secrets' },
      { id: 'ssh-private-key',   regex: /(?:^|\/)\.ssh\/id_[^/]+$/,                  reason: 'SSH private key' },
      { id: 'ssh-private-key-2', regex: /(?:^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$/, reason: 'SSH private key' },
      { id: 'ssh-authorized',    regex: /(?:^|\/)\.ssh\/authorized_keys$/,           reason: 'SSH authorized_keys' },
      { id: 'aws-credentials',   regex: /(?:^|\/)\.aws\/credentials$/,                reason: 'AWS credentials file' },
      { id: 'aws-config',        regex: /(?:^|\/)\.aws\/config$/,                     reason: 'AWS config may contain secrets' },
      { id: 'kube-config',       regex: /(?:^|\/)\.kube\/config$/,                   reason: 'Kubernetes config contains credentials' },
      { id: 'pem-key',           regex: /\.pem$/i,                                   reason: 'PEM key file' },
      { id: 'key-file',          regex: /\.key$/i,                                   reason: 'Key file' },
      { id: 'p12-key',           regex: /\.(p12|pfx)$/i,                            reason: 'PKCS12 key file' },
    ]
  },
  // HIGH - ask
  {
    level: 'high', decision: 'ask', patterns: [
      { id: 'credentials-json',  regex: /(?:^|\/)credentials\.json$/i,               reason: 'Credentials file' },
      { id: 'secrets-file',     regex: /(?:^|\/)(secrets?|credentials?)\.(json|ya?ml|toml)$/i, reason: 'Secrets configuration file' },
      { id: 'service-account',   regex: /service[_-]?account.*\.json$/i,             reason: 'GCP service account key' },
      { id: 'gcloud-creds',      regex: /(?:^|\/)\.config\/gcloud\/.*(credentials|tokens)/i, reason: 'GCloud credentials' },
      { id: 'azure-creds',       regex: /(?:^|\/)\.azure\/(credentials|accessTokens)/i, reason: 'Azure credentials' },
      { id: 'docker-config',     regex: /(?:^|\/)\.docker\/config\.json$/,           reason: 'Docker config may contain registry auth' },
      { id: 'netrc',             regex: /(?:^|\/)\.netrc$/,                          reason: '.netrc contains credentials' },
      { id: 'npmrc',             regex: /(?:^|\/)\.npmrc$/,                          reason: '.npmrc may contain auth tokens' },
      { id: 'pypirc',            regex: /(?:^|\/)\.pypirc$/,                         reason: '.pypirc contains PyPI credentials' },
      { id: 'gem-creds',         regex: /(?:^|\/)\.gem\/credentials$/,               reason: 'RubyGems credentials' },
      { id: 'vault-token',       regex: /(?:^|\/)(\.vault-token|vault-token)$/,       reason: 'Vault token file' },
      { id: 'keystore',          regex: /\.(keystore|jks)$/i,                        reason: 'Java keystore' },
      { id: 'htpasswd',          regex: /(?:^|\/)\.?htpasswd$/,                      reason: 'htpasswd contains hashed passwords' },
      { id: 'pgpass',            regex: /(?:^|\/)\.pgpass$/,                          reason: 'PostgreSQL password file' },
      { id: 'my-cnf',            regex: /(?:^|\/)\.my\.cnf$/,                         reason: 'MySQL config may contain password' },
      { id: 'terraform-tfstate', regex: /(?:^|\/)terraform.*\.tfstate$/i,            reason: 'Terraform state may contain secrets' },
      { id: 'filezilla-xml',    regex: /(?:^|\/)filezilla\.xml$/i,                   reason: 'FileZilla FTP credentials' },
      { id: 's3cfg',           regex: /(?:^|\/)s3cfg$/i,                             reason: 'S3 cmdline config file' },
      { id: 'pipenv-env',      regex: /(?:^|\/)Pipfile\.env$/i,                    reason: 'Pipenv env file contains secrets' },
      { id: 'google-creds',    regex: /(?:^|\/)\.google\/credentials$/i,           reason: 'GCP service account credentials' },
      { id: 'git-credentials', regex: /(?:^|\/)\.git-credentials$/i,               reason: 'Git credential store' },
      { id: 'npm-auth',       regex: /(?:^|\/)\.npm\/(_auth|_cacert)$/i,          reason: 'npm registry authentication' },
    ]
  },
  // STRICT - ask
  {
    level: 'strict', decision: 'ask', patterns: [
      { id: 'database-config',   regex: /(?:^|\/)(?:config\/)?database\.(json|ya?ml)$/i, reason: 'Database config may contain passwords' },
      { id: 'ssh-known-hosts',   regex: /(?:^|\/)\.ssh\/known_hosts$/,                reason: 'SSH known_hosts reveals infrastructure' },
      { id: 'gitconfig',        regex: /(?:^|\/)\.gitconfig$/,                       reason: '.gitconfig may contain credentials' },
      { id: 'curlrc',            regex: /(?:^|\/)\.curlrc$/,                          reason: '.curlrc may contain auth' },
      { id: 'mongoid-yml',       regex: /(?:^|\/)mongoid\.yml$/i,                    reason: 'MongoDB connection string' },
      { id: 'database-url',      regex: /(?:^|\/)database.*\.env$/i,                  reason: 'Database URL env file' },
    ]
  },
];

const BASH_PATTERNS = [
  // CRITICAL - deny
  {
    level: 'critical', decision: 'deny', patterns: [
      { id: 'cat-env',      regex: /\b(cat|less|head|tail|more|bat|view)\s+[^|;]*\.env\b/i,             reason: 'Reading .env file exposes secrets' },
      { id: 'cat-ssh-key',  regex: /\b(cat|less|head|tail|more|bat)\s+[^|;]*(id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key)\b/i, reason: 'Reading private key' },
      { id: 'cat-aws-creds', regex: /\b(cat|less|head|tail|more)\s+[^|;]*\.aws\/credentials/i,          reason: 'Reading AWS credentials' },
    ]
  },
  // HIGH - ask
  {
    level: 'high', decision: 'ask', patterns: [
      { id: 'env-dump',         regex: /\bprintenv\b|(?:^|[;&|]\s*)env\s*(?:$|[;&|])/,                   reason: 'Environment dump may expose secrets' },
      { id: 'echo-secret-var', regex: /\becho\b[^;|&]*\$\{?[A-Za-z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSW|CREDENTIAL|API_KEY|AUTH|PRIVATE)[A-Za-z_]*\}?/i, reason: 'Echoing secret variable' },
      { id: 'printf-secret-var', regex: /\bprintf\b[^;|&]*\$\{?[A-Za-z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH|PRIVATE)[A-Za-z_]*\}?/i, reason: 'Printing secret variable' },
      { id: 'cat-secrets-file', regex: /\b(cat|less|head|tail|more)\s+[^|;]*(credentials?|secrets?)\.(json|ya?ml|toml)/i, reason: 'Reading secrets file' },
      { id: 'cat-netrc',        regex: /\b(cat|less|head|tail|more)\s+[^|;]*\.netrc/i,                  reason: 'Reading .netrc credentials' },
      { id: 'source-env',       regex: /\bsource\s+[^|;]*\.env\b|(?:^|[;&|]\s*)\.\s+[^|;]*\.env\b|^\.\s+[^|;]*\.env\b/i, reason: 'Sourcing .env loads secrets' },
      { id: 'export-cat-env',   regex: /export\s+.*\$\(cat\s+[^)]*\.env/i,                               reason: 'Exporting secrets from .env' },

      { id: 'curl-upload-env',  regex: /\bcurl\b[^;|&]*(-d\s*@|-F\s*[^=]+=@|--data[^=]*=@)[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)/i, reason: 'Uploading secrets via curl' },
      { id: 'curl-post-secrets', regex: /\bcurl\b[^;|&]*-X\s*POST[^;|&]*[^;|&]*(\.env|credentials|secrets)/i, reason: 'POSTing secrets via curl' },
      { id: 'wget-post-secrets', regex: /\bwget\b[^;|&]*--post-file[^;|&]*(\.env|credentials|secrets)/i, reason: 'POSTing secrets via wget' },
      { id: 'scp-secrets',      regex: /\bscp\b[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)[^;|&]+:/i, reason: 'Copying secrets via scp' },
      { id: 'rsync-secrets',    regex: /\brsync\b[^;|&]*(\.env|credentials|secrets|id_rsa)[^;|&]+:/i,  reason: 'Syncing secrets via rsync' },
      { id: 'nc-secrets',       regex: /\bnc\b[^;|&]*<[^;|&]*(\.env|credentials|secrets|id_rsa)/i,     reason: 'Exfiltrating secrets via netcat' },

      { id: 'cp-env',           regex: /\bcp\b[^;|&]*\.env\b/i,                                           reason: 'Copying .env file' },
      { id: 'cp-ssh-key',       regex: /\bcp\b[^;|&]*(id_rsa|id_ed25519|\.pem|\.key)\b/i,                reason: 'Copying private key' },
      { id: 'mv-env',           regex: /\bmv\b[^;|&]*\.env\b/i,                                           reason: 'Moving .env file' },
      { id: 'rm-ssh-key',       regex: /\brm\b[^;|&]*(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,    reason: 'Deleting SSH key' },
      { id: 'rm-env',           regex: /\brm\b.*\.env\b/i,                                                reason: 'Deleting .env file' },
      { id: 'rm-aws-creds',     regex: /\brm\b[^;|&]*\.aws\/credentials/i,                                reason: 'Deleting AWS credentials' },
      { id: 'truncate-secrets', regex: /\btruncate\b.*\.(env|pem|key)\b|(?:^|[;&|]\s*)>\s*\.env\b/i,     reason: 'Truncating secrets file' },

      { id: 'proc-environ',      regex: /\/proc\/[^/]*\/environ/,                                          reason: 'Reading process environment' },
      { id: 'xargs-cat-env',    regex: /xargs.*cat|\.env.*xargs/i,                                        reason: 'Reading .env via xargs' },
      { id: 'find-exec-cat-env', regex: /find\b.*\.env.*-exec|find\b.*-exec.*(cat|less)/i,               reason: 'Finding and reading .env files' },
      { id: 'aws-secretsmanager', regex: /\baws\s+secretsmanager\b/i,                                    reason: 'AWS Secrets Manager access' },
      { id: 'kubectl-proxy-secret', regex: /\bkubectl\s+proxy\b.*secret/i,                               reason: 'Proxy to Kubernetes secret endpoint' },
    ]
  },
  // STRICT - ask
  {
    level: 'strict', decision: 'ask', patterns: [
      { id: 'grep-password',   regex: /\bgrep\b[^|;]*(-r|--recursive)[^|;]*(password|secret|api.?key|token|credential)/i, reason: 'Grep for secrets may expose them' },
      { id: 'base64-secrets', regex: /\bbase64\b[^|;]*(\.env|credentials|secrets|id_rsa|\.pem)/i,       reason: 'Base64 encoding secrets' },
      { id: 'kubectl-json-secret', regex: /\bkubectl\b[^|;]*(-o\s+json|-o\s+yaml)[^|;]*(secret|config)/i, reason: 'Kubectl output may contain secrets' },
      { id: 'base64-decode-env', regex: /\bbase64\b.*-d.*\.env|\.env.*base64.*-d/i,                       reason: 'Decoding .env file reveals secrets' },
      { id: 'env-from-secret', regex: /\bkubectl\b[^|;]*\bsecret\b[^|;]*\benv\b/i,                       reason: 'Extracting env from k8s secret' },
      { id: 'docker-login',   regex: /\bdocker\s+login\b/,                                               reason: 'Docker registry login exposes auth' },
      { id: 'mysql-password', regex: /\bmysql\b[^|;]*-p[^\s][^|;]*/,                                    reason: 'mysql password in command line' },
    ]
  },
];

const LEVELS = { critical: 1, high: 2, strict: 3 };
const EMOJIS = { critical: '🔐', high: '🛡️', strict: '⚠️' };
const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'protect-secrets', ...data }) + '\n');
  } catch {}
}

function isAllowlisted(filePath) {
  return filePath && ALLOWLIST.some(p => p.test(filePath));
}

function checkFilePath(filePath, safetyLevel = SAFETY_LEVEL) {
  if (!filePath || isAllowlisted(filePath)) return { blocked: false, pattern: null };
  const threshold = LEVELS[safetyLevel] || 2;
  for (const group of SENSITIVE_FILES) {
    if (LEVELS[group.level] <= threshold) {
      for (const p of group.patterns) {
        if (p.regex.test(filePath)) {
          return { blocked: true, pattern: { ...p, level: group.level, decision: group.decision } };
        }
      }
    }
  }
  return { blocked: false, pattern: null };
}

function checkBashCommand(cmd, safetyLevel = SAFETY_LEVEL) {
  if (!cmd) return { blocked: false, pattern: null };
  for (const allow of ALLOWLIST) {
    if (allow.test(cmd)) return { blocked: false, pattern: null };
  }
  const threshold = LEVELS[safetyLevel] || 2;
  for (const group of BASH_PATTERNS) {
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

function check(toolName, toolInput, safetyLevel = SAFETY_LEVEL) {
  if (['Read', 'Edit', 'Write'].includes(toolName)) {
    return checkFilePath(toolInput?.file_path, safetyLevel);
  }
  if (toolName === 'Bash') {
    return checkBashCommand(toolInput?.command, safetyLevel);
  }
  return { blocked: false, pattern: null };
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name, tool_input, session_id, cwd, permission_mode } = data;

    if (!['Read', 'Edit', 'Write', 'Bash'].includes(tool_name)) {
      return console.log('{}');
    }

    const result = check(tool_name, tool_input);

    if (result.blocked) {
      const p = result.pattern;
      const target = tool_input?.file_path || tool_input?.command?.slice(0, 100);
      log({ level: 'BLOCKED', id: p.id, priority: p.level, tool: tool_name, target, session_id, cwd, permission_mode });

      const action = { Read: 'read', Edit: 'modify', Write: 'write to', Bash: 'execute' }[tool_name];
      return console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: p.decision,
          permissionDecisionReason: `${EMOJIS[p.level]} [${p.id}] Cannot ${action}: ${p.reason}`
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
  module.exports = {
    SENSITIVE_FILES, BASH_PATTERNS, ALLOWLIST, LEVELS, SAFETY_LEVEL,
    check, checkFilePath, checkBashCommand, isAllowlisted,
  };
}
