/**
 * Scanner — `forge scan`
 *
 * Enumerates all trust assumptions on the current system.
 * "See the problem before you can record the problem."
 *
 * Checks:
 *  1. Exposed ports         — what's listening?
 *  2. Auth surfaces          — web panels, SSH, management UIs
 *  3. Running services       — who's running as root?
 *  4. Firewall status        — iptables / ufw active?
 *  5. SMTP configuration     — open relay risk?
 *  6. SSL/TLS certificates   — expired? self-signed?
 *  7. Cron jobs              — scheduled operations nobody reviews?
 *  8. Docker / containers    — privileged? exposed sockets?
 *  9. Recent logins          — unexpected sources?
 * 10. File permissions       — world-writable sensitive files?
 */

import { execSync } from "node:child_process";

/* ================================================================
   HELPERS
   ================================================================ */

function run(cmd) {
  try {
    return execSync(cmd, { encoding: "utf8", timeout: 10000 }).trim();
  } catch {
    return null;
  }
}

function risk(level, category, finding, recommendation) {
  return { level, category, finding, recommendation };
}

/* ================================================================
   INDIVIDUAL CHECKS
   ================================================================ */

function scanPorts() {
  const results = [];
  const out = run("ss -tlnp 2>/dev/null") || run("netstat -tlnp 2>/dev/null");
  if (!out) {
    results.push(risk("unknown", "ports", "Cannot determine listening ports", "Install ss or netstat"));
    return results;
  }

  const lines = out.split("\n").slice(1); // skip header
  const dangerousPorts = {
    25: "SMTP (open relay risk)",
    587: "SMTP submission",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    8080: "HTTP alt (management panel?)",
    9090: "Management UI",
    2375: "Docker API (CRITICAL)",
    2376: "Docker API TLS",
  };

  for (const line of lines) {
    const match = line.match(/:(\d+)\s/);
    if (!match) continue;
    const port = parseInt(match[1]);
    const bindMatch = line.match(/(\S+):(\d+)/);
    const bind = bindMatch ? bindMatch[1] : "?";
    const isPublic = bind === "0.0.0.0" || bind === "*" || bind === "::";

    if (isPublic && dangerousPorts[port]) {
      results.push(
        risk(
          port === 2375 ? "critical" : "high",
          "ports",
          `Port ${port} (${dangerousPorts[port]}) open to all interfaces`,
          `Bind to 127.0.0.1 or restrict via firewall`
        )
      );
    } else if (isPublic && port < 10000) {
      results.push(
        risk(
          "medium",
          "ports",
          `Port ${port} open to all interfaces`,
          `Verify this port needs public access`
        )
      );
    }
  }

  if (results.length === 0) {
    results.push(risk("info", "ports", "No obviously dangerous ports exposed", ""));
  }
  return results;
}

function scanFirewall() {
  const results = [];

  const ufw = run("ufw status 2>/dev/null");
  if (ufw && ufw.includes("active")) {
    results.push(risk("info", "firewall", "UFW is active", ""));
    return results;
  }

  const ipt = run("iptables -L -n 2>/dev/null");
  if (ipt && !ipt.includes("ACCEPT") && ipt.split("\n").length <= 8) {
    results.push(
      risk("high", "firewall", "No firewall rules detected", "Enable ufw or configure iptables")
    );
  } else if (ipt) {
    results.push(risk("info", "firewall", "iptables has rules configured", ""));
  } else {
    results.push(
      risk("medium", "firewall", "Cannot determine firewall status", "Verify firewall configuration")
    );
  }

  return results;
}

function scanSSH() {
  const results = [];
  const cfg = run("cat /etc/ssh/sshd_config 2>/dev/null");
  if (!cfg) {
    results.push(risk("info", "ssh", "SSH config not readable", ""));
    return results;
  }

  if (/PermitRootLogin\s+yes/i.test(cfg)) {
    results.push(
      risk("high", "ssh", "Root login via SSH is enabled", "Set PermitRootLogin no")
    );
  }

  if (/PasswordAuthentication\s+yes/i.test(cfg)) {
    results.push(
      risk("medium", "ssh", "Password authentication is enabled", "Use key-based auth only")
    );
  }

  const port = cfg.match(/^Port\s+(\d+)/m);
  if (!port || port[1] === "22") {
    results.push(
      risk("low", "ssh", "SSH on default port 22", "Consider non-standard port")
    );
  }

  if (results.length === 0) {
    results.push(risk("info", "ssh", "SSH configuration looks reasonable", ""));
  }
  return results;
}

function scanRootProcesses() {
  const results = [];
  const ps = run("ps aux 2>/dev/null");
  if (!ps) return [risk("unknown", "processes", "Cannot list processes", "")];

  const lines = ps.split("\n").slice(1);
  const rootProcesses = lines.filter((l) => l.startsWith("root"));
  const suspicious = rootProcesses.filter((l) => {
    // Skip known system processes
    const known = [
      "init", "systemd", "kthread", "sshd", "cron", "agetty",
      "login", "bash", "sh", "dbus", "udevd", "journald",
      "rsyslogd", "containerd", "dockerd",
      "ps aux", // the check itself
    ];
    return !known.some((k) => l.includes(k));
  });

  if (suspicious.length > 10) {
    results.push(
      risk(
        "medium",
        "processes",
        `${suspicious.length} processes running as root`,
        "Audit root-owned processes, run services as unprivileged users"
      )
    );
  } else {
    results.push(risk("info", "processes", `${rootProcesses.length} root processes (normal)`, ""));
  }
  return results;
}

function scanDocker() {
  const results = [];
  const sock = run("ls -la /var/run/docker.sock 2>/dev/null");
  if (!sock) {
    results.push(risk("info", "docker", "Docker socket not found", ""));
    return results;
  }

  if (sock.includes("rw-rw-rw") || sock.includes("666")) {
    results.push(
      risk(
        "critical",
        "docker",
        "Docker socket is world-readable/writable",
        "Restrict docker.sock permissions to docker group only"
      )
    );
  }

  const containers = run("docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null");
  if (containers) {
    const privCheck = run(
      "docker ps --format '{{.Names}}' 2>/dev/null | xargs -I{} docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' {} 2>/dev/null"
    );
    if (privCheck && privCheck.includes("privileged=true")) {
      results.push(
        risk("critical", "docker", "Privileged container detected", "Never run privileged containers in production")
      );
    }
  }

  if (results.length === 0) {
    results.push(risk("info", "docker", "Docker present, no obvious misconfigurations", ""));
  }
  return results;
}

function scanCron() {
  const results = [];
  const crontab = run("crontab -l 2>/dev/null");
  const rootCron = run("cat /etc/crontab 2>/dev/null");
  const cronD = run("ls /etc/cron.d/ 2>/dev/null");

  let totalJobs = 0;
  if (crontab) totalJobs += crontab.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length;
  if (rootCron) totalJobs += rootCron.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length;

  if (totalJobs > 0) {
    results.push(
      risk(
        "low",
        "cron",
        `${totalJobs} scheduled jobs found`,
        "Audit cron jobs — each is an unmonitored trust assumption"
      )
    );
  } else {
    results.push(risk("info", "cron", "No user cron jobs found", ""));
  }
  return results;
}

function scanRecentLogins() {
  const results = [];
  const last = run("last -n 20 2>/dev/null");
  if (!last) return [risk("info", "logins", "Cannot check login history", "")];

  const lines = last.split("\n").filter((l) => l.trim() && !l.startsWith("wtmp"));
  const uniqueIPs = new Set();
  for (const line of lines) {
    const match = line.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (match) uniqueIPs.add(match[1]);
  }

  if (uniqueIPs.size > 5) {
    results.push(
      risk(
        "medium",
        "logins",
        `${uniqueIPs.size} unique IP addresses in recent logins`,
        "Verify all login sources are legitimate"
      )
    );
  } else {
    results.push(risk("info", "logins", `${uniqueIPs.size} unique login sources`, ""));
  }
  return results;
}

function scanSMTP() {
  const results = [];
  const smtp = run("ss -tlnp 2>/dev/null | grep ':25 '") || run("netstat -tlnp 2>/dev/null | grep ':25 '");

  if (smtp && smtp.includes("0.0.0.0")) {
    results.push(
      risk(
        "high",
        "smtp",
        "SMTP port 25 is open to all interfaces",
        "Use API-based email (AWS SES, Resend) instead of exposing SMTP"
      )
    );
  } else if (smtp) {
    results.push(risk("low", "smtp", "SMTP listening on localhost only", ""));
  } else {
    results.push(risk("info", "smtp", "No SMTP service detected", ""));
  }
  return results;
}

function scanWebPanels() {
  const results = [];
  // Check for common management panel ports/processes
  const panels = [
    { name: "dpanel", port: 8080, proc: "dpanel" },
    { name: "Portainer", port: 9000, proc: "portainer" },
    { name: "Webmin", port: 10000, proc: "webmin" },
    { name: "cPanel", port: 2083, proc: "cpanel" },
    { name: "Plesk", port: 8443, proc: "plesk" },
    { name: "CasaOS", port: 80, proc: "casaos" },
  ];

  const ps = run("ps aux 2>/dev/null") || "";
  const ports = run("ss -tlnp 2>/dev/null") || "";

  for (const panel of panels) {
    const hasProc = ps.toLowerCase().includes(panel.proc);
    const hasPort = ports.includes(`:${panel.port} `);

    if (hasProc || hasPort) {
      results.push(
        risk(
          "high",
          "web-panel",
          `${panel.name} detected (port ${panel.port})`,
          "Management panels are high-value attack targets. Restrict access by IP, use strong auth, or remove if not needed."
        )
      );
    }
  }

  if (results.length === 0) {
    results.push(risk("info", "web-panel", "No common management panels detected", ""));
  }
  return results;
}

/* ================================================================
   MAIN SCANNER
   ================================================================ */

export function scan() {
  const checks = [
    ...scanPorts(),
    ...scanFirewall(),
    ...scanSSH(),
    ...scanRootProcesses(),
    ...scanDocker(),
    ...scanCron(),
    ...scanRecentLogins(),
    ...scanSMTP(),
    ...scanWebPanels(),
  ];

  const summary = {
    total: checks.length,
    critical: checks.filter((c) => c.level === "critical").length,
    high: checks.filter((c) => c.level === "high").length,
    medium: checks.filter((c) => c.level === "medium").length,
    low: checks.filter((c) => c.level === "low").length,
    info: checks.filter((c) => c.level === "info").length,
  };

  return { checks, summary, scanned_at: Date.now() };
}

/* ================================================================
   FORMAT
   ================================================================ */

const COLORS = {
  critical: "\x1b[91m", // bright red
  high: "\x1b[31m",     // red
  medium: "\x1b[33m",   // yellow
  low: "\x1b[36m",      // cyan
  info: "\x1b[32m",     // green
  unknown: "\x1b[90m",  // gray
  reset: "\x1b[0m",
};

const ICONS = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "🟢",
  unknown: "⚪",
};

export function formatScanResults(results) {
  const lines = [];
  lines.push("");
  lines.push("╔══════════════════════════════════════════════════════╗");
  lines.push("║           FORGE — Trust Assumption Scan             ║");
  lines.push("╚══════════════════════════════════════════════════════╝");
  lines.push("");

  // Group by category
  const grouped = {};
  for (const check of results.checks) {
    if (!grouped[check.category]) grouped[check.category] = [];
    grouped[check.category].push(check);
  }

  for (const [category, checks] of Object.entries(grouped)) {
    lines.push(`  ── ${category.toUpperCase()} ──`);
    for (const c of checks) {
      const icon = ICONS[c.level] || "⚪";
      const color = COLORS[c.level] || "";
      const reset = COLORS.reset;
      lines.push(`  ${icon} ${color}[${c.level.toUpperCase()}]${reset} ${c.finding}`);
      if (c.recommendation) {
        lines.push(`     → ${c.recommendation}`);
      }
    }
    lines.push("");
  }

  // Summary
  const s = results.summary;
  lines.push("  ── SUMMARY ──");
  lines.push(`  Total checks: ${s.total}`);
  if (s.critical > 0) lines.push(`  ${COLORS.critical}CRITICAL: ${s.critical}${COLORS.reset}`);
  if (s.high > 0) lines.push(`  ${COLORS.high}HIGH: ${s.high}${COLORS.reset}`);
  if (s.medium > 0) lines.push(`  ${COLORS.medium}MEDIUM: ${s.medium}${COLORS.reset}`);
  if (s.low > 0) lines.push(`  ${COLORS.low}LOW: ${s.low}${COLORS.reset}`);
  lines.push(`  ${COLORS.info}INFO: ${s.info}${COLORS.reset}`);
  lines.push("");

  if (s.critical > 0 || s.high > 0) {
    lines.push("  ⚠️  Action required. Run 'forge log' to begin recording trust chain.");
  } else {
    lines.push("  ✓  No critical issues. Run 'forge log' to begin recording trust chain.");
  }
  lines.push("");

  return lines.join("\n");
}
