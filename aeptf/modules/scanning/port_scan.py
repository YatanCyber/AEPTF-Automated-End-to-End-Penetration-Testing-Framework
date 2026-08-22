"""Bounded top-100 TCP / light service-version scan plugin.

Runs a single `nmap` invocation using nmap's built-in --top-ports N flag
against exactly one authorized target. N is capped by
safety.max_scan_ports (default 100) and cannot be raised by request
input -- only by an operator editing configuration. Light service
detection (-sV, restrained intensity) is used instead of a full,
unbounded version-scan sweep. No scripts, no OS fingerprinting, no
range/subnet targets.
"""
from __future__ import annotations

import subprocess

from aeptf.core.config import Settings
from aeptf.core.plugins import AssessmentPlugin, Finding, PluginMeta, PluginResult
from aeptf.core.logging import get_logger

logger = get_logger("scanning.port_scan")

# Services that, if found open, are worth flagging as a finding for human
# review -- not because they're inherently vulnerable, but because
# they're common initial-access or lateral-movement surface.
_NOTABLE_SERVICES = {
    "21": "FTP",
    "23": "Telnet",
    "3389": "RDP",
    "445": "SMB",
    "135": "MSRPC",
    "1433": "MSSQL",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "27017": "MongoDB",
}


class TopPortsScanPlugin(AssessmentPlugin):
    name = "scanning"
    description = "Top-N TCP port scan with light service detection against one authorized target."
    meta = PluginMeta(version="1.0.0", requires_binaries=["nmap"], network_scope="single-target")

    def run(self, target: str, settings: Settings) -> PluginResult:
        started_at = self._start()
        self.authorize(target, settings)

        readiness = self.check_ready()
        if not readiness.ready:
            return self.finish(
                target=target,
                started_at=started_at,
                finished_at=self._finish(),
                status="error",
                summary="Plugin preconditions not met.",
                error="; ".join(readiness.reasons),
            )

        top_ports = max(1, min(settings.safety.max_scan_ports, 100))
        command = [
            "nmap",
            "-Pn",          # skip a second host-discovery pass; discovery is a separate plugin
            "-n",
            "--top-ports", str(top_ports),
            "-sV",
            "--version-intensity", "2",  # light probing only
            "-T3",
            target,
        ]
        timeout = settings.safety.nmap_timeout_seconds
        logger.info("Running top-%s port scan against %s (timeout=%ss)", top_ports, target, timeout)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self.finish(
                target=target,
                started_at=started_at,
                finished_at=self._finish(),
                status="error",
                summary=f"Port scan timed out after {timeout}s.",
                error="timeout",
            )

        open_ports = self._parse_open_ports(completed.stdout)
        findings = self._findings_for(target, open_ports)
        summary = (
            f"Scanned top {top_ports} ports on {target}: {len(open_ports)} open."
            if completed.returncode == 0
            else f"Port scan against {target} exited with an error."
        )

        return self.finish(
            target=target,
            started_at=started_at,
            finished_at=self._finish(),
            status="success" if completed.returncode == 0 else "error",
            summary=summary,
            data={
                "top_ports": top_ports,
                "open_ports": open_ports,
                "command": " ".join(command),
                "raw_stdout": completed.stdout.strip(),
                "return_code": completed.returncode,
            },
            error=None if completed.returncode == 0 else completed.stderr.strip(),
            findings=findings,
        )

    @staticmethod
    def _parse_open_ports(nmap_stdout: str) -> list[dict[str, str]]:
        open_ports: list[dict[str, str]] = []
        for line in nmap_stdout.splitlines():
            line = line.strip()
            if "/tcp" not in line or "open" not in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            port_proto, state = parts[0], parts[1]
            if not state.startswith("open"):
                continue
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            port = port_proto.split("/")[0]
            open_ports.append({"port": port, "service": service, "version": version})
        return open_ports

    @staticmethod
    def _findings_for(target: str, open_ports: list[dict[str, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for entry in open_ports:
            notable = _NOTABLE_SERVICES.get(entry["port"])
            if notable:
                findings.append(
                    Finding(
                        title=f"{notable} exposed on port {entry['port']}",
                        severity="low",
                        description=(
                            f"{target} has {notable} (port {entry['port']}) reachable. "
                            "Worth confirming this is intentionally exposed and, if so, "
                            "that authentication and patch level are reviewed."
                        ),
                        evidence={"port": entry["port"], "service": entry["service"], "version": entry["version"]},
                    )
                )
        return findings
