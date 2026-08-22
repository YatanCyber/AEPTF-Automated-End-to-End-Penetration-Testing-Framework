"""Bounded host-discovery plugin.

Runs a single `nmap -sn` (ping scan, no port scan) against exactly one
authorized target. Does not sweep ranges, does not scan ports, does not
accept arbitrary nmap flags from the caller.
"""
from __future__ import annotations

import subprocess

from aeptf.core.config import Settings
from aeptf.core.plugins import AssessmentPlugin, PluginMeta, PluginResult
from aeptf.core.logging import get_logger

logger = get_logger("reconnaissance.discovery")


class HostDiscoveryPlugin(AssessmentPlugin):
    name = "reconnaissance"
    description = "Single-host up/down check via `nmap -sn` against one authorized target."
    meta = PluginMeta(version="1.0.0", requires_binaries=["nmap"], network_scope="single-target")

    def run(self, target: str, settings: Settings) -> PluginResult:
        started_at = self._start()
        self.authorize(target, settings)  # raises AuthorizationError if not approved

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

        # Fixed, minimal flag set. No user-supplied flags are ever accepted.
        command = ["nmap", "-sn", "-n", target]
        timeout = settings.safety.nmap_timeout_seconds
        logger.info("Running host discovery against %s (timeout=%ss)", target, timeout)

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
                summary=f"nmap host discovery timed out after {timeout}s.",
                error="timeout",
            )

        host_up = "Host is up" in completed.stdout
        summary = f"Host {target} is {'up' if host_up else 'down or filtered'}."

        return self.finish(
            target=target,
            started_at=started_at,
            finished_at=self._finish(),
            status="success" if completed.returncode == 0 else "error",
            summary=summary,
            data={
                "host_up": host_up,
                "command": " ".join(command),
                "raw_stdout": completed.stdout.strip(),
                "return_code": completed.returncode,
            },
            error=None if completed.returncode == 0 else completed.stderr.strip(),
        )
