"""Bounded HTTP metadata plugin.

Issues exactly one HTTP HEAD request to the authorized target (https first,
falling back to http) and records response headers. Does not crawl links,
does not brute-force paths, does not send any other request.
"""
from __future__ import annotations

import httpx

from aeptf.core.config import Settings
from aeptf.core.plugins import AssessmentPlugin, Finding, PluginMeta, PluginResult
from aeptf.core.logging import get_logger

logger = get_logger("enumeration.http_metadata")

_EXPECTED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
]


class HttpMetadataPlugin(AssessmentPlugin):
    name = "enumeration"
    description = "Single HTTP HEAD request to an authorized target; records status and headers."
    meta = PluginMeta(version="1.0.0", requires_binaries=[], network_scope="single-target")

    def run(self, target: str, settings: Settings) -> PluginResult:
        started_at = self._start()
        self.authorize(target, settings)

        timeout = settings.safety.network_timeout_seconds
        candidates = [f"https://{target}", f"http://{target}"] if "://" not in target else [target]

        last_error: str | None = None
        for url in candidates:
            try:
                with httpx.Client(timeout=timeout, follow_redirects=False, verify=True) as client:
                    response = client.head(url)
                headers = dict(response.headers)
                findings = self._header_findings(url, headers)
                return self.finish(
                    target=target,
                    started_at=started_at,
                    finished_at=self._finish(),
                    status="success",
                    summary=f"HEAD {url} -> {response.status_code}",
                    data={
                        "url": url,
                        "status_code": response.status_code,
                        "headers": headers,
                    },
                    findings=findings,
                )
            except httpx.HTTPError as exc:
                last_error = str(exc)
                logger.info("HEAD %s failed (%s); trying next scheme if available", url, exc)
                continue

        return self.finish(
            target=target,
            started_at=started_at,
            finished_at=self._finish(),
            status="error",
            summary=f"HTTP HEAD request(s) against {target} failed.",
            error=last_error,
        )

    @staticmethod
    def _header_findings(url: str, headers: dict[str, str]) -> list[Finding]:
        lower_headers = {k.lower() for k in headers}
        missing = [h for h in _EXPECTED_SECURITY_HEADERS if h not in lower_headers]
        if not missing:
            return []
        return [
            Finding(
                title="Missing common security headers",
                severity="info",
                description=(
                    f"{url} did not return: {', '.join(missing)}. "
                    "Not necessarily a vulnerability on its own, but worth noting "
                    "for a defense-in-depth review."
                ),
                evidence={"missing_headers": missing},
            )
        ]
