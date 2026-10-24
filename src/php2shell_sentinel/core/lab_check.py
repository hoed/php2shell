"""Lab environment health and isolation checker.

Verifies that the Docker lab is correctly configured and isolated before use.
Does NOT run exploit code; only checks container status and network binding.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LabStatus:
    docker_available: bool = False
    compose_available: bool = False
    containers: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.docker_available and not self.errors


def check_lab(compose_file: Optional[str] = None) -> LabStatus:
    """Inspect the Docker lab environment."""
    status = LabStatus()

    # ── Docker availability ───────────────────────────────────────────────────
    status.docker_available = shutil.which("docker") is not None
    if not status.docker_available:
        status.errors.append(
            "Docker not found. Install Docker Engine: "
            "https://docs.docker.com/engine/install/"
        )
        return status

    status.compose_available = _check_compose()

    # ── Running containers ────────────────────────────────────────────────────
    containers = _list_lab_containers()
    status.containers = containers

    for c in containers:
        _check_container_isolation(c, status)

    # ── Compose file present ──────────────────────────────────────────────────
    if compose_file:
        import os
        if not os.path.isfile(compose_file):
            status.warnings.append(
                f"docker-compose.yml not found at {compose_file}. "
                "Run from the project root or specify --compose-file."
            )

    # ── Recommendations ───────────────────────────────────────────────────────
    if not status.containers:
        status.recommendations.append(
            "No lab containers running. "
            "Start with: docker compose -f lab/docker-compose.yml up -d"
        )
    else:
        status.recommendations.append(
            "Lab containers running. "
            "Use 'php2shell-sentinel lab-check' to re-verify before testing."
        )

    return status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_compose() -> bool:
    # Try both 'docker compose' (v2) and 'docker-compose' (v1)
    for cmd in [["docker", "compose", "version"], ["docker-compose", "--version"]]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _list_lab_containers() -> list[dict]:
    """Return Docker containers whose names contain 'php2shell'."""
    try:
        result = subprocess.run(
            [
                "docker", "ps",
                "--filter", "name=php2shell",
                "--format",
                "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                containers.append({
                    "name": parts[0],
                    "image": parts[1],
                    "status": parts[2],
                    "ports": parts[3],
                })
        return containers
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not list containers: %s", exc)
        return []


def _check_container_isolation(c: dict, status: LabStatus) -> None:
    """Warn if a lab container appears to be publicly bound."""
    ports = c.get("ports", "")
    name = c.get("name", "unknown")

    public_indicators = ["0.0.0.0:", ":::", "[::]:"]
    for indicator in public_indicators:
        if indicator in ports:
            status.warnings.append(
                f"Container {name!r} has a publicly-bound port ({ports!r}). "
                "Lab containers should only bind to 127.0.0.1 or an internal network. "
                "Check lab/docker-compose.yml port mappings."
            )
            status.recommendations.append(
                f"Change the port binding for {name} to '127.0.0.1:<port>:<port>' "
                "in lab/docker-compose.yml."
            )
