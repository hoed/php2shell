<?php
// PHP2Shell Sentinel — Lab reference page (VULNERABLE version, detection testing only)
// This container exists purely for version-detection comparison.
// No exploit payloads are executed here.
// NEVER expose this to public interfaces.

header('X-Powered-By: PHP/' . PHP_VERSION);
header('Content-Type: text/plain');
echo 'PHP2Shell Sentinel Lab — VULNERABLE instance (detection testing only)' . PHP_EOL;
echo 'PHP version: ' . PHP_VERSION . PHP_EOL;
echo 'Status: VULNERABLE (CVE-2026-109618, CVE-2026-109619) — lab comparison only' . PHP_EOL;
