<?php
// PHP2Shell Sentinel — Lab reference page (PATCHED)
// This page exposes PHP version information intentionally for lab use only.
// Never expose this to public interfaces.

header('X-Powered-By: PHP/' . PHP_VERSION);
header('Content-Type: text/plain');
echo 'PHP2Shell Sentinel Lab — PATCHED instance' . PHP_EOL;
echo 'PHP version: ' . PHP_VERSION . PHP_EOL;
echo 'Status: PATCHED (CVE-2026-109618, CVE-2026-109619)' . PHP_EOL;
