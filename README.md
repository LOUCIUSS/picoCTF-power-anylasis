# CTF & Security Writeups

Writeups for picoCTF challenges in cryptography (side-channels) and forensics, written as short technical reports. Every writeup uses the same four sections: **Executive Summary**, **Vulnerability Analysis**, **Exploit Development** and **Mitigation**. Flags are left out on purpose.

---

## Featured: PowerAnalysis side-channel series

Three cryptography challenges (all rated Hard) that build on each other. In each one, the secret key of a simple cipher is recovered from information that leaks while the cipher runs.

| Writeup | What it covers |
|---|---|
| [PowerAnalysis: Warmup](PowerAnalysis-Warmup-Writeup.md) | The server leaks one bit per byte, returned only as a total count. Changing one input byte at a time isolates each key byte (differential analysis), automated in Python over raw sockets. |
| [PowerAnalysis: Part 1](PowerAnalysis-Part1-Writeup.md) | Correlation power analysis on noisy power traces: Hamming weight model and Pearson correlation, recovering the key byte by byte with NumPy. |
| [PowerAnalysis: Part 2](PowerAnalysis-Part2-Writeup.md) | The same attack with only 100 fixed traces. Scoring by a single correlation peak left two key bytes ambiguous; summing squared correlation over a time window resolved them. |

---

## Forensics writeups

| Writeup | Technique | Tools |
|---|---|---|
| [Ph4nt0m 1ntrud3r](Ph4nt0m-1ntrud3r-Writeup.md) | Data hidden in TCP SYN payloads: Base64 chunks mixed with decoys, put in order by timestamp | tshark, Python |
| [Scan Surprise](Scan-Surprise-Writeup.md) | Decoding a QR code from the command line | zbarimg |
| [RED](RED-Writeup.md) | LSB steganography in a PNG, with a Base64 payload | exiftool, zsteg, Python (Pillow) |
| [DISKO 1](DISKO-1-Writeup.md) | Finding flag-shaped strings in a raw disk image | zcat, strings, grep |
| [Corrupted file](Corrupted-File-Writeup.md) | Repairing a damaged JPEG header (magic bytes) | file, xxd, dd |

---

## Other practice (no writeups)

- OverTheWire Bandit: all levels completed
- picoCTF General Skills: 8 challenges completed (command line, grep, find, strings, netcat, pipes)

---

## About these writeups

- Flags are omitted from every writeup.
- The scripts and commands in the RED, DISKO 1 and Corrupted file writeups were also checked on generated test data.
- All work was done on CTF platforms or on targets that are meant to be tested.
