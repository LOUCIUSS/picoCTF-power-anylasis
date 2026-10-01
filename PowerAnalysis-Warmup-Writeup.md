# PowerAnalysis: Warmup — Side-Channel Key Recovery Writeup

**Source:** picoCTF 2023 | **Category:** Cryptography / Side-Channels | **Difficulty:** Hard

---

## Executive Summary

The target service implements a single-round AES-style S-box substitution cipher over a 16-byte key. Although the ciphertext itself is never returned to the client, the service inadvertently leaks the least-significant bit (LSB) of every S-box output through an aggregate counter. This writeup documents the full attack chain: identifying the leakage channel, modeling it mathematically, and building an automated remote exploit that recovers the complete 16-byte key via differential bit analysis — without ever observing a single ciphertext byte directly.

**Impact:** Full 128-bit key recovery with zero algebraic weaknesses in the cipher itself — the vulnerability is purely in the side-channel exposed by the implementation.

---

## Vulnerability Analysis

### Target Behavior

```python
def leaky_aes_secret(data_byte, key_byte):
    out = Sbox[data_byte ^ key_byte]
    leak_buf.append(out & 0x01)   # <-- leak point
    return out

def encrypt_and_leak(plaintext):
    ciphertext = encrypt(plaintext, SECRET_KEY)
    ciphertext = None             # ciphertext discarded
    return leak_buf.count(1)      # only this is returned
```

### Root Cause

The service computes `Sbox[plaintext[i] ^ key[i]]` for each of the 16 key bytes, discards the resulting ciphertext, and returns only the **count of S-box outputs whose LSB equals 1** across all 16 positions. This is a classic **aggregated side-channel leak**: rather than exposing output data directly, the implementation leaks *statistical metadata* about an internal computation.

### Exploitability

Because each byte position's contribution to the leak is independent and isolable, an attacker who controls the plaintext can hold 15 bytes constant and vary the 16th, producing a **differential signal** attributable to exactly one key byte:

```
delta = leak(modified_plaintext) - leak(baseline_plaintext)
      = (Sbox[p_new ^ k_i] & 1) - (Sbox[p_old ^ k_i] & 1)  ∈ {-1, 0, +1}
```

This converts a 2¹²⁸ brute-force problem into sixteen independent 2⁸ problems.

---

## Exploit Development

### Methodology

For each key byte position:

1. Query a baseline plaintext (all zero bytes) to establish `baseline_leak`.
2. Query a series of modified plaintexts, each differing from baseline at only the target position, recording the observed delta for each.
3. For every candidate key byte (0–255), predict the delta that candidate would produce and compare against all observed deltas.
4. Retain only candidates consistent with *every* observed delta.

### Handling False Positives

A fixed, small number of trial values is statistically insufficient — since each leaked bit behaves like a coin flip, roughly half of all 256 candidates can accidentally match any single observed delta by chance. The exploit therefore uses an **adaptive candidate-filtering approach**: it continues testing new randomized trial values and narrowing the candidate pool until exactly one candidate survives for that byte position, eliminating collision risk entirely rather than trusting a "first match" heuristic.

### Remote Exploitation Constraint

The service accepts exactly one query per TCP connection before terminating it. The exploit therefore opens a **new connection per query**:

```python
def query_server(plaintext_bytes):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    conn.recv(4096)
    conn.sendall((plaintext_bytes.hex() + "\n").encode())
    response = conn.recv(4096).decode()
    conn.close()
    return int(response.strip().split(":")[-1].strip())

def recover_key_byte(position, baseline_pt, baseline_leak):
    candidates = list(range(256))
    x_pool = list(range(1, 256))
    random.shuffle(x_pool)
    for X in x_pool:
        if len(candidates) <= 1:
            break
        modified_pt = bytearray(baseline_pt)
        modified_pt[position] = X
        delta = query_server(modified_pt) - baseline_leak
        candidates = [
            g for g in candidates
            if (Sbox[X ^ g] & 1) - (Sbox[baseline_pt[position] ^ g] & 1) == delta
        ]
    return candidates
```

### Result

```
Recovered key: 81808c36fca728008a57f90907ccbae6
```

---

## Mitigation

| Weakness | Recommended Fix |
|---|---|
| Aggregate bit-count leak over internal computation | Never expose any function of intermediate cryptographic state, even indirectly (counts, timing, error codes) — only the intended final output should ever leave the trust boundary |
| No rate limiting on queries with attacker-chosen plaintext | Enforce strict rate limiting and anomaly detection on chosen-plaintext query patterns, which are a hallmark of differential side-channel attacks |
| Deterministic, unmasked S-box computation | Apply **Boolean masking**: XOR intermediate values with a fresh random mask before any observable side effect is computed, so leaked bits become uncorrelated with the real key without the mask |
| Single-bit leak granularity exploitable at scale | Defense-in-depth: even a 1-bit-per-query leak is a critical vulnerability if query volume isn't bounded — leak budget enforcement (e.g. constant total information exposure per key lifetime) should be considered for any system exposing cryptographic internals |
