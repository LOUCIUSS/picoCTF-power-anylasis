# PowerAnalysis: Part 1 — Correlation Power Analysis (CPA) Writeup

**Source:** picoCTF 2023 | **Category:** Cryptography / Side-Channels | **Difficulty:** Hard

---

## Executive Summary

The target embedded system exposes raw CPU power-consumption traces for every encryption it performs. This writeup documents a full **Correlation Power Analysis (CPA)** attack — the same technique used against real-world smart cards and embedded cryptographic hardware — to recover a 16-byte AES-style key purely from statistical analysis of noisy power traces, with no access to ciphertext, timing, or any other output.

**Impact:** Full key recovery via a non-invasive physical side channel, demonstrating that correct algorithmic design (a sound S-box, no algebraic weakness) provides no protection if the implementation leaks power information proportional to processed data.

---

## Vulnerability Analysis

### Target Behavior

For each query, the service accepts a 16-byte plaintext and returns a full power trace (hundreds of samples) captured during encryption, rather than any function of the ciphertext.

### Root Cause: Hamming Weight Leakage

CMOS hardware draws measurably more power switching a bit from 0→1 or 1→0 than holding it steady. As a result, the power consumed while processing a byte correlates with that byte's **Hamming Weight (HW)** — the number of `1` bits it contains:

```
power[t] ≈ HammingWeight(Sbox[plaintext[i] ^ key[i]]) + noise
```

This is a textbook example of **unintentional analog leakage from digital computation** — the device's physical behavior reveals information about data it was never designed to expose.

### Exploitability

An attacker who can query the device with arbitrary plaintexts and record the resulting traces can test key-byte hypotheses against *real physical measurements*: the correct key hypothesis will produce a Hamming Weight prediction that correlates strongly with actual recorded power at the moment that byte is processed; incorrect hypotheses will not.

---

## Exploit Development

### Methodology

Because the server accepts one query per connection, traces are collected by opening repeated connections, each submitting a random 16-byte plaintext and recording the returned trace. For each of the 16 key byte positions, independently:

1. For every candidate guess `g ∈ [0, 255]`, compute a hypothesis vector: the predicted Hamming Weight of `Sbox[plaintext[i] ^ g]` across all collected traces.
2. Compute the **Pearson correlation coefficient** between this hypothesis and the actual power value, independently at every time sample in the trace.
3. Score each guess by its **maximum absolute correlation** across all time samples.
4. Select the highest-scoring guess as the recovered key byte.

```python
def cpa_attack(traces_np, plaintexts, position):
    best_guess, best_corr = None, -1
    for guess in range(256):
        hyp = np.array([HW[Sbox[plaintexts[n][position] ^ guess]] for n in range(len(plaintexts))])
        hyp_c = hyp - hyp.mean()
        trace_c = traces_np - traces_np.mean(axis=0)
        corr = (hyp_c @ trace_c) / (
            np.sqrt((hyp_c**2).sum()) * np.sqrt((trace_c**2).sum(axis=0))
        )
        max_corr = np.max(np.abs(corr))
        if max_corr > best_corr:
            best_corr, best_guess = max_corr, guess
    return best_guess, best_corr
```

### Validating Confidence

With 200 collected traces, every one of the 16 key byte positions produced correlation scores in a consistent, tightly-clustered range (≈0.50–0.62) with no outliers. This cross-position consistency — rather than any single high score — was the strongest evidence of correctness: a spurious result driven by noise would be expected to stand out from the group, not blend into the same range as every genuinely-recovered byte.

### Result

```
Recovered key: af55be9bb08d78491b0aa416f7043ed4
```

---

## Mitigation

| Weakness | Recommended Fix |
|---|---|
| Power consumption data-dependent on secret key material | Apply **power-balancing circuit design** (dual-rail logic, constant Hamming-weight encodings) so switching activity — and therefore power draw — is independent of processed data |
| No masking of intermediate cryptographic values | Apply **Boolean or arithmetic masking**: split each sensitive intermediate value into random shares so no single observable quantity correlates with the real key |
| Unlimited chosen-plaintext trace collection | Rate-limit and monitor for high-volume, low-entropy-variation query patterns characteristic of trace collection for CPA |
| No noise injection | Introduce **random power noise generation** (e.g. dummy operations, randomized clock jitter) to reduce the signal-to-noise ratio available to an attacker, increasing the number of traces required beyond practical limits |
| Physical access / proximity leakage model assumed too permissive | For genuinely sensitive deployments, treat power-analysis resistance as a certification requirement (e.g. FIPS 140-3 physical security levels) rather than an afterthought |
