# PowerAnalysis: Part 2 — CPA Under Trace-Constrained Conditions Writeup

**Source:** picoCTF 2023 | **Category:** Cryptography / Side-Channels | **Difficulty:** Hard

---

## Executive Summary

This writeup extends the Correlation Power Analysis (CPA) technique from Part 1 to a realistic constraint: only 100 pre-recorded power traces are available, with no ability to request additional measurements. This mirrors real-world engagements where physical access to a target device is time-limited. A naive application of the Part 1 methodology left two of sixteen key bytes statistically ambiguous; this writeup documents the signal-processing refinement — aggregating correlation evidence across multiple trace samples rather than relying on a single peak — required to fully recover the key under this tighter data budget.

**Impact:** Demonstrates that CPA remains a viable full key-recovery technique even under significantly reduced data availability, provided the statistical distinguisher is adapted to extract more information per trace.

---

## Vulnerability Analysis

### Target Behavior

A fixed archive of 100 trace files is provided, each containing a plaintext and its corresponding power trace (2,666 samples), recorded under the same Hamming Weight leakage model established in Part 1. No live oracle is available — this is the entire exploitable dataset.

### Root Cause

Identical to Part 1: power draw correlates with the Hamming Weight of the S-box output `Sbox[plaintext[i] ^ key[i]]`. The constraint introduced here is not a new vulnerability class, but a reduced **signal-to-noise budget**: with fewer traces, the sampling error of a single-point Pearson correlation estimate becomes large enough that closely-matched candidate keys can't always be distinguished by one sample alone.

### Exploitability Under Constraint

Applying the Part 1 method unchanged (maximum single-point correlation per guess) correctly resolved 14 of 16 key bytes with a clear confidence margin, but left two ambiguous:

```
pos  6: best corr=0.591  2nd=0.512  gap=0.079   (weak)
pos 11: best corr=0.480  2nd=0.474  gap=0.006   (statistically indistinguishable)
```

This is the exploitable gap: a reduced trace count does not eliminate the leak, it only reduces the margin by which a naive distinguisher separates correct from incorrect guesses.

---

## Exploit Development

### Diagnosing the Ambiguity

Before modifying the distinguisher, the location of peak correlation was checked across all 16 positions, including the two ambiguous ones. All 16 peaks clustered within the same narrow time window (samples ≈330–390), confirming the attack was searching the correct region of the trace — the issue was single-sample statistical power, not search location.

### Refined Distinguisher: Windowed Sum-of-Squares

Rather than scoring each guess by its single strongest correlated sample, the score was changed to the **sum of squared correlation values across the full known-signal window** (samples 300–420):

```python
def recover_key_byte(position):
    best_guess, best_score = None, -1
    for guess in range(256):
        hyp = np.array([HW[Sbox[plaintexts[n][position] ^ guess]] for n in range(len(plaintexts))])
        hyp_c = hyp - hyp.mean()
        window = traces_np[:, WIN_LO:WIN_HI]
        win_c = window - window.mean(axis=0)
        corr = (hyp_c @ win_c) / (
            np.sqrt((hyp_c**2).sum()) * np.sqrt((win_c**2).sum(axis=0))
        )
        score = np.sum(corr ** 2)
        if score > best_score:
            best_score, best_guess = score, guess
    return best_guess
```

Squaring is required because correlation can be negative; without it, genuinely strong positive and negative correlations at different time points within the window could cancel out in a plain sum rather than reinforcing the signal.

### Result of the Refinement

```
pos  6: single-point gap=0.079   →   windowed sum-of-squares relative gap=0.389
pos 11: single-point gap=0.006   →   windowed sum-of-squares relative gap=0.288
```

Both the original and refined methods agreed on the final guess for every position, providing a built-in cross-check that the result was not a statistical artifact.

### Result

```
Recovered key: a132dc5c44cc08cc381a78a8982ddc55
```

---

## Mitigation

| Weakness | Recommended Fix |
|---|---|
| Power leakage remains exploitable even with limited physical access time | Treat *any* measurable trace count as a non-zero risk — security claims should not assume an attacker is limited to "too few" traces, since distinguisher improvements (as shown here) can recover signal from data previously assumed insufficient |
| Fixed, narrow time window of leakage (sequential byte processing) | Architecturally randomize or shuffle the processing order of key bytes per operation, forcing an attacker to also solve an alignment problem before any correlation attack is possible |
| No noise injection to widen the margin between correct/incorrect guesses | Increase the practical trace requirement for CPA via randomized power noise or operation reordering, so that realistic data-collection constraints (as modeled in this challenge) become genuinely prohibitive rather than merely inconvenient |
| Masking absent | As in Part 1, **first-order Boolean masking** of the S-box computation remains the primary structural fix — it would require second-order CPA (correlating combinations of multiple leak points against unmasked hypotheses) rather than the single-order attack used here |
