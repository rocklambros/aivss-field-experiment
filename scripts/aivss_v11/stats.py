"""Agreement statistics for the v1.1 analysis.

Version: 1.1.0
Owner: Rock Lambros

Closes premortem P16, P41, P44, P46, P49, P50, P73 (fix plan R2.9):
- Fleiss kappa is declined only when the pooled marginal is a single category.
  Each assessor's marginal and its degeneracy are reported beside it.
- Cohen kappa is declined when either assessor's marginal is a single category.
- Linear weighted kappa for ordinal metrics, bands, and agent class.
- Krippendorff alpha (nominal or ordinal), missing values allowed.
- Cluster bootstrap: sorted cluster keys, seed 42, 2000 resamples, percentile
  interval on the defined resamples with the count shown.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from itertools import combinations

SEED = 42
RESAMPLES = 2000
ORDERS = {
    "LC": ["N", "M", "I", "D"], "CP": ["N", "S", "C"], "AP": ["N", "C", "L"], "RH": ["N", "P", "D"],
    "ES": ["N", "M", "W"], "AV": ["P", "L", "A", "N"], "AC": ["H", "L"], "AT": ["P", "N"], "PR": ["H", "L", "N"],
    "UI": ["A", "P", "N"], "VC": ["N", "L", "H"], "VI": ["N", "L", "H"], "VA": ["N", "L", "H"], "SC": ["N", "L", "H"],
    "SI": ["N", "L", "H"], "SA": ["N", "L", "H"], "cvss_band": ["None", "Low", "Medium", "High", "Critical"],
    "aivss_band": ["None", "Low", "Medium", "High", "Critical"], "effect_class": ["A0", "A1", "A2"],
}


def fleiss(table: list[list[str]]) -> dict:
    """table: one list of assessor labels per finding, all the same length, unknowns already removed."""
    n = len(table)
    if n == 0:
        return {"n": 0, "kappa": None, "p0": None, "declined": "no findings"}
    raters = len(table[0])
    cats = sorted({x for row in table for x in row})
    per_rater = [Counter(row[i] for row in table) for i in range(raters)]
    marg = {"per_assessor": [dict(c) for c in per_rater], "degenerate_assessors": [i for i, c in enumerate(per_rater) if len(c) == 1]}
    p0 = sum(sum(c * (c - 1) for c in Counter(row).values()) / (raters * (raters - 1)) for row in table) / n
    prevalence = {k: sum(row.count(k) for row in table) / (n * raters) for k in cats}
    if len(cats) < 2:
        return {"n": n, "kappa": None, "p0": p0, "prevalence": prevalence, "declined": "pooled marginal is one category", **marg}
    pe = sum(p * p for p in prevalence.values())
    kappa = (p0 - pe) / (1 - pe) if pe < 1 else None
    return {"n": n, "kappa": kappa, "p0": p0, "pe": pe, "prevalence": prevalence, **marg}


def cohen(pairs: list[tuple[str, str]]) -> dict:
    n = len(pairs)
    if n == 0:
        return {"n": 0, "kappa": None, "p0": None, "declined": "no pairs"}
    p0 = sum(a == b for a, b in pairs) / n
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    if len(left) < 2 or len(right) < 2:
        return {"n": n, "kappa": None, "p0": p0, "declined": "an assessor's marginal is one category",
                "marginals": [dict(left), dict(right)]}
    cats = set(left) | set(right)
    pe = sum((left[c] / n) * (right[c] / n) for c in cats)
    return {"n": n, "kappa": (p0 - pe) / (1 - pe), "p0": p0, "pe": pe, "marginals": [dict(left), dict(right)]}


def weighted_kappa(pairs: list[tuple[str, str]], order: list[str]) -> dict:
    use = [(a, b) for a, b in pairs if a in order and b in order]
    n = len(use)
    if n == 0:
        return {"n": 0, "kappa": None, "declined": "no ordinal pairs"}
    k = len(order)
    idx = {v: i for i, v in enumerate(order)}
    left, right = Counter(a for a, _ in use), Counter(b for _, b in use)
    if len(left) < 2 or len(right) < 2:
        return {"n": n, "kappa": None, "declined": "an assessor's marginal is one category"}
    w = lambda i, j: abs(i - j) / (k - 1)  # noqa: E731
    obs = sum(w(idx[a], idx[b]) for a, b in use) / n
    exp = sum(left[a] * right[b] * w(idx[a], idx[b]) for a in left for b in right) / (n * n)
    return {"n": n, "kappa": None if exp == 0 else 1 - obs / exp}


def krippendorff(units: list[list[str | None]], level: str = "nominal", order: list[str] | None = None) -> dict:
    """Krippendorff alpha. Each unit is a list of assessor values with None for missing."""
    vals = [[v for v in u if v is not None] for u in units]
    vals = [u for u in vals if len(u) >= 2]
    cats = sorted({v for u in vals for v in u}, key=(lambda v: order.index(v)) if level == "ordinal" and order else None)
    if len(cats) < 2:
        return {"alpha": None, "units": len(vals), "declined": "fewer than two values observed"}
    o = {(c, k): 0.0 for c in cats for k in cats}
    for u in vals:
        m = len(u)
        for i, j in ((i, j) for i in range(m) for j in range(m) if i != j):
            o[(u[i], u[j])] += 1 / (m - 1)
    nc = {c: sum(o[(c, k)] for k in cats) for c in cats}
    n = sum(nc.values())

    def d2(c, k):
        if c == k:
            return 0.0
        if level == "nominal":
            return 1.0
        a, b = sorted((cats.index(c), cats.index(k)))
        s = sum(nc[cats[g]] for g in range(a, b + 1)) - (nc[c] + nc[k]) / 2
        return s * s

    do = sum(o[(c, k)] * d2(c, k) for c in cats for k in cats)
    de = sum(nc[c] * nc[k] * d2(c, k) for c in cats for k in cats) / (n - 1)
    return {"alpha": None if de == 0 else 1 - do / de, "units": len(vals), "level": level}


def cluster_bootstrap(ids: list[str], cluster_of: dict[str, str], stat_fn, resamples: int = RESAMPLES, seed: int = SEED) -> dict:
    groups: dict[str, list[str]] = {}
    for fid in sorted(ids):
        groups.setdefault(cluster_of[fid], []).append(fid)
    keys = sorted(groups)
    rng = random.Random(seed)
    stats = []
    for _ in range(resamples):
        drawn = [fid for _k in keys for fid in groups[keys[rng.randrange(len(keys))]]]
        value = stat_fn(drawn)
        if value is not None and not (isinstance(value, float) and math.isnan(value)):
            stats.append(value)
    if not stats:
        return {"low": None, "high": None, "defined": 0, "resamples": resamples, "clusters": len(keys)}
    stats.sort()
    lo = stats[int(0.025 * (len(stats) - 1))]
    hi = stats[int(0.975 * (len(stats) - 1))]
    return {"low": lo, "high": hi, "defined": len(stats), "resamples": resamples, "clusters": len(keys), "seed": seed}


def kendall_tau_b(x: list[float], y: list[float]) -> float | None:
    n = len(x)
    conc = disc = tx = ty = 0
    for i, j in combinations(range(n), 2):
        dx, dy = x[i] - x[j], y[i] - y[j]
        if dx == 0 and dy == 0:
            continue
        if dx == 0:
            tx += 1
        elif dy == 0:
            ty += 1
        elif dx * dy > 0:
            conc += 1
        else:
            disc += 1
    denom = math.sqrt((conc + disc + tx) * (conc + disc + ty))
    return None if denom == 0 else (conc - disc) / denom


def exact_binomial_ci(k: int, n: int, alpha: float = 0.05) -> tuple[float, float] | tuple[None, None]:
    """Clopper-Pearson interval by bisection, no SciPy dependency."""
    if n == 0:
        return (None, None)

    def cdf(p, upto):
        return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(upto + 1))

    def solve(target, f, lo=0.0, hi=1.0):
        for _ in range(200):
            mid = (lo + hi) / 2
            if f(mid) > target:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(1 - alpha / 2, lambda p: cdf(p, k - 1))
    upper = 1.0 if k == n else solve(alpha / 2, lambda p: cdf(p, k))
    return (lower, upper)


def agreement_block(by_finding: dict[str, dict[str, str | None]], metric: str, cluster_of: dict[str, str],
                    slots=("A", "B", "C", "D", "E", "F", "G"), unknown=("X", "AX")) -> dict:
    """Headline and detail agreement for one metric. by_finding maps finding to {slot: value or None}."""
    complete = {f: v for f, v in by_finding.items() if all(v.get(s) is not None for s in slots)}
    x_rows = {f: v for f, v in complete.items() if any(v[s] in unknown for s in slots)}
    table_ids = sorted(f for f in complete if f not in x_rows)
    table = [[complete[f][s] for s in slots] for f in table_ids]
    head = fleiss(table)
    lookup = dict(zip(table_ids, table))

    def kfn(drawn):
        sub = [lookup[f] for f in drawn if f in lookup]
        return fleiss(sub)["kappa"] if len(sub) >= 2 else None

    head["ci"] = cluster_bootstrap(table_ids, cluster_of, kfn)
    head["excluded_unknown"] = len(x_rows)
    head["excluded_incomplete"] = len(by_finding) - len(complete)
    order = ORDERS.get(metric)
    units = [[complete[f][s] if complete[f][s] not in unknown else None for s in slots] for f in sorted(complete)]
    head["alpha"] = krippendorff(units, "ordinal" if order else "nominal", order)
    units_x = [[complete[f][s] for s in slots] for f in sorted(complete)]
    head["alpha_unknown_as_category"] = krippendorff(units_x, "nominal")
    pairs = {}
    for a, b in combinations(slots, 2):
        pr = [(complete[f][a], complete[f][b]) for f in sorted(complete) if complete[f][a] not in unknown and complete[f][b] not in unknown]
        blk = cohen(pr)
        if order:
            blk["linear_weighted"] = weighted_kappa(pr, order)
        pairs[f"{a}-{b}"] = blk
    head["pairwise"] = pairs
    return head
