"""Report figures for v1.1, drawn in the report template's palette.

Version: 1.1.0
Owner: Rock Lambros

Forms follow the data's job (dataviz skill): a KPI tile row for the headline,
a band-flow diagram and per-finding dumbbells for inflation, a forest plot for
agreement, a unit chart with emphasis for disagreement attribution, a heatmap
for unknowns, a slope chart for exploit maturity policy, a bump chart for
ordering, and an outcome grid for FinBot. Palettes were checked with the
skill's validate_palette.js: band ramp (ordinal) BBA6F0 9670E8 6E32E0 2A0F66
passes; assessor palette (categorical) 6E32E0 00A0A8 D35400 passes every check.
Every function returns the saved path and the table behind the figure.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, PathPatch, Rectangle  # noqa: E402
from matplotlib.path import Path as MPath  # noqa: E402

SURFACE = "#FFFFFF"
TEXT, MUTED, GRID = "#050320", "#6C6A7A", "#E4E3E8"
BAND = {"None": "#E4E3E8", "Low": "#BBA6F0", "Medium": "#9670E8", "High": "#6E32E0", "Critical": "#2A0F66"}
BANDS = ["None", "Low", "Medium", "High", "Critical"]
# One hue per assessor (owner decision 2026-11-07: skip the colorblind check). This set passes the
# lightness, chroma, normal-vision, and contrast checks of validate_palette.js and fails only CVD
# separation, so every mark also carries its assessor letter.
SLOT = {"A": "#6E32E0", "B": "#00A0A8", "C": "#D35400", "D": "#2F6FD6", "E": "#B8327A", "F": "#3E8E41", "G": "#A0522D"}
ACCENT, CONTEXT = "#6E32E0", "#B9B7C4"
CVSS_INK = "#6C6A7A"
FONT = "DejaVu Sans"


def setup() -> None:
    plt.rcParams.update({
        "font.family": FONT, "font.size": 9.5, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
        "xtick.color": MUTED, "ytick.color": MUTED, "axes.titleweight": "bold", "axes.titlesize": 11.5,
        "axes.titlecolor": TEXT, "axes.titlelocation": "left", "figure.dpi": 170, "savefig.bbox": "tight",
        "savefig.pad_inches": 0.12, "axes.spines.top": False, "axes.spines.right": False,
    })


def _save(fig, out: Path) -> str:
    fig.savefig(out, facecolor=SURFACE)
    plt.close(fig)
    return str(out)


def _hair(ax, axis="x"):
    ax.grid(axis=axis, color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)


def kpi_tiles(tiles: list[tuple[str, str, str]], out: Path) -> tuple[str, list]:
    """tiles: (value, label, context). A row of stat tiles for the executive summary."""
    import textwrap
    fig, ax = plt.subplots(figsize=(7.4, 1.75))
    ax.set_axis_off()
    w = 1 / len(tiles)
    for i, (value, label, ctx) in enumerate(tiles):
        x = i * w + 0.008
        ax.add_patch(FancyBboxPatch((x, 0.04), w - 0.016, 0.92, boxstyle="round,pad=0,rounding_size=0.03",
                                    transform=ax.transAxes, facecolor="#F3EFFD", edgecolor="none"))
        ax.add_patch(Rectangle((x, 0.04), 0.006, 0.92, transform=ax.transAxes, color=ACCENT))
        ax.text(x + 0.03, 0.74, value, transform=ax.transAxes, fontsize=17 if len(value) > 5 else 20, color=TEXT, weight="bold", va="center")
        ax.text(x + 0.03, 0.42, textwrap.fill(label, 22), transform=ax.transAxes, fontsize=7.8, color=TEXT, va="center", linespacing=1.15)
        ax.text(x + 0.03, 0.13, textwrap.fill(ctx, 24), transform=ax.transAxes, fontsize=6.6, color=MUTED, va="center", linespacing=1.1)
    return _save(fig, out), tiles


def band_flow(rows: list[dict], out: Path) -> tuple[str, dict]:
    """Ribbons from each finding's CVSS-BT band (left) to its AIVSS band (right)."""
    flows = Counter((r["cvss_band"], r["aivss_band"]) for r in rows)
    left = Counter(r["cvss_band"] for r in rows)
    right = Counter(r["aivss_band"] for r in rows)
    n = len(rows)
    gap = 0.6
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    ax.set_xlim(-0.35, 1.35)
    total_h = n + gap * (len(BANDS) - 1)
    ax.set_ylim(-2.6, total_h + 0.5)
    ax.set_axis_off()

    def stack(counts):
        pos, y = {}, total_h
        for b in reversed(BANDS):  # Critical on top
            h = counts.get(b, 0)
            pos[b] = (y - h, y)
            y -= h + (gap if h else 0)
        return pos

    lp, rp = stack(left), stack(right)
    lcur = {b: lp[b][1] for b in BANDS}
    rcur = {b: rp[b][1] for b in BANDS}
    for src in reversed(BANDS):
        for dst in reversed(BANDS):
            k = flows.get((src, dst), 0)
            if not k:
                continue
            y0a, y0b = lcur[src] - k, lcur[src]
            y1a, y1b = rcur[dst] - k, rcur[dst]
            lcur[src] -= k
            rcur[dst] -= k
            x0, x1 = 0.09, 0.91
            verts = [(x0, y0b), (0.5, y0b), (0.5, y1b), (x1, y1b), (x1, y1a), (0.5, y1a), (0.5, y0a), (x0, y0a), (x0, y0b)]
            codes = [MPath.MOVETO, MPath.CURVE4, MPath.CURVE4, MPath.CURVE4, MPath.LINETO, MPath.CURVE4, MPath.CURVE4, MPath.CURVE4, MPath.CLOSEPOLY]
            moved = src != dst
            ax.add_patch(PathPatch(MPath(verts, codes), facecolor=BAND[dst] if moved else CONTEXT,
                                   alpha=0.85 if moved else 0.45, edgecolor=SURFACE, linewidth=1.2))
    for side, pos, counts, x in (("CVSS-BT", lp, left, 0.0), ("AIVSS", rp, right, 0.91)):
        for b in BANDS:
            lo, hi = pos[b]
            if hi > lo:
                ax.add_patch(Rectangle((x, lo), 0.09, hi - lo, color=BAND[b], ec=SURFACE, lw=2))
                label_x, ha = (x - 0.02, "right") if x == 0 else (x + 0.11, "left")
                ax.text(label_x, (lo + hi) / 2, f"{b}  {counts[b]}" if ha == "left" else f"{counts[b]}  {b}",
                        ha=ha, va="center", fontsize=9, color=TEXT)
        ax.text(x + 0.045, total_h + 0.9, side, ha="center", fontsize=10, weight="bold", color=TEXT)
    ax.set_title(f"Where each finding's severity band moves when AIVSS is applied (N={n})", pad=18)
    ax.text(0.5, -2.2, "Colored ribbons are findings whose band rises; gray ribbons keep their band. No ribbon falls.",
            ha="center", fontsize=8, color=MUTED)
    return _save(fig, out), {f"{a} -> {b}": c for (a, b), c in sorted(flows.items(), key=lambda kv: (BANDS.index(kv[0][0]), BANDS.index(kv[0][1])))}


def dumbbells(rows: list[dict], out: Path) -> tuple[str, list]:
    """One row per finding: CVSS-BT dot to AIVSS dot, grouped by agent class, band zones behind."""
    order = {"A2": 0, "A1": 1, "AX": 2, "A0": 3}
    rows = sorted(rows, key=lambda r: (order[r["effect_class"]], -r["aivss"], -r["cvss_bt"], r["id"]))
    fig, ax = plt.subplots(figsize=(7.4, 0.15 * len(rows) + 1.4))
    for lo, hi, b in ((0, 4, "Low"), (4, 7, "Medium"), (7, 9, "High"), (9, 10.05, "Critical")):
        ax.axvspan(lo, hi, color=BAND[b], alpha=0.12, lw=0)
        ax.text((lo + hi) / 2, -1.6, b, ha="center", fontsize=7.5, color=MUTED)
    prev = None
    for i, r in enumerate(rows):
        if r["effect_class"] != prev:
            ax.text(10.35, i, f"Class {r['effect_class']}", fontsize=8, color=TEXT, weight="bold", va="center")
            if prev is not None:
                ax.axhline(i - 0.5, color=GRID, lw=0.8)
            prev = r["effect_class"]
        ax.plot([r["cvss_bt"], r["aivss"]], [i, i], color=ACCENT if r["aivss"] > r["cvss_bt"] else CONTEXT, lw=1.6, solid_capstyle="round")
        ax.scatter([r["cvss_bt"]], [i], s=22, color=CVSS_INK, zorder=3, edgecolors=SURFACE, linewidths=1.2)
        ax.scatter([r["aivss"]], [i], s=26, color=ACCENT, zorder=4, edgecolors=SURFACE, linewidths=1.2)
    ax.set_yticks(range(len(rows)), [r["id"] for r in rows], fontsize=6.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 10.05)
    ax.set_ylim(len(rows) - 0.4, -2.3)
    ax.set_xlabel("Score")
    ax.scatter([], [], color=CVSS_INK, s=22, label="CVSS-BT")
    ax.scatter([], [], color=ACCENT, s=26, label="AIVSS")
    ax.legend(frameon=False, loc="upper left", ncol=2, fontsize=8, bbox_to_anchor=(0.0, -0.035 * 48 / len(rows) - 0.02))
    ax.set_title("Each finding's lift from CVSS-BT to AIVSS, grouped by agent class")
    _hair(ax)
    return _save(fig, out), [(r["id"], r["effect_class"], r["cvss_bt"], r["aivss"]) for r in rows]


def forest(stats: list[dict], noise: tuple[float, float] | None, out: Path, title: str = "How often the assessors agree beyond chance") -> tuple[str, list]:
    """stats: name, kappa, low, high, n, declined. Forest plot with Landis-Koch style zones as muted context."""
    fig, ax = plt.subplots(figsize=(7.4, 0.36 * len(stats) + 1.1))
    for lo, hi, lab in ((-0.4, 0.2, "slight or none"), (0.2, 0.4, "fair"), (0.4, 0.6, "moderate"), (0.6, 0.8, "substantial"), (0.8, 1.0, "almost perfect")):
        ax.axvspan(lo, hi, color="#F3EFFD" if lab in ("moderate", "almost perfect") else SURFACE, lw=0)
        ax.text((max(lo, -0.4) + hi) / 2, -0.9, lab, ha="center", fontsize=7, color=MUTED)
    ax.axvline(0, color=MUTED, lw=0.8)
    for i, s in enumerate(stats):
        if s["kappa"] is None:
            ax.text(0.02, i, f"not computed: {s['declined']}", va="center", fontsize=7.5, color=MUTED)
            continue
        if s["low"] is not None:
            ax.plot([s["low"], s["high"]], [i, i], color="#9670E8", lw=2.4, solid_capstyle="round")
        ax.scatter([s["kappa"]], [i], s=46, color=ACCENT, zorder=3, edgecolors=SURFACE, linewidths=1.5)
        ax.text(1.03, i, f"{s['kappa']:.2f}   N={s['n']}", va="center", fontsize=7.8, color=TEXT)
    ax.set_yticks(range(len(stats)), [s["name"] for s in stats], fontsize=8.5)
    ax.set_ylim(len(stats) - 0.4, -1.4)
    ax.set_xlim(-0.4, 1.0)
    ax.set_xlabel("Fleiss' kappa with 95% cluster bootstrap interval (0 is chance agreement)")
    ax.set_title(title)
    _hair(ax)
    return _save(fig, out), [(s["name"], s["kappa"], s["low"], s["high"], s["n"]) for s in stats]


def unit_chart(cells: dict[str, int], emphasis: str, labels: dict[str, str], out: Path, title: str) -> tuple[str, dict]:
    """Waffle of units, one square per assessor pair; one category emphasized, the rest gray."""
    order = [emphasis] + [k for k in labels if k != emphasis]
    shades = {emphasis: ACCENT}
    greys = ["#8E8C9C", "#B9B7C4", "#DAD9E0"]
    for k, g in zip([k for k in order if k != emphasis], greys):
        shades[k] = g
    units = [k for k in order for _ in range(cells.get(k, 0))]
    cols = 16 if len(units) <= 96 else 32
    rows_n = (len(units) + cols - 1) // cols
    fig, ax = plt.subplots(figsize=(7.4, (0.42 * rows_n + 1.1) * 16 / cols + 0.6))
    for i, k in enumerate(units):
        r, c = divmod(i, cols)
        ax.add_patch(FancyBboxPatch((c, -r), 0.82, 0.82, boxstyle="round,pad=0,rounding_size=0.12", color=shades[k], lw=0))
    ax.set_xlim(-0.2, cols + 0.2)
    ax.set_aspect("equal")
    ax.set_axis_off()
    for idx, k in enumerate(order):
        v = cells.get(k, 0)
        x, y = (idx % 2) * cols / 2, 2.6 - (idx // 2) * 1.1
        sq = 0.7
        ax.add_patch(Rectangle((x, y - sq / 2), sq, sq, color=shades[k], clip_on=False))
        ax.text(x + sq * 1.5, y, f"{labels[k]}: {v}", va="center", fontsize=8, color=TEXT)
    ax.set_ylim(-(rows_n - 1) - 0.15, 3.3)
    ax.set_title(title, pad=6)
    return _save(fig, out), {labels[k]: cells.get(k, 0) for k in order}


def heatmap(matrix: dict[str, dict[str, int]], cols: list[str], col_names: list[str], total: int, out: Path) -> tuple[str, dict]:
    rows = list(matrix)
    fig, ax = plt.subplots(figsize=(7.4, 0.55 * len(rows) + 1.2))
    vmax = max(1, max(matrix[r][c] for r in rows for c in cols))
    ramp = ["#F6F5F8", "#E3DAF8", "#BBA6F0", "#9670E8", "#6E32E0", "#2A0F66"]
    for i, r in enumerate(rows):
        for j, c in enumerate(cols):
            v = matrix[r][c]
            step = 0 if v == 0 else min(5, 1 + int(4 * v / vmax))
            if v == 0:
                ax.add_patch(FancyBboxPatch((j + 0.04, i + 0.04), 0.92, 0.92, boxstyle="round,pad=0,rounding_size=0.08", color="#F6F5F8", lw=0))
            ax.add_patch(FancyBboxPatch((j + 0.04, i + 0.04), 0.92, 0.92, boxstyle="round,pad=0,rounding_size=0.08", color=ramp[step], lw=0))
            ax.text(j + 0.5, i + 0.5, str(v), ha="center", va="center", fontsize=9, color="white" if step >= 3 else TEXT)
    ax.set_xlim(0, len(cols))
    ax.set_ylim(len(rows), 0)
    ax.set_xticks([j + 0.5 for j in range(len(cols))], col_names, fontsize=8)
    ax.set_yticks([i + 0.5 for i in range(len(rows))], [f"Assessor {r}" for r in rows], fontsize=8.5)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(f"Unknown answers by assessor and metric (of {total} findings each)")
    return _save(fig, out), matrix


def slope(policy: dict[str, dict], n: int, out: Path) -> tuple[str, dict]:
    names = list(policy)
    fig, ax = plt.subplots(figsize=(7.4, 3.4))
    for key, color, label in (("aivss_hc", ACCENT, "AIVSS"), ("cvss_hc", CVSS_INK, "CVSS-BT")):
        ys = [policy[p][key] for p in names]
        ax.plot(range(len(names)), ys, color=color, lw=2, marker="o", ms=7, mec=SURFACE, mew=2)
        for i, y in enumerate(ys):
            ax.text(i, y + (1.6 if key == "aivss_hc" else -2.6), str(y), ha="center", fontsize=8.5, color=TEXT)
        ax.text(len(names) - 1 + 0.08, ys[-1], label, va="center", fontsize=9, color=TEXT, weight="bold")
    ax.set_xticks(range(len(names)), [f"Every finding\n{p.lower()}" for p in names], fontsize=8.5)
    ax.set_xlim(-0.3, len(names) - 0.3)
    ax.set_ylim(0, n + 4)
    ax.set_ylabel(f"Findings rated High or Critical (of {n})")
    ax.set_title("As exploit evidence weakens, CVSS-BT drops and AIVSS holds")
    _hair(ax, "y")
    return _save(fig, out), {p: {"AIVSS": policy[p]["aivss_hc"], "CVSS-BT": policy[p]["cvss_hc"]} for p in names}


def bump(scores_a: dict[str, float], scores_c: dict[str, float], k: int, out: Path) -> tuple[str, list]:
    """Rank lines for the findings in either top k; tied scores share a rank."""
    def ranks(sc):
        vals = sorted(set(sc.values()), reverse=True)
        return {f: 1 + sum(1 for v in sc.values() if v > sc[f]) for f in sc}, vals
    ra, _ = ranks(scores_a)
    rc, _ = ranks(scores_c)
    ids = sorted({f for f in scores_a if ra[f] <= k or rc[f] <= k}, key=lambda f: (rc[f], ra[f], f))
    span = max(max(ra[f] for f in ids), max(rc[f] for f in ids))
    fig, ax = plt.subplots(figsize=(7.4, min(5.2, 0.16 * span + 1.6)))
    for f in ids:
        top_both = ra[f] <= k and rc[f] <= k
        col = ACCENT if top_both else CONTEXT
        ax.plot([0, 1], [rc[f], ra[f]], color=col, lw=2 if top_both else 1.3, zorder=2)
        ax.scatter([0, 1], [rc[f], ra[f]], s=30, color=col, zorder=3, edgecolors=SURFACE, linewidths=1.5)
    for side, rk, sc, x, ha in (("CVSS-BT", rc, scores_c, -0.04, "right"), ("AIVSS", ra, scores_a, 1.04, "left")):
        groups: dict[int, list[str]] = {}
        for f in ids:
            groups.setdefault(rk[f], []).append(f)
        for r_, fs in groups.items():
            ax.text(x, r_, f"{', '.join(sorted(fs))}  ({sc[fs[0]]:.1f})" if ha == "left" else f"({sc[fs[0]]:.1f})  {', '.join(sorted(fs))}",
                    ha=ha, va="center", fontsize=7, color=TEXT)
        ax.text(0 if side == "CVSS-BT" else 1, 0.1, f"{side} rank", ha="center", fontsize=9, weight="bold", color=TEXT)
    ax.axhspan(0.5, k + 0.5, color="#F3EFFD", lw=0, zorder=0)
    ax.set_ylim(span + 1, -0.6)
    ax.set_xlim(-1.1, 2.1)
    ax.set_axis_off()
    ax.set_title(f"Where the findings in either top {k} rank under each score")
    return _save(fig, out), [(f, rc[f], scores_c[f], ra[f], scores_a[f]) for f in ids]


def outcome_grid(rows: list[tuple[str, str, str]], out: Path) -> tuple[str, list]:
    """rows: (scenario, fallback decision, model decision)."""
    fig, ax = plt.subplots(figsize=(7.4, 0.55 * len(rows) + 1.3))
    ax.set_axis_off()
    heads = ("Scenario", "No-key fallback rules", "Model through a US endpoint")
    xs = (0.0, 0.36, 0.69)
    for x, h in zip(xs, heads):
        ax.text(x, len(rows) + 0.25, h, fontsize=9, weight="bold", color=TEXT)
    for i, (name, fb, md) in enumerate(rows):
        y = len(rows) - 1 - i
        import textwrap
        ax.text(xs[0], y + 0.35, textwrap.fill(name, 30), fontsize=8.2, color=TEXT, va="center", linespacing=1.1)
        for x, dec in ((xs[1], fb), (xs[2], md)):
            approved = str(dec).lower() == "approved"
            ax.add_patch(Rectangle((x, y + 0.1), 0.28, 0.5, color=ACCENT if approved else "#F3EFFD", lw=0))
            label = "Approved, paid" if approved else ("Sent to review" if dec else "Not run")
            ax.text(x + 0.14, y + 0.35, ("✕ " if approved else "✓ ") + label, ha="center", va="center",
                    fontsize=8.2, color="white" if approved else TEXT)
    ax.set_xlim(0, 1)
    ax.set_ylim(-0.2, len(rows) + 0.7)
    ax.set_title("Same invoices, two different systems: who approved payment", pad=10)
    return _save(fig, out), rows


def stability(data: dict[str, dict[str, tuple[int, int]]], out: Path) -> tuple[str, dict]:
    """data: comparison name -> slot -> (same band count, compared). One hue per assessor plus a letter on each dot."""
    comps = list(data)
    fig, ax = plt.subplots(figsize=(7.4, 0.75 * len(comps) + 1.3))
    for i, c in enumerate(comps):
        ax.axhline(i, color=GRID, lw=0.7, zorder=0)
        slots = sorted(data[c])
        for j, s in enumerate(slots):
            same, n = data[c][s]
            if not n:
                continue
            x = 100 * same / n
            dy = (j - (len(slots) - 1) / 2) * 0.1
            ax.scatter([x], [i + dy], s=120, color=SLOT.get(s, MUTED), edgecolors=SURFACE, linewidths=1.5, zorder=3)
            ax.text(x, i + dy, s, ha="center", va="center", fontsize=6.5, color="white", weight="bold", zorder=4)
    ax.set_yticks(range(len(comps)), comps, fontsize=8.5)
    ax.set_ylim(len(comps) - 0.5, -0.6)
    ax.set_xlim(0, 105)
    ax.set_xlabel("Findings that kept the same AIVSS band (%)")
    ax.set_title("How stable each assessor's AIVSS band is when a briefing is resent or changed")
    _hair(ax)
    return _save(fig, out), data
