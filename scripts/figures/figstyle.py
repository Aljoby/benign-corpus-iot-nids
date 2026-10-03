"""Shared typography for the paper figures (fig_scores_both_v1n.pdf, fig_ablation_v2.pdf).
normal=True: Times New Roman (STIX math), normal weight — the settings used for fig_scores_both_v1n.pdf."""
import matplotlib.pyplot as plt

TICK, LABEL, TITLE, LEGEND, SMALL = 9, 10, 10, 8, 7     # pt: ticks, axis labels, titles, legend, notes


def apply(normal=True):
    w = "normal" if normal else "bold"
    plt.rcParams.update({"font.weight": w, "axes.labelweight": w, "axes.titleweight": w,
                         "xtick.labelsize": TICK, "ytick.labelsize": TICK, "axes.labelsize": LABEL,
                         "axes.titlesize": TITLE, "pdf.fonttype": 42})
    if normal:
        plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Times", "STIXGeneral"],
                             "mathtext.fontset": "stix"})
    return w
