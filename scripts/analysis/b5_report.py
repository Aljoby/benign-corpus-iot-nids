"""B5 figure + summary from outputs/B5_ablation.csv (works on partial results)."""
import json
import os
import sys

import numpy as np
import pandas as pd

T = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def macro16(df, run, col):
    d = df[(df.run == run) & (df.attack != "http_ddos")]
    return d[col].mean()


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    df = pd.read_csv(os.path.join(T, "B5_ablation.csv"))
    state = json.load(open(os.path.join(T, "B5_state.json"))) if os.path.exists(os.path.join(T, "B5_state.json")) else {}
    b1 = pd.read_csv(os.path.join(T, "B1_repro.csv"))
    ref = {"artifact proprietary (R1)": (macro16(b1, "R1_A_HE", "tpr_5e5"), macro16(b1, "R1_A_HE", "roc_auc")),
           "artifact open-source (R5)": (macro16(b1, "R5_B_HE", "tpr_5e5"), macro16(b1, "R5_B_HE", "roc_auc"))}
    he = df[df.model == "HorusEye"].drop_duplicates("subset", keep="last")
    order = [s for s in ["all14", "all14_seed1", "all14_seed2", "vol_match", "cam8", "gw6", "rand5_a", "rand5_a_seed1",
                         "rand5_b", "os_days1", "os_days2", "os_days3", "os_days5"] if s in set(he.subset)]
    he = he.set_index("subset").loc[order]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6))
    colors = ["#4C72B0" if c == "A" else "#55A868" for c in he.corpus]
    for ax, col, lab, k in ((axes[0], "macro_tpr_5e5", "Macro TPR @ FPR≤5e-5", 0), (axes[1], "macro_roc_auc", "Macro ROC-AUC", 1)):
        ax.bar(range(len(he)), he[col].values, color=colors)
        ax.set_xticks(range(len(he)))
        ax.set_xticklabels([s.replace("_", "\n", 1) for s in he.index], fontsize=7)
        for (name, v), ls in zip(ref.items(), ("--", ":")):
            ax.axhline(v[k], color="k", ls=ls, lw=1, label=name)
        for ref_sub, ls in (("all14", "-."), ("os_days5", "-.")):
            if ref_sub in he.index:
                ax.axhline(he.loc[ref_sub, col], color="#4C72B0" if ref_sub == "all14" else "#55A868", ls=ls, lw=1,
                           label="retrained %s (same epochs)" % ref_sub)
        if k == 0:  # allowed false positives at FPR<=5e-5 for each subset's benign test set
            for i, nb in enumerate(he.n_benign_test.values):
                ax.text(i, he[col].values[i] + 0.01, "≤%d FP" % int(np.floor((5e-5 + 1e-6) * nb)), ha="center", fontsize=6)
        ax.set_ylabel(lab)
        ax.legend(fontsize=6)
    fig.suptitle("HorusEye retrained on subsets (blue: proprietary subsets, green: open-source day subsets); "
                 "epochs=%s" % state.get("epochs"), fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(T, "fig_ablation.pdf"))
    L = ["# B5 / B5x — composition, volume and duration ablation", "",
         "Status: %s. Epochs per model: %s (original 20; first-epoch time %ss on %s; cap rule: ≤45 min/model and "
         "B5+B5x ≤ 3 h, same epochs for every model incl. the all14 reference). Planned (priority order): %s." % (
             "COMPLETE" if set(state.get("planned", [])) <= set(he.index) else "PARTIAL (missing: %s)" %
             sorted(set(state.get("planned", [])) - set(he.index)), state.get("epochs"), state.get("first_epoch_sec"),
             "mps", state.get("planned")), "",
         "Gulliver is retrained on each proprietary subset; the open-source day sweep keeps the artifact rules (as in "
         "the paper's open-source configuration). Test: benign test files of the same devices (proprietary) / standard "
         "open-source test days, all 17 attacks; macro over the 16 new attacks.", "",
         "| Subset | corpus | devices | train rows (packets) | n benign test | HorusEye macro TPR@5e-5 | HorusEye macro ROC-AUC | Magnifier macro TPR@5e-5 | Magnifier macro ROC-AUC | best epoch |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    mag = df[df.model == "Magnifier"].drop_duplicates("subset", keep="last").set_index("subset")
    for s, r in he.iterrows():
        L.append("| %s | %s | %s | %d | %d | %.4f | %.4f | %.4f | %.4f | %s |" % (
            s, "prop." if r.corpus == "A" else "open", r.devices if r.corpus == "A" else r.devices.replace("os_files_", "files "),
            r.n_train_rows, r.n_benign_test, r.macro_tpr_5e5, r.macro_roc_auc,
            mag.loc[s, "macro_tpr_5e5"] if s in mag.index else np.nan, mag.loc[s, "macro_roc_auc"] if s in mag.index else np.nan,
            r.best_epoch))
    L += ["", "Reference (artifact models, 16 attacks): proprietary macro TPR %.4f / ROC-AUC %.4f; open-source %.4f / %.4f." % (
        ref["artifact proprietary (R1)"] + ref["artifact open-source (R5)"])]
    seeds = he[he.index.str.startswith("all14")]
    if len(seeds) > 1:
        L.append("Magnifier/HorusEye retraining spread, all14 (n=%d seeds): macro TPR %.4f ± %.4f (sd), ROC-AUC %.4f ± %.4f." % (
            len(seeds), seeds.macro_tpr_5e5.mean(), seeds.macro_tpr_5e5.std(ddof=1), seeds.macro_roc_auc.mean(), seeds.macro_roc_auc.std(ddof=1)))
    open(os.path.join(T, "B5_summary.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
