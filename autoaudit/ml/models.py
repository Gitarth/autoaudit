"""
Models for learned triage (needs the `[ml]` extra: scikit-learn, torch).

  gbdt    gradient-boosted trees on the hand-made features (fast, strong baseline)
  ggnn    gated graph neural network on the code graph (Devign-style; no hand-made features)
  hybrid  the GGNN with the hand-made features joined before the classifier head

Every model outputs P(real). The decision threshold is not 0.5: it is chosen on
out-of-fold predictions so that a target share of REAL findings is kept (default
98%), because dismissing a real vulnerability costs far more than reviewing a
false one. Reported metrics therefore include "false alerts removed at that
recall", the number that matters to a reviewer.

Cross-validation splits:
  random   stratified k-fold (what most papers report; optimistic)
  grouped  stratified group k-fold on the dataset's `group` (abstracted slice,
           file or project): near-duplicates never straddle train and test
  cwe      leave one vulnerability class out: does the model generalise to a
           class it never saw?

Security: a saved GBDT is a pickle; load only models you trained. GGNN weights
are loaded with `weights_only=True`.
"""

from __future__ import annotations

import json
import logging
import math
import pickle
import random
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .graph import EDGE_TYPES, KINDS, N_FLAGS, VOCAB

log = logging.getLogger(__name__)
KINDS_N = len(KINDS)
MODEL_VERSION = "ml-v1"


def _require():
    try:
        import numpy  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("learned triage needs the ml extra: pip install 'autoaudit[ml]'") from e


def _torch():
    try:
        import torch
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("the GGNN needs PyTorch: pip install 'autoaudit[ml]'") from e
    return torch


# ------------------------------------------------------------------ features
@dataclass
class FeatureSpace:
    names: list[str] = field(default_factory=list)
    mean: list[float] = field(default_factory=list)
    std: list[float] = field(default_factory=list)

    @classmethod
    def fit(cls, records: list[dict], min_count: int = 3) -> FeatureSpace:
        counts = Counter(k for r in records for k in r["features"])
        names = sorted(k for k, c in counts.items() if c >= min_count or "=" not in k)
        fs = cls(names)
        x = fs.matrix(records, standardize=False)
        fs.mean = x.mean(axis=0).tolist()
        fs.std = [s if s > 1e-9 else 1.0 for s in x.std(axis=0).tolist()]
        return fs

    def matrix(self, records: list[dict], standardize: bool = False):
        import numpy as np

        col = {n: i for i, n in enumerate(self.names)}
        x = np.zeros((len(records), len(self.names)), dtype=np.float32)
        for i, r in enumerate(records):
            for k, v in r["features"].items():
                j = col.get(k)
                if j is not None:
                    x[i, j] = v
        if standardize:
            x = (x - np.asarray(self.mean, dtype=np.float32)) / np.asarray(self.std, dtype=np.float32)
        return x


# ---------------------------------------------------------------------- GBDT
class GBDT:
    kind = "gbdt"

    def __init__(self, seed: int = 0, **_):
        self.seed = seed
        self.space: FeatureSpace | None = None
        self.clf = None

    def fit(self, records: list[dict], labels: list[int]) -> GBDT:
        from sklearn.ensemble import HistGradientBoostingClassifier

        self.space = FeatureSpace.fit(records)
        self.clf = HistGradientBoostingClassifier(
            max_iter=300,
            learning_rate=0.05,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            class_weight="balanced",
            random_state=self.seed,
        )
        self.clf.fit(self.space.matrix(records), labels)
        return self

    def predict(self, records: list[dict]) -> list[float]:
        return self.clf.predict_proba(self.space.matrix(records))[:, 1].tolist()

    def save(self, d: Path) -> None:
        with open(d / "gbdt.pkl", "wb") as fh:
            pickle.dump({"space": self.space.__dict__, "clf": self.clf}, fh)

    @classmethod
    def load(cls, d: Path, meta: dict) -> GBDT:
        m = cls()
        with open(d / "gbdt.pkl", "rb") as fh:
            obj = pickle.load(fh)  # noqa: S301 - only models you trained (see module docstring)
        m.space, m.clf = FeatureSpace(**obj["space"]), obj["clf"]
        return m


# ---------------------------------------------------------------------- GGNN
def _net(hidden: int, steps: int, n_extra: int, dropout: float):
    torch = _torch()
    nn = torch.nn
    n_rel = 2 * len(EDGE_TYPES)  # every edge type in both directions

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb_type = nn.Embedding(VOCAB, hidden)
            self.emb_tok = nn.Embedding(VOCAB, hidden)
            self.emb_kind = nn.Embedding(KINDS_N, hidden)
            self.flags = nn.Linear(N_FLAGS, hidden)
            self.rel = nn.ModuleList(nn.Linear(hidden, hidden, bias=False) for _ in range(n_rel))
            self.gru = nn.GRUCell(hidden, hidden)
            self.gate = nn.Linear(2 * hidden, 1)
            self.proj = nn.Linear(2 * hidden, hidden)
            self.head = nn.Sequential(
                nn.Linear(2 * hidden + n_extra, hidden),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden, 1),
            )

        def forward(self, x, edges, batch, n_graphs, extra=None):
            h0 = (
                self.emb_type(x[:, 0])
                + self.emb_tok(x[:, 1])
                + self.emb_kind(x[:, 2])
                + self.flags(x[:, 3:].float())
            )
            src, dst, et = edges[:, 0], edges[:, 1], edges[:, 2]
            src2 = torch.cat([src, dst])
            dst2 = torch.cat([dst, src])
            rel2 = torch.cat([et, et + len(EDGE_TYPES)])
            groups = [(rel2 == r).nonzero(as_tuple=True)[0] for r in range(n_rel)]
            h = h0
            for _ in range(steps):
                agg = torch.zeros_like(h)
                for r, idx in enumerate(groups):
                    if idx.numel():
                        agg.index_add_(0, dst2[idx], self.rel[r](h[src2[idx]]))
                h = self.gru(agg, h)
            z = torch.cat([h, h0], dim=1)
            g = torch.sigmoid(self.gate(z)) * self.proj(z)  # gated readout (Li et al., GGNN)
            pooled = torch.zeros(n_graphs, g.shape[1]).index_add_(0, batch, g)
            on_flow = x[:, 3].float().unsqueeze(1)  # nodes on the reported path
            flow_sum = torch.zeros(n_graphs, h.shape[1]).index_add_(0, batch, h * on_flow)
            flow_n = torch.zeros(n_graphs, 1).index_add_(0, batch, on_flow).clamp(min=1)
            parts = [pooled, flow_sum / flow_n]
            if extra is not None:
                parts.append(extra)
            return self.head(torch.cat(parts, dim=1)).squeeze(1)

    return Net()


class GGNN:
    kind = "ggnn"

    def __init__(
        self,
        seed: int = 0,
        hidden: int = 64,
        steps: int = 4,
        epochs: int = 30,
        batch_size: int = 32,
        lr: float = 1e-3,
        dropout: float = 0.2,
        patience: int = 6,
        hybrid: bool = False,
        **_,
    ):
        self.cfg = dict(hidden=hidden, steps=steps, dropout=dropout)
        self.seed, self.epochs, self.batch_size, self.lr, self.patience = (
            seed,
            epochs,
            batch_size,
            lr,
            patience,
        )
        self.hybrid = hybrid
        self.space: FeatureSpace | None = None
        self.net = None
        if hybrid:
            self.kind = "hybrid"

    def _tensors(self, records: list[dict]):
        torch = _torch()
        extra = self.space.matrix(records, standardize=True) if self.hybrid else None
        out = []
        for i, r in enumerate(records):
            g = r.get("graph") or {"x": [[0] * (3 + N_FLAGS)], "e": []}
            x = torch.tensor(g["x"], dtype=torch.long)
            e = torch.tensor(g["e"], dtype=torch.long).reshape(-1, 3)
            ex = torch.from_numpy(extra[i]) if extra is not None else None
            out.append((x, e, ex))
        return out

    @staticmethod
    def _collate(items):
        torch = _torch()
        xs, es, batch, extras, offset = [], [], [], [], 0
        for i, (x, e, ex) in enumerate(items):
            xs.append(x)
            if e.numel():
                es.append(torch.cat([e[:, :2] + offset, e[:, 2:]], dim=1))
            batch.append(torch.full((x.shape[0],), i, dtype=torch.long))
            if ex is not None:
                extras.append(ex)
            offset += x.shape[0]
        edges = torch.cat(es) if es else torch.zeros((0, 3), dtype=torch.long)
        extra = torch.stack(extras) if extras else None
        return torch.cat(xs), edges, torch.cat(batch), len(items), extra

    def _scores(self, data) -> list[float]:
        torch = _torch()
        self.net.eval()
        out: list[float] = []
        with torch.no_grad():
            for i in range(0, len(data), 64):
                x, e, b, n, ex = self._collate(data[i : i + 64])
                out += torch.sigmoid(self.net(x, e, b, n, ex)).tolist()
        return out

    def fit(self, records: list[dict], labels: list[int]) -> GGNN:
        torch = _torch()
        from sklearn.metrics import roc_auc_score

        torch.manual_seed(self.seed)
        rng = random.Random(self.seed)
        self.space = FeatureSpace.fit(records)
        data = self._tensors(records)
        # hold out 10% of the training groups for early stopping
        groups = sorted({r["group"] for r in records})
        rng.shuffle(groups)
        val_groups = set(groups[: max(1, len(groups) // 10)])
        tr = [i for i, r in enumerate(records) if r["group"] not in val_groups]
        va = [i for i, r in enumerate(records) if r["group"] in val_groups]
        if len({labels[i] for i in va}) < 2 or len(tr) < 10:
            tr, va = list(range(len(records))), []
        n_extra = len(self.space.names) if self.hybrid else 0
        self.net = _net(self.cfg["hidden"], self.cfg["steps"], n_extra, self.cfg["dropout"])
        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr, weight_decay=1e-5)
        pos = sum(labels[i] for i in tr)
        weight = torch.tensor((len(tr) - pos) / max(pos, 1))
        loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=weight)
        best, best_state, bad = -1.0, None, 0
        for _epoch in range(self.epochs):
            self.net.train()
            rng.shuffle(tr)
            for i in range(0, len(tr), self.batch_size):
                idx = tr[i : i + self.batch_size]
                x, e, b, n, ex = self._collate([data[j] for j in idx])
                y = torch.tensor([labels[j] for j in idx], dtype=torch.float32)
                opt.zero_grad()
                loss = loss_fn(self.net(x, e, b, n, ex), y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.net.parameters(), 5.0)
                opt.step()
            if not va:
                continue
            auc = roc_auc_score([labels[j] for j in va], self._scores([data[j] for j in va]))
            log.debug("epoch %d: validation AUC %.3f", _epoch + 1, auc)
            if auc > best + 1e-4:
                best, bad = auc, 0
                best_state = {k: v.clone() for k, v in self.net.state_dict().items()}
            else:
                bad += 1
                if bad >= self.patience:
                    break
        if best_state is not None:
            self.net.load_state_dict(best_state)
        return self

    def predict(self, records: list[dict]) -> list[float]:
        return self._scores(self._tensors(records))

    def save(self, d: Path) -> None:
        torch = _torch()
        torch.save(self.net.state_dict(), d / "ggnn.pt")
        (d / "ggnn.json").write_text(
            json.dumps({"cfg": self.cfg, "hybrid": self.hybrid, "space": self.space.__dict__})
        )

    @classmethod
    def load(cls, d: Path, meta: dict) -> GGNN:
        torch = _torch()
        conf = json.loads((d / "ggnn.json").read_text())
        m = cls(hybrid=conf["hybrid"], **conf["cfg"])
        m.space = FeatureSpace(**conf["space"])
        n_extra = len(m.space.names) if m.hybrid else 0
        m.net = _net(conf["cfg"]["hidden"], conf["cfg"]["steps"], n_extra, conf["cfg"]["dropout"])
        m.net.load_state_dict(torch.load(d / "ggnn.pt", weights_only=True))
        return m


KINDS_OF_MODEL = {"gbdt": GBDT, "ggnn": GGNN, "hybrid": GGNN}


def make(kind: str, **kw):
    if kind == "hybrid":
        kw["hybrid"] = True
    return KINDS_OF_MODEL[kind](**kw)


# ------------------------------------------------------------------- metrics
def threshold_for_recall(probs: list[float], labels: list[int], target: float) -> float:
    """Largest threshold that still keeps at least `target` of the real findings."""
    pos = sorted(p for p, y in zip(probs, labels) if y)
    if not pos:
        return 0.5
    k = int(math.floor((1 - target) * len(pos) + 1e-9))
    return pos[min(k, len(pos) - 1)]


def metrics(probs: list[float], labels: list[int], threshold: float) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score

    out: dict = {"n": len(labels), "real": sum(labels)}
    if len(set(labels)) == 2:
        out["auc"] = round(float(roc_auc_score(labels, probs)), 3)
        out["avg_precision"] = round(float(average_precision_score(labels, probs)), 3)
    for name, t in (("at_0.5", 0.5), ("at_threshold", threshold)):
        tp = sum(1 for p, y in zip(probs, labels) if y and p >= t)
        fp = sum(1 for p, y in zip(probs, labels) if not y and p >= t)
        fn = sum(1 for p, y in zip(probs, labels) if y and p < t)
        tn = sum(1 for p, y in zip(probs, labels) if not y and p < t)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        out[name] = {
            "threshold": round(t, 4),
            "accuracy": round((tp + tn) / max(1, len(labels)), 3),
            "precision": round(prec, 3),
            "real_kept": round(rec, 3),
            "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
            "false_alerts_removed": round(tn / (tn + fp), 3) if tn + fp else None,
            "real_dismissed": fn,
        }
    return out


def cross_validate(
    records: list[dict], kind: str, split: str = "grouped", folds: int = 5, seed: int = 0, **kw
) -> list[float]:
    """Out-of-fold P(real) for every record."""
    _require()
    import numpy as np
    from sklearn.model_selection import LeaveOneGroupOut, StratifiedGroupKFold, StratifiedKFold

    y = np.array([int(r["label"]) for r in records])
    if split == "random":
        splitter = StratifiedKFold(folds, shuffle=True, random_state=seed).split(y, y)
    elif split == "grouped":
        groups = [r["group"] for r in records]
        splitter = StratifiedGroupKFold(folds, shuffle=True, random_state=seed).split(y, y, groups)
    elif split == "cwe":
        groups = [(r["cwes"] or [r["rule_id"]])[0] for r in records]
        splitter = LeaveOneGroupOut().split(y, y, groups)
    else:
        raise ValueError(f"unknown split {split!r}")
    oof = np.full(len(records), np.nan)
    for fold, (tr, te) in enumerate(splitter):
        log.info("%s %s fold %d: train %d, test %d", kind, split, fold + 1, len(tr), len(te))
        if len(set(y[tr])) < 2:
            oof[te] = y[tr].mean()
            continue
        m = make(kind, seed=seed, **kw).fit([records[i] for i in tr], y[tr].tolist())
        oof[te] = m.predict([records[i] for i in te])
    return oof.tolist()


# ------------------------------------------------------------- save and load
def save(model, d: Path, meta: dict) -> None:
    d.mkdir(parents=True, exist_ok=True)
    model.save(d)
    (d / "meta.json").write_text(json.dumps({"kind": model.kind, "version": MODEL_VERSION, **meta}, indent=2))


def load(d: Path):
    meta = json.loads((d / "meta.json").read_text())
    return KINDS_OF_MODEL[meta["kind"]].load(d, meta), meta
