"""
Learned triage: score alerts with a model trained on audited findings.

Each alert becomes one training example with two views:

- `features`: a handful of language-agnostic numbers a reviewer would look at
  (path length, files and functions crossed, conversions, sanitiser-like and
  collection calls on the path, guards around the sink, corroboration by other
  tools, whether the AST pruner proves it dead, ...) for gradient-boosted trees;
- `graph`: a code graph in the spirit of Devign (Zhou et al., NeurIPS 2019):
  the AST of every function on the reported path, with statement order, token
  order, def-use and call edges plus the analyzer's own source-to-sink edges,
  for a gated graph neural network (GGNN).

Identifiers and literals are abstracted (only call, field and type names are
kept), comments are stripped and node types are bucketed into coarse kinds
shared by every tree-sitter grammar, so one model can be trained on several
languages. Examples are grouped by a hash of their abstracted slice: grouped
cross-validation keeps near-identical findings out of the test fold, which a
random split does not.

Modules: `graph` (code graphs), `features` (hand-made features and groups),
`data` (labels and the JSONL dataset), `models` (GBDT, GGNN, cross-validation,
saving and loading; needs the `[ml]` extra).
"""
