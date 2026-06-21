# Pipeline Retrain — V2 Model on the Corrected Master Dataset

Retrains your friend's **exact pipeline architecture**
(`ColumnDropper → OneHotEncoder(protocol)+StandardScaler → SMOTE → RandomForest`)
on the corrected v2 dataset, with a **verification gate after every step**. The
only architectural change: `ColumnDropper` now **keeps** the features that were
dead in v1 (they carry signal in v2).

**Where to run:** the model host or the t530 — **Python ≥3.9** (the Controller VM
is 3.8 and cannot install scikit-learn ≥1.6). Inputs: `dataset_v2_master_training.csv`
(meta-stripped, from `dataset_merge.py`) and the existing `full_ml_pipeline.joblib`
(only to copy its drop list).

> Run the steps in order. **Do not proceed past a step whose verification fails.**
> You can paste them into one file `train_v2.py` and run it, or run block-by-block.

---

## Step 0 — Environment check

```bash
python3 -c "import sys,sklearn,imblearn,pandas,joblib;print('py',sys.version.split()[0]);print('sklearn',sklearn.__version__);print('imblearn',imblearn.__version__)"
```
**✅ Verify:** Python ≥ 3.9 and scikit-learn ≥ 1.6. If not:
`pip install "scikit-learn>=1.6" imbalanced-learn pandas joblib`.

---

## Step 1 — Imports + the custom transformer (defined in `__main__`)

`ColumnDropper` must live in `__main__` so the saved pickle resolves the same way
the controller's `ml_inference.py` expects it.

```python
import joblib, numpy as np, pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE

class ColumnDropper(BaseEstimator, TransformerMixin):
    def __init__(self, columns_to_drop=None):
        self.columns_to_drop = columns_to_drop or []
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        return X.drop(columns=[c for c in self.columns_to_drop if c in X.columns])
```
**✅ Verify:** no import errors.

---

## Step 2 — Load + sanity-check the master training file

```python
DF = pd.read_csv('dataset_v2_master_training.csv', low_memory=False)
print('shape:', DF.shape)
print(DF['attack_type'].value_counts())
```
**✅ Verify:** only the 7 canonical classes appear; every attack class has a
healthy count (≥200 ideally). If a class is thin, collect another session for it
before continuing.

---

## Step 3 — Fixed label mapping (matches `ml_inference.py`)

```python
INT_TO_LABEL = {0:'normal',1:'ICMP Flood',2:'SYN Flood',3:'ARP Spoofing',
                4:'UDP Flood',5:'Port Scan',6:'Control Plane Saturation'}
LABEL_TO_INT = {v:k for k,v in INT_TO_LABEL.items()}

unexpected = set(DF['attack_type'].unique()) - set(LABEL_TO_INT)
assert not unexpected, f'unexpected attack_type values: {unexpected}'
y = DF['attack_type'].map(LABEL_TO_INT)
assert y.notna().all(), 'NaN in encoded labels'
print('label mapping OK; class ints:', sorted(y.unique()))
```
**✅ Verify:** assertions pass. This mapping is identical to `ml_inference.py`'s
`INT_TO_LABEL`, so the controller will decode the new model correctly **without
any code change**.

---

## Step 4 — Build the v2 `ColumnDropper` (keep the now-live features)

```python
old = joblib.load('full_ml_pipeline.joblib')           # needs imblearn + ColumnDropper in scope (both above)
old_drop = list(old.named_steps['column_dropper'].columns_to_drop)

# Features that were DEAD in v1 (dropped) but carry real signal in v2 — re-include them:
REINCLUDE = {'reply_rate','bwd_packet_count','bwd_avg_packet_size','completed_sessions',
             'avg_session_duration','dst_port_std','sequential_port_score',
             'is_registered_iot','is_gateway','is_broadcast_dst',
             'multicast_ratio','arp_gratuitous_count'}

v2_drop = [c for c in old_drop if c not in REINCLUDE]
# always drop target + identifiers/leakage (belt-and-suspenders)
for c in ['attack_type','label','snort_sid','timestamp','src_ip','dst_ip','src_port','dst_port']:
    if c in DF.columns and c not in v2_drop:
        v2_drop.append(c)

reincluded = sorted(REINCLUDE & set(old_drop))
print('RE-INCLUDED (now features):', reincluded)
print('still dropped:', len(v2_drop), 'columns')
assert all(c not in v2_drop for c in reincluded), 'a re-included feature is still being dropped!'
```
**✅ Verify:** the printed RE-INCLUDED list contains the v2 features
(`reply_rate`, `bwd_*`, `dst_port_std`, `sequential_port_score`,
`is_broadcast_dst`, `is_registered_iot`, …) and the assert passes.

---

## Step 5 — Assemble the pipeline (same architecture)

```python
after_drop = [c for c in DF.columns if c not in v2_drop]
num_cols   = [c for c in after_drop if c != 'protocol']

preprocessor = ColumnTransformer([
    ('cat', OneHotEncoder(handle_unknown='ignore'), ['protocol']),
    ('num', StandardScaler(), num_cols),
], remainder='drop')

pipe = ImbPipeline([
    ('column_dropper', ColumnDropper(v2_drop)),
    ('preprocessor',   preprocessor),
    ('smote',          SMOTE(random_state=42)),
    ('classifier',     RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=10,
        class_weight='balanced', random_state=42, n_jobs=-1)),
])
print('numeric features:', len(num_cols))
assert any(c in num_cols for c in reincluded), 're-included features not in the model input!'
```
**✅ Verify:** `numeric features` is larger than the v1 count (was 63) and the
assert passes (the new features are actually fed to the model).

---

## Step 6 — Stratified train/test split

```python
X_tr, X_te, y_tr, y_te = train_test_split(DF, y, test_size=0.20,
                                          stratify=y, random_state=42)
print('train:', dict(y_tr.value_counts())); print('test:', dict(y_te.value_counts()))
assert set(y_tr.unique()) == set(y_te.unique()) == set(y.unique()), 'a class is missing from a split'
```
**✅ Verify:** all 7 classes present in both train and test.

---

## Step 7 — Fit

```python
pipe.fit(X_tr, y_tr)
print('fit complete')
```
**✅ Verify:** completes without error. If SMOTE raises
*"Expected n_neighbors <= n_samples"*, a class is too small — collect more rows
for it (re-run that session) and restart.

---

## Step 8 — Evaluate on the hold-out

```python
pred = pipe.predict(X_te)
names = [INT_TO_LABEL[i] for i in sorted(y.unique())]
print('accuracy:', round(accuracy_score(y_te, pred)*100, 2), '%')
print(classification_report(y_te, pred, target_names=names, digits=3))
print(confusion_matrix(y_te, pred))
```
**✅ Verify:** every attack class recall ≥ ~0.90 and **no class at 0**. (This is
in-distribution; the real test is Step 9.)

---

## Step 9 — Evaluate on a SEPARATE unseen session (the real generalization test)

Collect **one extra session not used in training** — ideally a mixed/infected
scenario with a device whose normal profile differs from training — validate it
(`validate_dataset.py`), then:

```python
UN = pd.read_csv('dataset_unseen_session.csv', low_memory=False)
y_un  = UN['attack_type'].map(LABEL_TO_INT)
pred_un = pipe.predict(UN)
print('UNSEEN accuracy:', round(accuracy_score(y_un, pred_un)*100, 2), '%')
print(classification_report(y_un, pred_un,
      target_names=[INT_TO_LABEL[i] for i in sorted(y_un.unique())], digits=3))
print(confusion_matrix(y_un, pred_un))
```
**✅ Verify (the decisive check):** the model detects attacks from a device whose
*normal profile differs from training* — i.e. it does **not** repeat the v1
failure (0% recall on an infected host with a busy/different profile). If recall
collapses here, your training set still lacks profile diversity → collect more
varied sessions and retrain.

---

## Step 10 — Save + round-trip verify

```python
joblib.dump(pipe, 'full_ml_pipeline_v2.joblib')
reloaded = joblib.load('full_ml_pipeline_v2.joblib')
assert (reloaded.predict(X_te) == pred).all(), 'reloaded model predicts differently'
print('saved full_ml_pipeline_v2.joblib + round-trip OK')
```
**✅ Verify:** assert passes (the saved file reproduces predictions exactly).

---

## Step 11 — Deploy to the controller

```bash
# on the host that runs the controller (Python >=3.9):
mkdir -p <repo>/Controller/ml_models
cp full_ml_pipeline_v2.joblib <repo>/Controller/ml_models/full_ml_pipeline.joblib
pip install "scikit-learn>=1.6" imbalanced-learn pandas
```
Then start the controller and confirm it loads:
```bash
IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**✅ Verify:** the log shows `ML inference engine loaded pipeline: …/ml_models/full_ml_pipeline.joblib`
and `Feature schema mode: v2 (corrected)`. `ml_inference.py` needs **no edits** —
its `ColumnDropper` and `INT_TO_LABEL` already match this model.

> **Run live in OBSERVE first** (`CONTROL:ML:OBSERVE`) and watch predictions
> before `CONTROL:ML:AUTHORIZE:0.80`. Critically, the controller must capture in
> **v2 mode** (`IPS_V2_FEATURES=1`) at inference time — the model now expects the
> corrected features, so v2 capture and the v2 model must always be paired.

---

## Why each verification matters

| Step | Guards against |
|---|---|
| 0 | wrong Python/sklearn → pipeline won't load on this host |
| 2 | thin/missing classes, label pollution slipping into training |
| 3 | label-order mismatch (the `pd.unique()` bug) → scrambled predictions |
| 4–5 | silently training on the OLD feature set (the whole point of v2) |
| 6 | a class absent from train or test → unmeasurable / untrained |
| 8 | in-distribution sanity (a class at 0 = broken) |
| 9 | **the v1 failure repeating** — poor generalization to new device profiles |
| 10 | a save/load mismatch shipping a different model than you evaluated |
| 11 | deploying a model the controller can't load or feeds wrong features |
