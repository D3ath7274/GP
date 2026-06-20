"""
Reusable definition of the friend's custom `ColumnDropper` transformer.

`full_ml_pipeline.joblib` was pickled with a `ColumnDropper` class that lived in
the training notebook's `__main__` module. joblib/pickle therefore looks for
`__main__.ColumnDropper` at load time and raises
`AttributeError: Can't get attribute 'ColumnDropper'` if it is absent.

Importing this module makes the class available AND registers it into `__main__`
so the pipeline unpickles anywhere — the test script, the Ryu controller, or the
t530 — without copy-pasting the class definition each time:

    import column_dropper          # noqa: F401  (registers into __main__)
    pipe = joblib.load('full_ml_pipeline.joblib')
"""
from sklearn.base import BaseEstimator, TransformerMixin


class ColumnDropper(BaseEstimator, TransformerMixin):
    """Drops a fixed list of columns (the list is restored from the pickle)."""

    def __init__(self, columns_to_drop=None):
        self.columns_to_drop = columns_to_drop or []

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # Defensive: only drop columns that are present, so a missing optional
        # column never crashes inference.
        return X.drop(columns=[c for c in self.columns_to_drop if c in X.columns])


# Register into __main__ so pickle can resolve `__main__.ColumnDropper`.
import __main__ as _main  # noqa: E402
if not hasattr(_main, "ColumnDropper"):
    _main.ColumnDropper = ColumnDropper
