"""Pure functions over lists and dicts. Reads os.environ for one config flag."""
import os
from statistics import mean

DEBUG = os.environ.get("APP_DEBUG") == "1"


def normalize(rows):
    total = sum(r["weight"] for r in rows) or 1
    return [{**r, "share": r["weight"] / total} for r in rows]


def summarize(values):
    return {"n": len(values), "avg": mean(values) if values else 0.0}
