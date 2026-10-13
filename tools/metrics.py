"""
Precision / recall / F1 for predicted vs expected ATT&CK technique IDs.

strict:  an ID counts only if it matches exactly.
lenient: an ID also counts if it is the parent or a sub-technique of an expected ID
         (T1059 <-> T1059.007). Siblings (T1059.005 vs T1059.007) do not count.
"""


def is_related(a: str, b: str) -> bool:
    """Same technique, or one is the parent of the other."""
    return a == b or a == b.split(".")[0] or b == a.split(".")[0]


def match_counts(predicted: set[str], expected: set[str], lenient: bool = False) -> tuple[int, int, int, int]:
    """
    Returns (correct predictions, number predicted, expected IDs found, number expected).
    Precision uses the first pair, recall the second.
    """
    if lenient:
        correct = sum(any(is_related(p, e) for e in expected) for p in predicted)
        found = sum(any(is_related(p, e) for p in predicted) for e in expected)
    else:
        correct = found = len(predicted & expected)
    return correct, len(predicted), found, len(expected)


def scores_from_counts(correct: int, n_predicted: int, found: int, n_expected: int) -> dict:
    precision = correct / n_predicted if n_predicted else 0.0
    recall = found / n_expected if n_expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


def lenient_precision_recall_f1(predicted: set[str], expected: set[str]) -> dict:
    """Like precision_recall_f1, but parent/sub-technique matches count."""
    result = scores_from_counts(*match_counts(predicted, expected, lenient=True))
    result["missed"] = sorted(e for e in expected if not any(is_related(p, e) for p in predicted))
    return result


def precision_recall_f1(predicted: set[str], expected: set[str]) -> dict:
    """
    precision = correct predictions / all predictions
    recall    = correct predictions / all expected techniques
    f1        = harmonic mean of precision and recall
    """
    true_positives = predicted & expected
    precision = len(true_positives) / len(predicted) if predicted else 0.0
    recall = len(true_positives) / len(expected) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "true_positives": sorted(true_positives),
        "false_positives": sorted(predicted - expected),
        "missed": sorted(expected - predicted),
    }
