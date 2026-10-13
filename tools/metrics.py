"""Precision / recall / F1 for predicted vs expected ATT&CK technique IDs."""


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
