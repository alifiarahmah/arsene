#!/usr/bin/env python3
import argparse
import re
import json

import pandas as pd
from bs4 import BeautifulSoup


def preprocess_endpoint(ep: str) -> str:
    """
    Normalisasi endpoint:
    - buang HTTP method (GET/POST/...)
    - buang skema+host
    - buang query string
    - buang placeholder {id}, {xyz}
    - buang trailing slash
    """
    ep = str(ep).strip()

    # Remove method prefix
    ep = re.sub(r'^(GET|POST|PUT|DELETE|PATCH)\s+', '', ep, flags=re.IGNORECASE)

    # Remove schema+host
    ep = re.sub(r'^https?://[^/]+', '', ep)

    # Remove query string
    ep = ep.split('?', 1)[0]

    # Remove path parameters like {id}
    ep = re.sub(r'\{[^}]+\}', '', ep)

    # Remove trailing slash (but keep root '/')
    if ep != '/':
        ep = ep.rstrip('/')

    return ep


def load_ground_truth(csv_path: str) -> pd.DataFrame:
    """
    Load CSV ground truth dengan engine='python' untuk toleransi format.
    Mengharapkan kolom 'Location (Endpoint)'.
    """
    df = pd.read_csv(
        csv_path,
        engine="python",
        quotechar='"',
        on_bad_lines="skip"  # abaikan baris aneh
    )
    if "Location (Endpoint)" not in df.columns:
        raise ValueError("CSV must contain a 'Location (Endpoint)' column")
    return df


def extract_zap_paths(html_path: str) -> set:
    """
    Ekstrak semua path yang mirip URL/endpoint dari report ZAP HTML.
    - Dari <a href="...">
    - Dari teks dengan regex
    Normalisasi: buang skema+host dan fragment.
    """
    with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    soup = BeautifulSoup(html, "html.parser")
    paths = set()

    # 1) from hrefs
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("http") or href.startswith("/"):
            path = re.sub(r"^https?://[^/]+", "", href)
            path = path.split("#", 1)[0]
            paths.add(path)

    # 2) from raw text
    text = soup.get_text("\n")
    # match http URLs or absolute-paths (/...)
    for match in re.findall(r"(https?://[^\s\"']+|/[^\s\"']+)", text):
        path = re.sub(r"^https?://[^/]+", "", match)
        path = path.split("#", 1)[0]
        paths.add(path)

    # Normalisasi trailing slash
    normalized = set()
    for p in paths:
        if p != "/":
            p = p.rstrip("/")
        normalized.add(p)

    return normalized


def match_endpoints(gt_df: pd.DataFrame, zap_paths: set):
    """
    Matching sangat sederhana berbasis prefix:
    - Untuk setiap ground-truth endpoint E, kalau ada path Z dari ZAP s.t. Z.startswith(E_norm) -> TP
    - Kalau tidak ada yang match -> FN
    - FP = jumlah path ZAP yang tidak pernah dipakai untuk match
    """
    tp = 0
    fn = 0
    matched_zap = set()

    # Preprocess semua ZAP paths sekali
    zap_norm = set(preprocess_endpoint(zp) for zp in zap_paths)

    for _, row in gt_df.iterrows():
        ep_raw = row["Location (Endpoint)"]
        ep = preprocess_endpoint(ep_raw)

        found = False
        for zp in zap_norm:
            if zp.startswith(ep) and ep != "":
                found = True
                matched_zap.add(zp)
                break

        if found:
            tp += 1
        else:
            fn += 1

    fp = len(zap_norm - matched_zap)
    return tp, fp, fn


def compute_metrics(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def evaluate_zap(zap_html_path: str, csv_gt_path: str) -> dict:
    """
    Evaluate ZAP HTML report against ground-truth CSV.

    Args:
        zap_html_path: Path to ZAP HTML report
        csv_gt_path: Path to ground-truth CSV file

    Returns:
        Dictionary containing:
        - tp: True positives
        - fp: False positives
        - fn: False negatives
        - precision: Precision score
        - recall: Recall score
        - f1: F1 score
        - total_gt: Total number of ground truth rows
        - total_zap_paths: Total number of ZAP paths found
    """
    gt_df = load_ground_truth(csv_gt_path)
    zap_paths = extract_zap_paths(zap_html_path)

    tp, fp, fn = match_endpoints(gt_df, zap_paths)
    precision, recall, f1 = compute_metrics(tp, fp, fn)

    result = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "total_gt": int(len(gt_df)),
        "total_zap_paths": int(len(zap_paths)),
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate ZAP HTML report against ground-truth CSV for Juice Shop."
    )
    parser.add_argument("zap_html", help="Path to ZAP HTML report (e.g., zap_report/juice-shop.html)")
    parser.add_argument("csv_gt", help="Path to ground-truth CSV (e.g., csv_vuln_list/juice_shop.csv)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of human-readable text."
    )
    args = parser.parse_args()

    result = evaluate_zap(args.zap_html, args.csv_gt)

    if args.json:
        # Convert to uppercase keys for JSON output to maintain backward compatibility
        json_result = {
            "TP": result["tp"],
            "FP": result["fp"],
            "FN": result["fn"],
            "precision": result["precision"],
            "recall": result["recall"],
            "f1": result["f1"],
            "total_gt": result["total_gt"],
            "total_zap_paths": result["total_zap_paths"],
        }
        print(json.dumps(json_result, indent=2))
    else:
        print(f"TP: {result['tp']}")
        print(f"FP: {result['fp']}")
        print(f"FN: {result['fn']}")
        print(f"Precision: {result['precision']:.3f}")
        print(f"Recall:    {result['recall']:.3f}")
        print(f"F1-score:  {result['f1']:.3f}")
        print()
        print(f"Total GT rows:      {result['total_gt']}")
        print(f"Total ZAP endpoints: {result['total_zap_paths']}")


if __name__ == "__main__":
    main()