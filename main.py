"""Unified Command-Line Interface for AI-Powered Network Intrusion Detection & CTI System.

Subcommands:
    python main.py verify-data      Verify data/raw and write SHA-256 dataset manifest
    python main.py eda              Execute exploratory data analysis and generate diagnostic plots
    python main.py preprocess       Execute anti-leakage data cleaning, feature selection, and split
    python main.py train            Train, tune, and evaluate Binary, Multiclass, and Anomaly models
    python main.py explain          Generate global and local SHAP explanations
    python main.py serve-api        Start production-ready FastAPI backend server (Uvicorn)
    python main.py dashboard        Launch interactive Streamlit SOC dashboard
    python main.py test             Run automated pytest test suite
"""
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nids_cli")


def cmd_verify(_: argparse.Namespace) -> int:
    return subprocess.call([sys.executable, str(ROOT / "scripts" / "verify_dataset.py")])


def cmd_eda(_: argparse.Namespace) -> int:
    from src.config import ensure_dirs
    from src.data.eda import run_eda
    from src.data.loader import load_dataset

    ensure_dirs()
    logger.info("Loading dataset for EDA ...")
    df = load_dataset()
    summary = run_eda(df)
    print(f"EDA complete: {summary['n_rows']:,} rows analyzed. Figures saved: {summary['figures']}")
    return 0


def cmd_preprocess(args: argparse.Namespace) -> int:
    from src.data.loader import load_dataset
    from src.data.preprocess import run_preprocessing_pipeline

    logger.info("Loading raw captures for preprocessing ...")
    df = load_dataset()
    meta = run_preprocessing_pipeline(df, sample_size=args.sample_size)
    print(f"Preprocessing finished. {meta['n_selected_features']} features retained across {meta['train_samples']} training samples.")
    return 0


def cmd_train(_: argparse.Namespace) -> int:
    from src.detection.train import train_and_evaluate_all
    logger.info("Training and evaluating all ML models ...")
    results = train_and_evaluate_all()
    print("Training finished successfully. Check outputs/evaluation/ for reports.")
    return 0


def cmd_explain(_: argparse.Namespace) -> int:
    from src.explainability.explainer import get_explainer
    logger.info("Generating global SHAP feature importances ...")
    explainer = get_explainer()
    importance = explainer.generate_global_importance()
    print("Top 10 Influential Features by Mean |SHAP| Value:")
    for i, (k, v) in enumerate(list(importance.items())[:10], 1):
        print(f"  {i}. {k:<28} : {v:.4f}")
    return 0


def cmd_serve_api(args: argparse.Namespace) -> int:
    import uvicorn
    logger.info("Starting FastAPI service on %s:%d ...", args.host, args.port)
    uvicorn.run("src.api.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    app_path = ROOT / "dashboard" / "app.py"
    logger.info("Starting Streamlit Dashboard on port %d ...", args.port)
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(args.port)]
    return subprocess.call(cmd)


def cmd_test(_: argparse.Namespace) -> int:
    logger.info("Executing pytest test suite ...")
    return subprocess.call([sys.executable, "-m", "pytest", "-v"])


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-Powered Network Intrusion Detection & CTI System")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify-data", help="Verify dataset schema & integrity").set_defaults(func=cmd_verify)
    sub.add_parser("eda", help="Run exploratory data analysis").set_defaults(func=cmd_eda)

    p_prep = sub.add_parser("preprocess", help="Run preprocessing pipeline")
    p_prep.add_argument("--sample-size", type=int, default=150_000, help="Balanced target sample size")
    p_prep.set_defaults(func=cmd_preprocess)

    sub.add_parser("train", help="Train and evaluate all machine learning models").set_defaults(func=cmd_train)
    sub.add_parser("explain", help="Compute SHAP explanations and plots").set_defaults(func=cmd_explain)

    p_api = sub.add_parser("serve-api", help="Launch FastAPI REST backend")
    p_api.add_argument("--host", default="0.0.0.0", help="Binding host")
    p_api.add_argument("--port", type=int, default=8000, help="Port")
    p_api.add_argument("--reload", action="store_true", help="Enable live auto-reload")
    p_api.set_defaults(func=cmd_serve_api)

    p_dash = sub.add_parser("dashboard", help="Launch Streamlit SOC dashboard")
    p_dash.add_argument("--port", type=int, default=8501, help="Port")
    p_dash.set_defaults(func=cmd_dashboard)

    sub.add_parser("test", help="Execute automated test suite").set_defaults(func=cmd_test)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
