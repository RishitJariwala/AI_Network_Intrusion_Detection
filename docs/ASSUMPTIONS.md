# Assumptions and Decisions Log

Every entry records a decision made without an official assessment brief. Revise as soon as a brief or rubric is available.

| ID | Assumption / decision | Reason | Status |
|----|-----------------------|--------|--------|
| A-01 | The master project specification is the working baseline; no CIA brief or rubric exists. | None supplied. | Open: replace when a brief arrives. |
| A-02 | Scope tiers: MVP first, add-ons next, stretch last (CTI, UNSW-NB15, PostgreSQL). | Agreed with the student. | Agreed |
| A-03 | Python 3.11 is the target interpreter. numpy is pinned to 2.4.6 because numpy 2.5.x requires Python 3.12 or newer. | Resolved while building the environment: `numpy==2.5.4` fails on 3.11. | Verified |
| A-04 | The supplied `requirements.txt` was a `pip freeze` from a different environment (numpy 2.5.4, an environment with `appnope`, `pexpect`, `ptyprocess`) and lacks FastAPI, Streamlit, SQLAlchemy and pytest. It is replaced by a curated, tested file. | Not installable on 3.11 as written; missing core packages. | Verified |
| A-05 | The build sandbox cannot reach the dataset hosts (HTTP 403 through the proxy). Real dataset statistics are therefore not available yet. Phase 1 code is tested only on synthetic data, which is never used for results. | Observed in Phase 0. | Student action: run `verify-data` and the EDA locally. |
| A-06 | The loader keeps integers lossless and floats at float64 so duplicate detection is exact. Cast to float32 only at modelling time if memory is tight. | Duplicate and leakage analysis must not be distorted by rounding. | Decided |
| A-07 | Timestamps are parsed day-first (the published files use D/M/YYYY, with the capture running 3-7 July 2017). Unparseable values are counted, never dropped silently. The files carry no AM/PM marker, so hour-of-day is validated against the published attack schedule before use. | Ambiguity in source format. | To confirm on real files |
| A-08 | `src/data/schema.py` was written from knowledge of CICFlowMeter output, not from the real files. `scripts/verify_dataset.py` compares it with the downloaded CSVs. The real files win any disagreement. | Schema could not be checked in the sandbox. | To confirm on real files |
| A-09 | SQLite is the default database; PostgreSQL is optional through `DATABASE_URL`. | Agreed with the student. | Agreed |
| A-10 | Commands are provided for Windows PowerShell, as the specification requires. All code uses `pathlib`, so it is OS-independent. | Specification. | Decided |
