# Argus NIDS: System Architecture & Data Flow

This document details the architectural topology, data pipelines, explainability framework, and operational workflows of the **AI-Powered Network Intrusion Detection & Cyber Threat Intelligence System (Argus NIDS)**.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    subgraph Ingestion["1. Data Ingestion & Offline Telemetry"]
        Raw["Raw Network Captures (CICIDS2017 / PCAP CSVs)"] --> Loader["Lossless Data Loader (src/data/loader.py)"]
        Loader --> Audit["Data-Quality & Statistical Audit (src/data/quality.py)"]
    end

    subgraph Preprocessing["2. Anti-Leakage Pipeline"]
        Audit --> Cleaner["Data Cleaner (Drop Nulls, Replace Infs)"]
        Cleaner --> Stripper["Identifier Stripper (Drop IP, Port, Time, FlowID)"]
        Stripper --> CollinearFilter["Collinearity Filter (|r| > 0.98 dropped)"]
        CollinearFilter --> Scaler["Median Imputer + RobustScaler"]
        Scaler --> Splitter["Stratified Train/Test Split (80/20)"]
    end

    subgraph Modeling["3. Dual-Engine AI Detection"]
        Splitter --> Supervised["Supervised Classifiers (XGBoost / RF / LogReg)"]
        Splitter --> Unsupervised["Unsupervised Anomaly Detector (Isolation Forest)"]
    end

    subgraph Intelligence["4. Explainability & CTI Engine"]
        Supervised --> SHAP["SHAP TreeExplainer (Local & Global)"]
        Unsupervised --> RiskEngine["Dynamic Multi-Factor Risk Engine (0-100)"]
        SHAP --> RiskEngine
        CTI["Threat Intelligence Feeds (AbuseIPDB / VT / Local IOCs)"] --> RiskEngine
    end

    subgraph Presentation["5. Deployment & Operations"]
        RiskEngine --> DB[("SQLAlchemy Database (SQLite / PostgreSQL)")]
        RiskEngine --> API["FastAPI REST Backend (Port 8000)"]
        API --> Dashboard["Streamlit SOC Wallboard (Port 8501)"]
        DB --> Dashboard
    end
```

---

## 2. Ingestion & Anti-Leakage Preprocessing Flow

The preprocessing pipeline prevents shortcut learning and memorization of specific endpoints:

```mermaid
flowchart LR
    A["Raw Capture CSV (85 columns)"] --> B["Strip Whitespace & Repair Labels"]
    B --> C["Filter Rows with Empty Labels"]
    C --> D["Drop Constant Columns (8 features, var=0)"]
    D --> E["Drop Known Duplicate Columns (Fwd Header Length.1)"]
    E --> F["Strip Endpoints (Source/Dest IP, Flow ID, Timestamp)"]
    F --> G["Prune Extreme Collinear Pairs (|r| > 0.98)"]
    G --> H["Impute Missing with Train Median"]
    H --> I["Scale with Train RobustScaler (5th-95th percentile)"]
    I --> J["Model-Ready 48 Feature Vector"]
```

---

## 3. Dual-Engine Detection & Multi-Factor Risk Assessment

Argus NIDS pairs supervised multi-class attack classification with unsupervised anomaly detection and contextual enrichment:

```mermaid
flowchart TD
    Flow["Incoming Network Flow Features"] --> Classifier["Multiclass XGBoost Classifier"]
    Flow --> Anomaly["Isolation Forest Anomaly Detector"]
    Flow --> ExtMetadata["Network Context (Dest Port, Source IP)"]

    Classifier -->|Class & Probability P| RiskScorer["Multi-Factor Dynamic Risk Scorer"]
    Anomaly -->|Outlier Flag & Anomaly Score| RiskScorer
    ExtMetadata -->|Port Criticality: 22, 445, 80| RiskScorer
    ExtMetadata -->|CTI Reputation Lookup| CTIModule["CTI Engine (AbuseIPDB / IOCs)"]
    CTIModule -->|Reputation Score 0-100| RiskScorer

    RiskScorer --> Decision{"Final Risk Score R in [0, 100]"}
    Decision -->|< 25| Low["LOW: Routine Benign Traffic (Monitor)"]
    Decision -->|25 - 54| Med["MEDIUM: Minor Anomaly / Scan (Triage)"]
    Decision -->|55 - 79| High["HIGH: Confirmed Attack / Critical Port (Rate Limit)"]
    Decision -->|>= 80| Crit["CRITICAL: Severe Exploit / C2 Blacklisted (Block IP)"]
```

---

## 4. Threat Intelligence (CTI) & Caching Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor System as SOC / Detection API
    participant CTI as CTI Client
    participant Cache as In-Memory / SQLite Cache
    participant Ext as AbuseIPDB / VirusTotal API
    participant Local as Local Curated IOC DB

    System->>CTI: lookup_ip(ip_address)
    CTI->>CTI: Check if IP is RFC 1918 Private/Loopback?
    alt Is Private IP
        CTI-->>System: Return Private IP Report (Score: 0, No External Query)
    else Is Public IP
        CTI->>Cache: Query cache for IP
        alt Cache Hit (< 24 hrs old)
            Cache-->>System: Return Cached CTI Report
        else Cache Miss
            alt API Key Available
                CTI->>Ext: GET /check (ipAddress)
                Ext-->>CTI: Response (AbuseConfidence, Reports, Country)
                CTI->>Cache: Store Report in Cache
                CTI-->>System: Return Live CTI Report
            else No API Key (Offline Fallback)
                CTI->>Local: Match against Curated IOC Database
                Local-->>CTI: IOC Match (Score, C2 Type, Tags) or Clean
                CTI->>Cache: Store Report in Cache
                CTI-->>System: Return Local Fallback Report (Explicitly Disclosed)
            end
        end
    end
```

---

## 5. SOC Analyst Alert Triage Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NEW: High/Critical Event Triggered
    NEW --> INVESTIGATING: SOC Analyst Claims Incident
    INVESTIGATING --> RESOLVED: Threat Contained & IP Blocked
    INVESTIGATING --> FALSE_POSITIVE: Validated as Authorized Enterprise Traffic
    RESOLVED --> [*]
    FALSE_POSITIVE --> [*]
```

