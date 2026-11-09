# Argus NIDS: Comprehensive MSc Viva Examination Guide (45 Questions & Model Answers)

This preparation guide prepares postgraduate researchers and candidates for the academic viva voce examination, defense panels, and technical peer reviews.

---

## Category 1: Problem Formulation, Threat Landscape & NIDS Taxonomy

### Q1: What is the core difference between a Network Intrusion Detection System (NIDS) and a Network Intrusion Prevention System (NIPS)?
**Answer:** A NIDS is a passive monitoring mechanism placed out-of-band (via a TAP or SPAN port) that inspects packet traffic, raises alerts, and produces forensic logs without disrupting traffic flow. A NIPS is deployed in-line, actively inspecting packet sequences and possessing the authority to drop packets, terminate TCP connections (via TCP RST injection), or reconfigure firewall rules in real-time. Argus NIDS is designed as an intelligent detection and threat intelligence platform that feeds actionable recommendations to active response systems.

### Q2: Why do traditional signature-based detection systems fail against modern cyber attacks?
**Answer:** Signature-based systems (e.g. Snort, Suricata) match packets against known byte strings or regular expressions. They fail because:
1. **Zero-Day Attacks:** Unknown vulnerabilities lack published signatures.
2. **Polymorphic / Metamorphic Malware:** Attackers mutate payload encodings, encryption, and packing.
3. **Behavioral Attacks:** Low-and-slow brute-force, slowloris DoS, and advanced persistent threats (APTs) mimic valid protocol semantics and do not contain recognizable malicious signatures in single packets.

### Q3: What is the distinction between packet-level analysis and flow-level analysis?
**Answer:** Packet-level analysis (deep packet inspection or DPI) examines the raw payload and headers of individual Ethernet frames. It is computationally expensive and blind to encrypted payloads (TLS/HTTPS). Flow-level analysis aggregates packets into bidirectional IP network sessions (5-tuple: Source IP, Source Port, Dest IP, Dest Port, Protocol) and extracts statistical features (packet inter-arrival times, byte rates, duration, TCP flag distributions), allowing detection of attacks even over encrypted channels without inspecting private payload contents.

### Q4: Why did your project utilize the CICIDS2017 dataset rather than KDD Cup 99 or NSL-KDD?
**Answer:** KDD99 and NSL-KDD are based on synthetic traffic captured in 1998 by DARPA. They suffer from severe obsolete attack distributions (smurf, neptune), outdated operating system artifacts, lack of contemporary attack paradigms (DDoS, modern botnets, web exploits), and unrepresentative network topology. CICIDS2017 provides contemporary benign background traffic alongside realistic multi-stage attack scenarios generated using modern attack toolkits.

### Q5: What are the primary attack families present in CICIDS2017?
**Answer:** CICIDS2017 incorporates 7 attack categories across 5 days:
1. **Brute Force:** FTP-Patator and SSH-Patator (Tuesday).
2. **Denial of Service (DoS):** DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, Heartbleed (Wednesday).
3. **Web Attacks:** SQL Injection, Cross-Site Scripting (XSS), Brute Force (Thursday AM).
4. **Infiltration & Port Scanning:** Internal compromise via vulnerable Adobe Acrobat followed by Nmap reconnaissance (Thursday PM & Friday PM).
5. **Distributed Denial of Service (DDoS):** High-rate LOIC flooding (Friday PM).
6. **Botnet Activity:** Ares Botnet command-and-control communication (Friday AM).

### Q6: What is the difference between misuse detection and anomaly detection?
**Answer:** Misuse (supervised) detection models train on labeled data of known attacks to identify known malicious signatures or patterns. Anomaly (unsupervised) detection models establish a statistical or geometric baseline profile of normal benign network traffic, flagging any significant deviation as a potential intrusion. Argus NIDS unifies both: supervised XGBoost classifies known attack families, while unsupervised Isolation Forest detects zero-day anomalies.

---

## Category 2: Dataset Realities, Ingestion & Data Quality Audits

### Q7: What data quality defects did your exploratory data analysis discover in CICIDS2017?
**Answer:** Our empirical audit of the 3,119,345 raw flows uncovered several critical issues:
1. **Corrupted Label Encoding:** Web Attack labels contained non-ASCII byte `0x96` (Latin-1 en-dash), breaking UTF-8 decoders.
2. **Missing & Infinite Values:** 289,960 rows had missing values, and 2,867 rows contained `+Inf` or `-Inf` in `Flow Bytes/s` and `Flow Packets/s` caused by division by zero during zero-duration flow calculations.
3. **Integer Overflows:** 13 features (e.g. `Flow Duration`, `Init_Win_bytes_forward`, `Header Length`) contained negative values due to 32-bit signed integer overflows in CICFlowMeter.
4. **Constant Features:** 8 features had zero variance across all 3.1 million flows.
5. **Severe Imbalance:** Max-to-min class ratio exceeded 206,645:1 (Heartbleed had only 11 flows; Benign had 2.27M).

### Q8: Which 8 features had zero variance, and why were they dropped?
**Answer:** The features were: `Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`, `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, and `Bwd Avg Bulk Rate`. They were completely constant (all zeros) across all 3,119,345 flows. Retaining zero-variance features adds memory overhead, slows training, and risks division-by-zero during standardization without providing any discriminative power.

### Q9: Why do negative values appear in `Flow Duration` and `Init_Win_bytes_forward`?
**Answer:** CICFlowMeter was implemented in Java using 32-bit signed integers (`int`) for microsecond timestamp subtraction and packet header parsing. When flow durations exceeded $2^{31}-1$ microseconds (~35.7 minutes) or window scale calculations overflowed, the values wrapped around into negative numbers.

### Q10: Why did Thursday morning have 288,602 rows with NaN labels?
**Answer:** In the raw capture file `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, trailing corrupted records or incomplete packet flow extractions resulted in empty label fields. In our pipeline, `clean_dataframe()` explicitly filters out rows where `Label` is NaN or empty before modeling.

### Q11: What is the significance of the duplicate feature vector audit you conducted?
**Answer:** We conducted a cryptographic hash audit across feature vectors and identified 597,449 duplicate rows (19.15% of the dataset) and 697 conflicting label groups (where identical flow feature vectors carry different labels, e.g. one labeled BENIGN and another labeled DoS Hulk). This reflects inherent label noise in network flow capture. Acknowledging this prevents unrealistic claims of 100% accuracy.

### Q12: How many total files and flows exist in the full CICIDS2017 dataset?
**Answer:** Exactly 8 CSV files comprising 3,119,345 total flow lines. When empty label rows (288,602) are removed, 2,830,743 valid labeled network flows remain (2,273,097 Benign and 846,248 Malicious).

### Q13: Why did you record the SHA-256 cryptographic hashes of the raw CSVs?
**Answer:** In scientific research, reproducibility requires proving that experimental artifacts were generated from verified, untampered source data. The SHA-256 manifest recorded in `outputs/evaluation/dataset_manifest.csv` allows any peer reviewer or academic examiner to verify the integrity of our dataset files.

---

## Category 3: Anti-Leakage Preprocessing & Feature Engineering

### Q14: What is data leakage in network intrusion detection, and why is it dangerous?
**Answer:** Data leakage occurs when information from outside the training partition (or information that will not be available or valid during live deployment) is used to create the model. In NIDS, the most severe leakage is including Source IP, Destination IP, or Flow ID. If included, models achieve 99.99% accuracy in tests simply by memorizing that `172.16.0.1` is the attacker. When deployed in a real environment where attacker IPs differ, the model's accuracy collapses to near zero.

### Q15: How did your pipeline prevent endpoint data leakage?
**Answer:** Our `get_feature_columns()` function strictly strips `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Timestamp`, `Protocol`, and `source_file` before creating the feature matrix `X`. The model is forced to learn intrinsic protocol dynamics (inter-arrival time distributions, packet size variances, TCP flag interactions) rather than memorizing host identities.

### Q16: How did you ensure transformation statistics did not leak from the test set into the train set?
**Answer:** We strictly fitted our `SimpleImputer` (median imputation) and `RobustScaler` (interquartile range scaling) **exclusively on the training split** (`X_train`). The fitted transformation parameters were then applied to `X_test` using the serialized pipeline artifact without recalculating statistics.

### Q17: Why did you select `RobustScaler` instead of `StandardScaler` or `MinMaxScaler`?
**Answer:** Network traffic metrics exhibit extreme heavy-tailed distributions and severe outliers (e.g. packet bursts of $10^7$ bytes vs typical 64-byte packets). `StandardScaler` uses the mean and variance, which are drastically skewed by extreme outliers. `MinMaxScaler` compresses normal traffic into an infinitesimal range near zero. `RobustScaler` scales data using the median and the interquartile/quantile range (5th to 95th percentile), making it immune to extreme packet bursts.

### Q18: How did you handle collinearity, and what was the threshold used?
**Answer:** We computed the pairwise absolute Pearson correlation matrix on `X_train`. Where two features had $|r| > 0.98$, the redundant feature was systematically pruned. This dropped 21 redundant features (including `Fwd Header Length.1`, duplicate packet lengths, and subflow averages), reducing dimensionality from 69 to 48 robust attributes without sacrificing predictive signal.

### Q19: Why was `Destination Port` retained while `Source Port` was dropped?
**Answer:** Source ports are ephemeral (randomly chosen by client OS between 1024 and 65535 for each connection) and offer no consistent predictive meaning. In contrast, `Destination Port` represents the targeted service (Port 80/HTTP, Port 443/HTTPS, Port 22/SSH, Port 21/FTP). Attacks such as SSH brute-forcing or Port Scanning inherently exhibit strong statistical relationships with specific destination ports.

### Q20: Explain your balanced stratified sampling strategy.
**Answer:** Randomly downsampling a dataset with a 206,645:1 imbalance would completely extinguish minority classes (Heartbleed with 11 samples and Infiltration with 36 samples). Our `sample_balanced_stratified` algorithm retains **100% of all instances** in rare classes (<5,000 samples), while proportionally sampling majority classes (Benign, DoS Hulk, PortScan) to create a clean, statistically representative 150,000-flow dataset for training and fast SHAP computations.

---

## Category 4: Machine Learning & Anomaly Detection Theory

### Q21: Explain the mathematical intuition behind Random Forests.
**Answer:** Random Forest is an ensemble bagging (Bootstrap Aggregating) algorithm. It builds $B$ deep decision trees, each trained on a bootstrap sample of the training data. At each node split, only a random subset $m \approx \sqrt{p}$ of features is considered. Predictions are made via majority voting:
$$\hat{y} = \text{mode}\left\{ h_b(x) \right\}_{b=1}^B$$
Bagging reduces the model's variance without increasing bias, making it robust against noise and overfitting.

### Q22: What is Gradient Boosting, and how does XGBoost differ from standard Random Forests?
**Answer:** While Random Forest trains trees independently in parallel, Gradient Boosting trains trees sequentially. Each new tree fits to the pseudo-residuals (negative gradient of the loss function) of the existing ensemble:
$$\hat{y}_i^{(t)} = \hat{y}_i^{(t-1)} + \eta f_t(x_i)$$
XGBoost enhances this with:
1. **Second-order Taylor expansion** of the loss function (using both gradients $g_i$ and Hessians $h_i$).
2. **Explicit regularization** ($\Omega(f) = \gamma T + \frac{1}{2}\lambda \sum w_j^2$) penalizing tree complexity and leaf weights.
3. **Exact and weighted quantile sketch** for optimal split finding.

### Q23: Why did you include Logistic Regression as a baseline?
**Answer:** In scientific machine learning research, complex non-linear ensemble models (RF, XGBoost) must be justified against a simple, interpretable linear baseline. Logistic Regression establishes whether linear hyperplanes can separate attacks from normal traffic. Our results showed Logistic Regression attained only 36.65% Multiclass Macro-F1, formally proving that network intrusion manifolds are highly non-linear.

### Q24: How does Isolation Forest detect anomalies without training labels?
**Answer:** Isolation Forest isolates anomalies instead of profiling normal points. It constructs an ensemble of Isolation Trees (iTrees) by randomly selecting a feature and randomly selecting a split value between the feature's minimum and maximum. Because anomalies are "few and different", they require significantly fewer random partitions to be isolated (shorter path lengths from root to leaf). The anomaly score $s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$ approaches 1 when the average path length $E(h(x))$ is short.

### Q25: Why train Isolation Forest exclusively on Benign traffic?
**Answer:** Training the Isolation Forest exclusively on Benign traffic models the normal baseline behavior of enterprise communication. Any incoming packet with unusual feature combinations (abnormal packet rates, rare window sizes, unexpected port combinations) exhibits shorter path lengths, enabling detection of novel zero-day exploits without requiring prior exposure to that attack class.

### Q26: What is the time and space complexity of XGBoost inference?
**Answer:** For an ensemble of $T$ trees with maximum depth $D$, predicting a single sample requires traversing at most $D$ decisions per tree. The inference time complexity is $O(T \times D)$, independent of the training dataset size $N$. With $T=120$ and $D=6$, inference takes less than 0.5 milliseconds per flow.

### Q27: How did you address class imbalance during training in XGBoost and Random Forest?
**Answer:** In Random Forest, we used `class_weight='balanced_subsample'`, which adjusts weights inversely proportional to class frequencies for each bootstrap sample. In XGBoost, sample weights $w_i = \frac{N}{K \cdot N_k}$ were passed during training, heavily penalizing classification errors on minority attack classes.

### Q28: What is the trade-off between tree depth and generalization?
**Answer:** Increasing tree depth allows trees to capture complex higher-order feature interactions, but excessive depth ($D > 18$) causes the model to memorize sample-specific noise, inflating variance and failing on unseen traffic. We constrained XGBoost to depth 6-7 and Random Forest to depth 16 with minimum leaf samples $\ge 2$, ensuring robust regularization.

---

## Category 5: Evaluation Metrics, Class Imbalance & Diagnostics

### Q29: Why is standard Accuracy a deceptive metric in Network Intrusion Detection?
**Answer:** Due to class imbalance. In a dataset where 95% of traffic is Benign, a trivial dummy classifier that always predicts "BENIGN" achieves 95% accuracy while completely failing to detect any intrusions (0% recall on attacks). Therefore, Macro-F1, Precision-Recall, False Positive Rate (FPR), and False Negative Rate (FNR) are mandatory.

### Q30: Define False Positive Rate (FPR) and False Negative Rate (FNR) mathematically.
**Answer:**
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} \quad (\text{Fall-out: proportion of benign flows mistakenly flagged as attacks})$$
$$\text{FNR} = \frac{\text{FN}}{\text{FN} + \text{TP}} \quad (\text{Miss rate: proportion of real attacks that slipped past undetected})$$
In an enterprise processing 10 million flows daily, an FPR of even 1% produces 100,000 false alerts, overwhelming the SOC. Argus NIDS achieves an FPR of **0.13%**.

### Q31: What is the difference between Macro-F1 and Weighted-F1?
**Answer:**
- **Macro-F1:** Computes the arithmetic mean of F1-scores across all classes equally: $\frac{1}{K}\sum_{k=1}^K F1_k$. It treats rare attacks (Infiltration with 7 test samples) with equal importance as Benign (23,683 test samples).
- **Weighted-F1:** Weights each class's F1-score by its support (sample count). Weighted-F1 is dominated by majority classes.
Achieving **95.95% Macro-F1** on multiclass XGBoost proves the model excels across both massive and rare attack categories.

### Q32: What is the Area Under the Receiver Operating Characteristic (ROC-AUC)?
**Answer:** ROC-AUC measures the two-dimensional area underneath the curve plotting True Positive Rate (Recall) against False Positive Rate across all classification thresholds from 0.0 to 1.0. It represents the probability that the classifier will rank a randomly chosen positive instance higher than a randomly chosen negative instance. Our binary XGBoost achieved **0.9999 ROC-AUC**.

### Q33: How does the One-vs-Rest (OvR) multiclass ROC-AUC calculation work?
**Answer:** In an 8-class problem, One-vs-Rest evaluates 8 separate binary problems, treating class $k$ as the positive class and all remaining 7 classes as negative. The individual AUCs are calculated and macro-averaged.

### Q34: What did your error analysis reveal regarding misclassifications?
**Answer:** Error analysis of the multiclass confusion matrix revealed that the small percentage of residual errors occurred primarily between structurally similar attack types: e.g. subtle Web Attack - XSS flows occasionally overlapping with benign HTTP GET transfers carrying query parameters, and Infiltration flows with normal payload sizes.

---

## Category 6: Explainable AI (SHAP) & Mathematical Attribution

### Q35: What are the mathematical axioms satisfied by Shapley values?
**Answer:** Shapley values are the only attribution method that uniquely satisfies four fundamental properties:
1. **Efficiency:** Attributions sum to the difference between model output and expected baseline: $\sum \phi_i = f(x) - E[f(x)]$.
2. **Symmetry:** If two features contribute equally to all possible coalitions, their Shapley values are identical.
3. **Dummy (Null Player):** A feature that does not change the model prediction for any coalition receives an attribution of zero: $\phi_i = 0$.
4. **Additivity:** When combining models, attributions can be summed: $\phi_i(f + g) = \phi_i(f) + \phi_i(g)$.

### Q36: How does TreeSHAP achieve polynomial time complexity over traditional KernelSHAP?
**Answer:** Traditional KernelSHAP requires evaluating $2^M$ feature coalitions, which is exponential and intractable for 48 features. TreeSHAP (Lundberg et al., 2020) exploits the tree structure by recursively tracking the proportion of training paths that pass through each node split. This reduces complexity from exponential $O(2^M)$ to polynomial $O(T \cdot L \cdot D^2)$ (where $T$ is trees, $L$ is leaves, $D$ is depth), enabling sub-second local explanations during live API inference.

### Q37: What were the top global features identified by SHAP across the dataset?
**Answer:**
1. `Destination Port`: Discriminates standard ports (80/443) from target attack vectors (22, 21, 8080).
2. `Init_Win_bytes_forward`: TCP window parameters distinguish browser handshakes from SYN flood attack scripts.
3. `Bwd Packet Length Min`: Identifies automated command response patterns in DoS and PortScan attacks.
4. `Average Bwd Segment Size`: Reflects response data payloads.
5. `Init_Win_bytes_backward`: Server window scaling responses.

### Q38: How does local SHAP explanation assist an operational SOC analyst?
**Answer:** When an alert triggers, an analyst cannot simply trust an opaque label saying "DDoS: 99%". The local SHAP waterfall graph reveals *why*: showing that `Bwd Packets/s = 5200` added $+0.42$ to the probability, `Init_Win_bytes_forward = 0` added $+0.31$, and `Average Packet Size = 40` added $+0.18$. The analyst can immediately verify the packet dynamics and authorize a firewall rule with confidence.

---

## Category 7: Cyber Threat Intelligence, Risk Engine & Architecture

### Q39: What is the role of Cyber Threat Intelligence (CTI) in this system?
**Answer:** Machine learning models evaluate *behavioral traffic anomalies* based on statistical flow features. CTI provides *external reputation corroboration* based on global threat feeds (AbuseIPDB, VirusTotal, AlienVault OTX). Combining behavioral ML with CTI reputation prevents both false positives (a high-volume legitimate backup server) and false negatives (an evasion attack using low packet rates originating from a known botnet C2 IP).

### Q40: How does your CTI client handle private network addresses (RFC 1918)?
**Answer:** In an enterprise LAN, internal hosts use RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Querying public CTI APIs for internal IP addresses is technically meaningless and leaks internal network topology to third-party APIs. Our `CTIClient` evaluates IP properties using the `ipaddress` module, automatically tagging private addresses with `is_private=True` and bypassing external queries.

### Q41: Explain the formula used by the Multi-Factor Risk Assessment Engine.
**Answer:**
$$\text{Risk Score } R = \min(100, \text{BaseSeverity} \times P(\text{Attack}) + \Delta_{\text{anomaly}} + \Delta_{\text{port}} + \Delta_{\text{CTI}})$$
- $\text{BaseSeverity} \times P(\text{Attack})$: Anchors the score in model confidence and attack threat level (Infiltration: 98, DDoS: 85, DoS: 70, PortScan: 45).
- $\Delta_{\text{anomaly}}$: Adds $+5$ to $+15$ points if the unsupervised Isolation Forest corroborates the event as a zero-day outlier.
- $\Delta_{\text{port}}$: Adds $+10$ points if high-risk critical enterprise ports (22/SSH, 445/SMB, 3389/RDP) are targeted.
- $\Delta_{\text{CTI}}$: Adds up to $+15$ points proportional to AbuseIPDB reputation.
This maps into 4 actionable SOC tiers: Low (<25), Medium (25-54), High (55-79), and Critical (80-100).

### Q42: What are the primary REST endpoints in your FastAPI backend?
**Answer:**
1. `GET /health`: System heartbeat, model status, database readiness.
2. `POST /predict`: Single flow inference with multiclass prediction, anomaly score, and risk assessment.
3. `POST /predict/batch`: High-throughput vectorized batch processing.
4. `POST /detect-anomalies`: Isolation Forest zero-day anomaly inspection.
5. `POST /explanations`: SHAP local feature attributions for a single flow.
6. `GET /alerts`: Filterable historical alerts from SQLAlchemy ORM.
7. `GET /statistics`: Aggregate SOC metrics, attack frequencies, and risk distributions.

---

## Category 8: Software Engineering, Reliability & Academic Ethics

### Q43: What automated software testing methodology did you implement?
**Answer:** We implemented a comprehensive pytest test suite comprising 39 automated tests covering:
- Data loader integrity and normalizations (`test_data_loading_and_quality.py`).
- Headless EDA execution and file writing (`test_eda.py`).
- Preprocessing and feature selection pipelines (`test_preprocessing.py`).
- Exact mathematical calculation of metrics including FPR and FNR (`test_models_and_evaluation.py`).
- SHAP TreeExplainer and Risk Engine boundary scores (`test_explainability_and_risk.py`).
- SQLAlchemy ORM persistence and CTI caching (`test_cti_and_database.py`).
- FastAPI REST endpoints using Starlette `TestClient` (`test_api_endpoints.py`).
All 39 tests execute in 13.8 seconds with 100% pass rate.

### Q44: What ethical guidelines governed your research and implementation?
**Answer:** In accordance with the ACM Code of Ethics and institutional research governance:
1. **No Live Attack Execution:** All experiments were conducted strictly offline using authorized public benchmark data (CICIDS2017). No unauthorized scanning, packet sniffing, or payload exploitation was directed against real external networks.
2. **GDPR Article 22 Compliance:** By integrating SHAP, automated high-risk triage decisions provide explainable feature rationales, preventing opaque automated decision-making.
3. **Scientific Integrity:** No dataset values, model metrics, or benchmark results were fabricated. All statistics derive directly from executable code outputs.

### Q45: If you had another 6 months of research funding, what would you implement next?
**Answer:**
1. **Real-Time Streaming Engine:** Integrate Apache Kafka and Apache Flink to transition from micro-batch CSV ingestion to streaming wire-speed packet capture (10 Gbps+).
2. **Cross-Dataset Domain Adaptation:** Evaluate model transferability against newer datasets (UNSW-NB15, TON_IoT) using domain adversarial neural networks (DANN).
3. **Adversarial Robustness:** Test and harden the tree ensembles against adversarial feature perturbations (e.g. packet timing jitter, dummy packet padding).

