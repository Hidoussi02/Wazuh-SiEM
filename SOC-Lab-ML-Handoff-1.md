# SOC Lab ML Layer — Handoff for the Next Chat

> Read this fully before answering. It records everything agreed so far, the reasoning behind each decision, what has been verified, and what remains. Do not re-open decisions marked **FIXED**. Do not ask the user to paste passwords.

---

## 0. How to work with this user (standing preferences)

- Give **full step-by-step guidance from scratch**: assume nothing is installed; give exact commands and how to verify each step before moving on.
- Keep explanations **clear, simple, to the point**. No long dense answers.
- Use **PowerShell** for all commands.
- All work lives on the **D drive**, in a folder named after the project: `D:\SOC-Lab-Detection`.
- The user may need to explain things to a teacher: when asked, give plain-language explanations they can say out loud.
- The user does not want to bother the teammate who owns Wazuh (he is very busy). Bundle any request to him into **one** message, and only when truly needed.

---

## 1. The project

A security-lab detection pipeline on VMware VMs:

1. **Kali Linux VM**: attacker. Runs scripted attacks against the Windows client only.
2. **Windows 10 VM** (agent name `WIN10-CLIENT`, agent id `001`): victim and the **only monitored machine**. Its Wazuh agent sends logs to the SIEM.
3. **Ubuntu VM**: Wazuh SIEM (manager + indexer/OpenSearch + its own dashboard, which is **not** the final UI).
4. **ML layer** (the user's job): Python (pandas, scikit-learn). Reads alerts from Wazuh, engineers features, flags important events.
5. **Custom dashboard** (the user's job): Streamlit. Shows only the ML layer's output.

**Out of scope for now:** Kali attack scripts, Wazuh's built-in dashboard, a future Red Hat automated-response VM, a future LLM/n8n notification workflow. An old Active Directory VM idea was dropped.

## 2. Team split

- **Teammates own everything through Wazuh** (Ubuntu VM, Wazuh install, VMware networking, alert generation). All working.
- **The user owns everything after that**: extraction from Wazuh, feature engineering, ML models, dashboard.
- **Delivery plan:** the user builds and prepares the ML part on their own PC, then gives the finished folder to a teammate, whose PC holds the rest of the work. The teammate merges everything. So the code must be **portable** (see section 9).

## 3. FIXED tools

VMware, Wazuh (on Ubuntu), Python / pandas / scikit-learn, Streamlit.

---

## 4. Decisions and justification

| Decision | Reason |
|---|---|
| **Extraction via Wazuh indexer REST API** (port 9200) | No SSH or file access needed on the teammate-owned Ubuntu box. Same kind of request the teammate already ran with `curl`. |
| **Near-live micro-batch polling, every 20-30 s** | Looks live in a demo; is just a repeated "alerts newer than timestamp X" query, so simple to build and debug. Expected delay attack-to-dashboard: about 30-60 s. |
| **SQLite (WAL mode) as ML-to-dashboard handoff** | Zero setup; pipeline can write while the dashboard reads. Not CSV, not FastAPI. |
| **Primary model: Isolation Forest** (live) | Unsupervised, needs no attack labels, fast, catches unseen attack types. Outperformed One-Class SVM in published comparisons. |
| **Secondary model: Random Forest** (offline comparison only, never deployed live) | Shows what labels add, validates the features, and justifies not deploying supervised models. Supervised results are fragile across datasets. |
| **Train entirely on a public dataset: Windows-APT 2025** | The user decided NOT to collect their own baseline. Closest public match to this stack (Wazuh + Sysmon on Windows 10). CC BY 4.0. |
| **Run everything on the user's PC (in `D:\SOC-Lab-Detection`)** | Dataset is small (about 100K rows). No extra VM needed. Colab/Kaggle is fine for training only, since it cannot reach the private lab network for live scoring. |

### Decisions refined in this chat (these correct the earlier handoff)

1. **Do not rely on MITRE-tag presence as a "malicious" signal.** The dataset paper says normal logs can also carry MITRE tags. Technique and rule *frequency* is acceptable; tag *presence* is not a clean signal.
2. **Train Isolation Forest on the "General" (normal) rows only**, not on everything. The dataset is about 62% malicious, which breaks Isolation Forest's assumption that anomalies are rare. Test it on the malicious rows. Set the alert threshold from normal data (e.g. flag scores above the 99th percentile of normal scores) instead of guessing a contamination value.
3. **Filter live queries to the Windows agent only** (`agent.id: 001`). The Ubuntu manager (`agent.id 000`) also writes alerts into the same index (sudo/PAM failures, rootcheck "trojaned file"); these are out of distribution and must not be scored.
4. **Use language-neutral features only.** The live Windows VM is **French** (event messages are in French); the dataset is English. Do not use text from `full_log` or `data.win.system.message`. Do not use hostnames or computer names as features.
5. **Unseen rules must not crash the pipeline.** Rules or descriptions never seen in the dataset are treated as "rare".
6. **Evaluate with a scenario/file split, not a random split**, to avoid leakage between near-duplicate rows. Watch for label-proxy features (check feature importances).

---

## 5. The dataset: Windows-APT 2025

- Paper: https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/
- Download (manual, Mendeley blocks bots), **use v3**: https://data.mendeley.com/datasets/b8fmtzvpy8/3  (DOI: https://doi.org/10.17632/b8fmtzvpy8.3)
- Combined CSV: **102,011 rows**, about 242 MB. Package includes `checksums.sha256`, a README, example scripts.
- Counts reported: **38,393 "General"** and **63,620 "Malicious"**. **The label column name is NOT confirmed**; it must be found by opening the real file.
- Collected with **Wazuh 4.5.2**, Sysmon (sysmon-modular config), custom Wazuh rules, **3 Windows 10 agents**, Oct-Dec 2024, MITRE Caldera post-compromise emulation.
- Reported gaps: Credential Access and Exfiltration produced no logged events.
- CSV columns are export-style names (`Timestamp`, `Agent-Name`, `Full-log`, `Rule Description`, MITRE tactic/ID/technique, `Source-OS`; the paper's example row also shows `EventID`, `Image`, `TargetFilename`). **No Wazuh `rule.level` and no rule ID.** Build rule frequency from the rule description.

### Field mapping, dataset to live Wazuh

| Dataset column | Live Wazuh field |
|---|---|
| Timestamp | `@timestamp` / `timestamp` (UTC) |
| Agent-Name | `agent.name` |
| Full-log | `full_log` (do not use as text feature) |
| Rule Description | `rule.description` |
| MITRE tactic / ID / technique | `rule.mitre.tactic` / `.id` / `.technique` |
| EventID | `data.win.system.eventID` |
| Paths, hashes, IPs | `data.win.eventdata.*` |

### Download steps (PowerShell)

```powershell
New-Item -ItemType Directory -Force -Path "D:\SOC-Lab-Detection\data\raw","D:\SOC-Lab-Detection\data\processed","D:\SOC-Lab-Detection\models","D:\SOC-Lab-Detection\docs"
Test-Path "D:\SOC-Lab-Detection\data\raw"        # expect True
```
Download All from the v3 page in the browser, save the zip into `D:\SOC-Lab-Detection\data\raw`, then:
```powershell
Get-ChildItem "D:\SOC-Lab-Detection\data\raw\*.zip" | ForEach-Object { Expand-Archive $_.FullName -DestinationPath "D:\SOC-Lab-Detection\data\raw" -Force }
Get-ChildItem "D:\SOC-Lab-Detection\data\raw" -Recurse -File | Select-Object FullName, @{n="MB";e={[math]::Round($_.Length/1MB,1)}}
Get-Content (Get-ChildItem "D:\SOC-Lab-Detection\data\raw" -Recurse -Filter checksums.sha256).FullName
Get-FileHash (Get-ChildItem "D:\SOC-Lab-Detection\data\raw" -Recurse -Filter "Combine*.csv").FullName -Algorithm SHA256
$f = (Get-ChildItem "D:\SOC-Lab-Detection\data\raw" -Recurse -Filter "Combine*.csv").FullName
Get-Content $f -TotalCount 1
Import-Csv $f | Select-Object -First 3 | Format-List
```
Verify: about 19 CSVs, combined file about 240 MB, hash matches `checksums.sha256`. **The user should send the header line and the 3 sample rows**, which are needed to find the label column. If no obvious label column exists, check the package's manifest/validation files for scenario time windows to derive labels.

---

## 6. What was verified on the live Wazuh (from the teammate's output)

- Wazuh **v4.9.2** (dataset used 4.5.2; same 4.x index format, acceptable).
- `log_alert_level` = **3** (low-level benign alerts are stored; good).
- Index pattern: `wazuh-alerts-4.x-*`, 15 shards.
- At check time: about **4,924** alerts total, **513** from Sysmon, **727** with MITRE tags (about 15%).
- Windows alert sample confirms nested fields: `data.win.system.eventID`, `providerName`, `data.win.eventdata.*`, `rule.id`, `rule.level`, `rule.description`, `decoder.name = windows_eventchannel`, `agent.ip 192.168.61.138`.
- **Not yet seen:** an actual Sysmon alert sample, the Sysmon config in use, and whether custom Wazuh rules were added.
- **Security:** the teammate's output contained the real indexer admin password in plain text. The user should tell him to change it. The pipeline should use a **read-only** account, with the password in an environment variable, never in code or in the handoff package. Never store or repeat that password.

### Decision on contacting the teammate

Not needed now. The pipeline will include a **first-run self-check** that prints which expected fields are missing (replacing the open Sysmon questions). The one later request (bundled in a single message): Ubuntu VM IP, a read-only indexer account, confirmation that port 9200 is reachable from the PC running the pipeline, and a password change. Optional extra if the self-check fails: a Sysmon alert sample and the `sysmon64 -c` output from the Windows VM.

---

## 7. How real-time collection works

```
Windows VM -> Wazuh agent -> Wazuh server (Ubuntu) -> Wazuh indexer
                                                         ^
                        pipeline polls every ~30 s: "agent.id 001 alerts newer than last timestamp"
                                                         v
                         features -> model -> SQLite -> Streamlit dashboard
```

Details: query `https://<ubuntu-ip>:9200/wazuh-alerts-*/_search`, filter `agent.id: 001` and `@timestamp` after the last seen value, page through results during bursts, skip already-stored `_id`s, re-query slightly before the last timestamp (indexer can show alerts late), keep UTC. The machine running the pipeline must reach `<ubuntu-ip>:9200` (test by opening that URL in a browser: a login prompt means it works).

---

## 8. The models

### Isolation Forest (live detector)
- **Idea:** many random trees with random splits; unusual events are isolated in few splits (short path = high anomaly score).
- **Train:** on "General" (normal) rows only. Trees 100-300; threshold from the normal-score distribution.
- **Test:** hold out normal rows; score all malicious rows. Metrics: ROC-AUC, PR-AUC, precision/recall at a fixed alert budget (e.g. top 1% flagged), detection rate per MITRE technique.
- **Pros/cons:** catches unseen attacks; produces some false positives.

### Random Forest (offline comparison only)
- **Idea:** many decision trees voting; needs labels.
- **Train:** all rows with labels, `class_weight` for imbalance.
- **Test:** hold out whole scenarios. Metrics: precision, recall, F1, confusion matrix, feature importances (to detect leakage).
- **Pros/cons:** accurate on known attack types; brittle on different data.

### Why two
1. Shows what labels add (a real result for the report).
2. Validates the features: if Random Forest cannot separate the classes, neither detector will.
3. Justifies not deploying supervised models using the user's own numbers.

### Alternatives (considered, not the focus)
Local Outlier Factor (novelty mode; slower, sensitive to neighbor count), One-Class SVM (slower, weaker in cited studies), XGBoost / Logistic Regression (supervised baselines; used in the minhaj-naqvi repo), Autoencoder (skipped: needs deep-learning libraries outside the fixed stack and more tuning).

### Honest caveats
- Isolation Forest may not separate classes well; if so, fix the features, not the model.
- The dataset attacks are host-level Caldera emulations; the user's attacks come from Kali (scans, brute force), so there is domain shift.
- **The final verdict is the user's own Kali attack test**, with attack time windows labeled by time. No accuracy numbers exist yet; none should be claimed until the evaluation is run.

---

## 9. Portability requirements (the folder will be handed to a teammate's PC)

- **No hardcoded paths** (nothing may mention `D:\SOC-Lab-Detection`); use paths relative to the project folder.
- **One config file / environment variables** for indexer host, port, username, index pattern, polling interval, SQLite location. **No password in the package.**
- **Pin exact versions** in `requirements.txt` and note the Python version in the README. Save library versions inside the model file's metadata and check them at startup (a `model.joblib` can break across scikit-learn versions).
- Ship: `README.md`, `requirements.txt`, config template, `models\model.joblib` (with feature list and version info), `src\` (wazuh_client, features, pipeline, dashboard). **Do not ship the 242 MB dataset.**
- Provide a `check_setup` script that tests, in order: Python/package versions, model loads, indexer reachable and login works, Windows agent alerts found, expected fields present.
- Provide one command or `.ps1` script that starts the pipeline and the dashboard together.
- Open question for the teammate (can be answered by the self-check instead): is Python installed on his PC, and which version?

---

## 10. Files from the earlier chat (not visible in this chat)

An earlier chat produced: `requirements.txt`, `wazuh_client.py`, `features.py`, `load_windows_apt.py`, `train_from_public_dataset.py`, `train_isolation_forest.py` (superseded), `pipeline.py`, `dashboard.py`. **None of these were reviewed in this chat.** Ask the user to upload them, or regenerate them, and update them for the refinements in section 4 (MITRE presence, normal-only training, agent filter, language-neutral features, unseen rules, portability, relative paths).

---

## 11. Status and next steps

**Done:** architecture and tool decisions; dataset research and compatibility review; live Wazuh compatibility review; model design and evaluation plan; portability plan.

**Not done:** dataset downloaded; label column found; code reviewed or updated; model trained; live pipeline connected; dashboard tested; Kali attack test.

**Next steps, in order:**
1. User downloads the dataset (section 5) and sends the CSV header line and 3 sample rows.
2. Identify the label column; fix `load_windows_apt.py` and `features.py` (shared by training and live scoring).
3. Train Isolation Forest (normal-only) and Random Forest (scenario split); report metrics.
4. Build the portable package (config, pinned requirements, `check_setup`, launcher script).
5. Connect the live pipeline to the indexer (after the single bundled request to the teammate), then the dashboard.
6. Final test with the Kali attacks.

---

## 12. Sources

- Dataset paper: https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/
- Dataset (v3): https://data.mendeley.com/datasets/b8fmtzvpy8/3  |  DOI https://doi.org/10.17632/b8fmtzvpy8.3
- Isolation Forest original paper (Liu, Ting, Zhou, 2008): https://doi.org/10.1109/ICDM.2008.17
- scikit-learn outlier detection guide: https://scikit-learn.org/stable/modules/outlier_detection.html
- scikit-learn `IsolationForest`: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- Isolation Forest vs One-Class SVM comparisons (from the earlier research, not re-opened in this chat): https://arxiv.org/html/2511.21842v1 , https://arxiv.org/pdf/1609.06676
- Wazuh + Sysmon + supervised ML prior work (RF F1 0.967, XGBoost 0.980, LR 0.903, 85% alert reduction): https://github.com/minhaj-naqvi/ML-SOC-Alert_Triage
- Fragility of supervised results (88% to 58%; about 95-99% to under 40% cross-dataset): https://arxiv.org/pdf/2208.12729 , https://arxiv.org/pdf/2605.04407
- Similar projects: `priyanshu-agg/wazuh-ml-threat-detection` (Wazuh + Isolation Forest + Streamlit), `iamishtiq/AI-Based-Anomaly-Detection-Wazuh` (OpenSearch anomaly-detection plugin)
- Wazuh indexer docs: https://documentation.wazuh.com/4.10/getting-started/components/wazuh-indexer.html

---

## 13. Plain-language summary for the teacher

"The Windows machine's Wazuh agent sends logs to Wazuh on Ubuntu, which stores alerts in its indexer. My program asks the indexer for new alerts every 30 seconds, turns each into numeric features that do not depend on language or machine names, and scores it with Isolation Forest, an anomaly detector trained on normal activity from a public Wazuh-and-Sysmon dataset. Flagged events and scores go into a SQLite database, and a Streamlit dashboard shows only the flagged events. A Random Forest is trained only to compare what labels add. I evaluate with a scenario split and a fixed alert budget, and the final test is our own Kali attacks. Limits: the public attacks differ from ours, and I have not run the evaluation yet."
