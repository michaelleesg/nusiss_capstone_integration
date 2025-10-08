# 📘 Capstone Report Collaboration Guide

## 1. Install LaTeX (one-time setup)
Each teammate needs a LaTeX distribution and editor:

- **Windows (recommended):**
  - Install [MiKTeX](https://miktex.org/download).
  - During installation, allow it to install missing packages on-the-fly.
  - Also install [Perl](https://strawberryperl.com/) if not already present (needed by `latexmk`).

- **macOS:**
  - Install [MacTeX](https://tug.org/mactex/).

- **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt update
  sudo apt install texlive-full
  ```

- **Editor options:**
  - VS Code with LaTeX Workshop extension, TeXworks, or Overleaf (online).

---

## 2. Build Instructions
After installing LaTeX:

1. Place all provided `.tex`, `.bib`, and `.bat` files in a single folder.
2. On Windows, double-click **`build_report.bat`** (this script runs `pdflatex` + `bibtex` and produces `main.pdf`).
3. On macOS/Linux, run manually in terminal:
   ```bash
   pdflatex main.tex
   bibtex main
   pdflatex main.tex
   pdflatex main.tex
   ```

The output will be **`main.pdf`** in the same folder.

---

## 3. File Roles
- `main.tex` → master file that pulls everything together (intro, abstract, agents, references).
- `CyberSage.bib` → reference database (citations used in each section).
- `agentA_ingest.tex` → Agent A: Ingest (pipeline normalization, feed adapters, schema).
- `agentB_ner.tex` → Agent B: Named Entity Recognition (NER models and experiments).
- `agentC_risk_triage.tex` → Agent C: Risk & Triage (KEV/EPSS scoring, prioritization).
- `agentD_assurance_explain.tex` → Agent D: Assurance & Explainability (traceability, dashboards).
- `build_report.bat` → Windows helper script for fast compilation.

---

## 4. Team Editing Tasks
Each teammate should **fill in/revise content only in their agent’s `.tex` file**:

- **Agent A (Ingest):** Explain how OSINT feeds are normalized, adapters built, JSON schemas, deduplication logic, and rate-limiting.
- **Agent B (NER):** Document model selection (BERT, RoBERTa, SecBERT, etc.), experiments, evaluation metrics.
- **Agent C (Risk & Triage):** Describe KEV/EPSS scoring, organizational asset mapping, triage pipeline, prioritization logic.
- **Agent D (Assurance & Explainability):** Discuss evidence traceability, citations, dashboards, human-in-the-loop validation.

📌 **Note:** Keep section headers intact (they’re already linked in `main.tex`).

---

## 5. Referencing
- To cite a paper or dataset:  
  ```latex
  As shown in \cite{devlin2018bert}, transformer models...
  ```
- Check **`CyberSage.bib`** for available references.  
- If you add a new citation, add the BibTeX entry to **`CyberSage.bib`**.

---

✅ With this setup, each team member edits only their `.tex` file → then run the build script → unified `main.pdf`.
