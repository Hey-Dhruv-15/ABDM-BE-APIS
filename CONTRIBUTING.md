# Contributing to ABDM Backend APIs & Interoperability Gateway

Thank you for your interest in contributing to **ABDM Backend APIs**! We welcome contributions of all levels—whether you are fixing a bug, improving documentation, implementing a new ABDM/FHIR profile, or suggesting architectural improvements.

---

## 🌟 How Can You Contribute?

- **Report Bugs**: If you find an issue or unexpected gateway behavior, submit a [Bug Report](https://github.com/Hey-Dhruv-15/ABDM-BE-APIS/issues/new?template=bug_report.md).
- **Suggest Features**: Propose new ideas, missing ABDM Milestone features, or FHIR converters via a [Feature Request](https://github.com/Hey-Dhruv-15/ABDM-BE-APIS/issues/new?template=feature_request.md).
- **Improve Documentation**: Enhance README guides, add architecture diagrams, or improve API curl examples.
- **Submit Pull Requests**: Fix issues, add test cases, or implement roadmap items.

---

## 🚀 Development Setup

### 1. Fork & Clone
```bash
git clone https://github.com/<your-username>/ABDM-BE-APIS.git
cd ABDM-BE-APIS
```

### 2. Create a Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
```bash
cp .env.example .env
```

### 5. Run the Server Locally
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Open **`http://localhost:8000/docs`** to explore the Swagger UI.

---

## 🧪 Running Tests

Before submitting a PR, make sure all tests pass:

```bash
# Run all tests
pytest

# Run ABDM Milestone 2 tests
pytest tests/test_abdm_m2.py

# Run HIU Milestone 3 mandatory tests
pytest tests/test_abdm_hiu_m3_mandatory.py
```

---

## 🌿 Branching & Pull Request Guidelines

1. **Create a branch**:
   ```bash
   git checkout -b feature/my-new-feature
   # or
   git checkout -b fix/issue-description
   ```
2. **Follow Code Quality**:
   - Write clean, type-annotated Python code (`typing`, `Pydantic`).
   - Maintain the zero-external-database lightweight architecture.
   - Add unit/integration tests for your new functionality in `tests/`.
3. **Commit Messages**:
   Use conventional commits:
   - `feat(m2): add support for user-initiated discovery`
   - `fix(m3): correct fhir diagnostic report bundle structure`
   - `docs: update api reference table`
4. **Submit Your PR**:
   - Push your branch to GitHub and open a Pull Request against `main`.
   - Fill out the PR template with a clear description of changes.

---

## 📜 Code of Conduct
Please review and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all community interactions.
