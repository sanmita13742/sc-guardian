# sc-guardian

| Folder | What it is |
|---|---|
| [`streamlit_app/`](streamlit_app/) | **SC Guardian**, the agentic supply-chain security scanner (Streamlit). Everything you run lives here — start with [`streamlit_app/README.md`](streamlit_app/README.md). |
| [`nodegoat/`](nodegoat/) | OWASP NodeGoat, an intentionally vulnerable Node.js app used as a demo/scan target. It is kept completely separate from the scanner and is not part of it. |

```bash
cd streamlit_app
pip install -r requirements.txt
python scripts/verify_environment.py
streamlit run app.py
```
