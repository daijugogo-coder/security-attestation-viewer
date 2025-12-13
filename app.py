import streamlit as st
from pathlib import Path
import hashlib

# ----------------------------

# Configuration (files are expected to be in the same folder as this app.py)

# ----------------------------

APP_DIR = Path(**file**).resolve().parent
ATTESTATION_PATH = APP_DIR / "SECURITY_ATTESTATION.md"
EVIDENCE_ZIP_PATH = APP_DIR / "SECURITY_EVIDENCE.zip"

st.set_page_config(
page_title="Security Attestation Viewer",
page_icon="🛡️",
layout="centered",
)

st.title("🛡️ Security Attestation Viewer")
st.caption("This page publishes security evidence for verification. It is not a formal certification.")

# ----------------------------

# Helpers

# ----------------------------

def sha256_file(path: Path) -> str:
h = hashlib.sha256()
with path.open("rb") as f:
for chunk in iter(lambda: f.read(1024 * 1024), b""):
h.update(chunk)
return h.hexdigest().upper()

# ----------------------------

# Attestation

# ----------------------------

st.header("SECURITY_ATTESTATION.md")

if ATTESTATION_PATH.exists():
md = ATTESTATION_PATH.read_text(encoding="utf-8", errors="replace")
st.markdown(md)
else:
st.error(f"Missing file: {ATTESTATION_PATH.name}")
st.info("Place SECURITY_ATTESTATION.md in the same folder as app.py.")

st.divider()

# ----------------------------

# Evidence ZIP + SHA256

# ----------------------------

st.header("Evidence Archive (ZIP)")

if EVIDENCE_ZIP_PATH.exists():
zip_bytes = EVIDENCE_ZIP_PATH.read_bytes()

```
# Compute hash from bytes (same result as hashing the file)
computed_sha256 = hashlib.sha256(zip_bytes).hexdigest().upper()

st.subheader("SHA256")
st.code(computed_sha256, language="text")

st.download_button(
    label="Download SECURITY_EVIDENCE.zip",
    data=zip_bytes,
    file_name="SECURITY_EVIDENCE.zip",
    mime="application/zip",
    use_container_width=True,
)

with st.expander("What this proves / what it does NOT prove"):
    st.markdown(
        "- **Proves**: the downloaded ZIP matches the SHA256 shown above (integrity).\n"
        "- **Does NOT prove**: the application is 'secure' in any absolute sense.\n"
        "- This is a self-attestation with evidence, not a third-party audit."
    )
```

else:
st.error(f"Missing file: {EVIDENCE_ZIP_PATH.name}")
st.info("Place SECURITY_EVIDENCE.zip in the same folder as app.py.")

st.divider()

# ----------------------------

# Quick verification instructions

# ----------------------------

st.header("How to verify locally (Windows PowerShell)")

st.code(
r"""# 1) Download SECURITY_EVIDENCE.zip from this page

# 2) Run:

Get-FileHash .\SECURITY_EVIDENCE.zip -Algorithm SHA256
""",
language="powershell",
)
