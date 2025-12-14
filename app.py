"""Security Attestation Viewer Streamlit app (upload-based)."""

import hashlib
import io
import re
import zipfile

import streamlit as st


st.set_page_config(
    page_title="Security Attestation Viewer",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ Security Attestation Viewer")
st.caption(
    "Verify an uploaded evidence ZIP (integrity check). "
    "This is not a formal certification."
)

# ----------------------------
# Helpers
# ----------------------------

def sha256_bytes(data: bytes) -> str:
    """Return SHA256 hex digest (uppercase) for bytes."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest().upper()


def extract_attestation_md(zip_bytes: bytes) -> tuple[str | None, list[str]]:
    """Extract SECURITY_ATTESTATION.md text from the ZIP (in-memory)."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        names = z.namelist()

        # allow either root or subfolder path
        candidates = [n for n in names if n.endswith("SECURITY_ATTESTATION.md")]
        if not candidates:
            return None, names

        md_name = candidates[0]
        md_bytes = z.read(md_name)
        md_text = md_bytes.decode("utf-8", errors="replace")
        return md_text, names


def find_sha256_in_markdown(md_text: str) -> str | None:
    """Find 'SHA256: <64hex>' in markdown."""
    m = re.search(r"SHA256\s*:\s*([0-9a-fA-F]{64})", md_text)
    return m.group(1).upper() if m else None


# ----------------------------
# UI
# ----------------------------

st.header("1) Upload evidence ZIP")
uploaded = st.file_uploader(
    "Drop SECURITY_EVIDENCE.zip here",
    type=["zip"],
    accept_multiple_files=False,
)

if uploaded is None:
    st.info("ZIPをアップロードしてください（このアプリはサーバ側にmd/zipを保持しません）。")
    st.stop()

zip_bytes = uploaded.read()
zip_hash = sha256_bytes(zip_bytes)

st.header("2) ZIP SHA256")
st.code(zip_hash, language="text")

md_text, file_list = extract_attestation_md(zip_bytes)

st.header("3) ZIP contents")
st.write(f"{len(file_list)} files found.")
with st.expander("Show file list"):
    for n in file_list:
        st.write(f"- {n}")

st.header("4) SECURITY_ATTESTATION.md (from ZIP)")
if md_text is None:
    st.error("ZIP内に SECURITY_ATTESTATION.md が見つかりません。")
    st.stop()

st.markdown(md_text)

st.header("5) Consistency check")
embedded = find_sha256_in_markdown(md_text)
if embedded is None:
    st.warning("SECURITY_ATTESTATION.md 内に 'SHA256: <64hex>' が見つかりません。照合できません。")
else:
    if embedded == zip_hash:
        st.success("一致：md記載のSHA256と、アップロードZIPのSHA256が一致しました。")
    else:
        st.error("不一致：md記載のSHA256と、アップロードZIPのSHA256が一致しません。")

st.caption("Note: Verification is performed in-memory; uploaded files are not persisted by this app.")
