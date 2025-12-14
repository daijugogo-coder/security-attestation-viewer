import hashlib
import io
import zipfile
import re
import streamlit as st


st.set_page_config(
    page_title="Security Attestation Viewer",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ Security Attestation Viewer")
st.caption(
    "Verify an uploaded evidence ZIP against an uploaded SHA256 file. "
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

# ----------------------------
# UI
# ----------------------------

st.header("1) Upload evidence ZIP")
uploaded_zip = st.file_uploader(
    "Drop SECURITY_EVIDENCE.zip here",
    type=["zip"],
    accept_multiple_files=False,
    key="zip",
)

st.header("2) Upload SHA256 file")
uploaded_sha = st.file_uploader(
    "Drop SECURITY_EVIDENCE.sha256 here",
    type=["sha256", "txt"],
    accept_multiple_files=False,
    key="sha256",
)

if uploaded_zip is None or uploaded_sha is None:
    st.info(
        "ZIPとSHA256ファイルの **2つ** をアップロードしてください（このアプリはサーバ側にファイルを保存しません）。"
    )
    st.stop()

zip_bytes = uploaded_zip.read()
zip_hash = sha256_bytes(zip_bytes)

sha_text = uploaded_sha.read().decode("utf-8", errors="replace")

def extract_sha256_from_sha256_file(text: str) -> str | None:
    """Extract 64-hex SHA256 from a .sha256 file content."""
    parts = text.strip().split()
    if len(parts) == 2 and len(parts[0]) == 64 and re.match(r"[0-9a-fA-F]{64}", parts[0]):
        return parts[0].upper()
    return None

expected_hash = extract_sha256_from_sha256_file(sha_text)

st.header("3) Calculated SHA256 (from uploaded ZIP)")
st.code(zip_hash, language="text")

st.header("4) Expected SHA256 (from uploaded .sha256)")
if expected_hash is None:
    st.error("sha256ファイルからSHA256値（64桁のhex）が抽出できません。内容形式を確認してください。")
    with st.expander("Show uploaded sha256 file text"):
        st.code(sha_text, language="text")
    st.stop()

st.code(expected_hash, language="text")

st.header("5) Consistency check (ZIP vs SHA256 file)")
if expected_hash == zip_hash:
    st.success("一致：sha256ファイル記載のSHA256と、アップロードZIPのSHA256が一致しました。")
else:
    st.error("不一致：sha256ファイル記載のSHA256と、アップロードZIPのSHA256が一致しません。")

st.header("6) SECURITY_ATTESTATION.md (from uploaded ZIP)")
md_text, file_list = extract_attestation_md(zip_bytes)

if md_text is None:
    st.error("ZIP内に SECURITY_ATTESTATION.md が見つかりません（必須）。")
    st.stop()

st.markdown(md_text)

st.caption("Note: Verification is performed in-memory; uploaded files are not persisted by this app.")
