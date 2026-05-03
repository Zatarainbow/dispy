import dis
import io
import marshal
import struct
import sys
import time

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="PYC Disassembler", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAGIC_SIZES = {
    # Python 3.8+: 16-byte header
    16: "3.8+",
    # Python 3.6–3.7: 12-byte header
    12: "3.6-3.7",
    # Python 3.0–3.5: 8-byte header
    8: "3.0-3.5",
}

def parse_pyc(data: bytes):
    """Parse .pyc file and return the code object."""
    if len(data) < 16:
        raise ValueError("File quá nhỏ, không phải .pyc hợp lệ.")

    magic = data[:4]
    magic_num = struct.unpack("<H", magic[:2])[0]

    # Try each known header size, pick the one that works
    code = None
    last_err = None
    for header_size in [16, 12, 8]:
        try:
            code = marshal.loads(data[header_size:])
            break
        except Exception as e:
            last_err = e

    if code is None:
        raise ValueError(f"Không thể parse bytecode: {last_err}")

    return code, magic_num


def disassemble_code(code_obj, depth=0) -> str:
    """Recursively disassemble code object."""
    out = io.StringIO()
    indent = "  " * depth

    out.write(f"{indent}# Code object: {code_obj.co_name}\n")
    out.write(f"{indent}# File: {code_obj.co_filename}, Line: {code_obj.co_firstlineno}\n")
    out.write(f"{indent}# Args: {code_obj.co_varnames[:code_obj.co_argcount]}\n\n")

    # Capture dis output
    buf = io.StringIO()
    sys.stdout = buf
    try:
        dis.dis(code_obj)
    finally:
        sys.stdout = sys.__stdout__

    for line in buf.getvalue().splitlines():
        out.write(f"{indent}{line}\n")

    # Recurse into nested code objects
    for const in code_obj.co_consts:
        if hasattr(const, "co_code"):
            out.write(f"\n{indent}{'─'*60}\n")
            out.write(disassemble_code(const, depth + 1))

    return out.getvalue()


@app.get("/", response_class=HTMLResponse)
async def index():
    return """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PYC Disassembler</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --border: #1e1e2e;
    --accent: #7c3aed;
    --accent2: #06b6d4;
    --text: #e2e8f0;
    --muted: #64748b;
    --green: #10b981;
  }
  body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace;
    min-height: 100vh; display: flex; flex-direction: column; align-items: center;
    padding: 40px 20px; }
  h1 { font-family: 'Syne', sans-serif; font-size: clamp(2rem, 5vw, 3.5rem);
    font-weight: 800; background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 8px; }
  .sub { color: var(--muted); font-size: 0.85rem; margin-bottom: 40px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
    padding: 32px; width: 100%; max-width: 720px; }
  .drop-zone { border: 2px dashed var(--border); border-radius: 12px; padding: 48px 24px;
    text-align: center; cursor: pointer; transition: all 0.2s; position: relative; }
  .drop-zone:hover, .drop-zone.drag { border-color: var(--accent); background: rgba(124,58,237,0.05); }
  .drop-zone input { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%; }
  .drop-icon { font-size: 2.5rem; margin-bottom: 12px; }
  .drop-text { color: var(--muted); font-size: 0.85rem; }
  .drop-text strong { color: var(--text); }
  #file-name { margin-top: 16px; color: var(--accent2); font-size: 0.85rem; }
  button { margin-top: 20px; width: 100%; padding: 14px; background: var(--accent);
    color: white; border: none; border-radius: 10px; font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem; font-weight: 700; cursor: pointer; transition: opacity 0.2s;
    letter-spacing: 0.05em; }
  button:hover:not(:disabled) { opacity: 0.85; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  #result { margin-top: 32px; display: none; }
  .result-header { display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 12px; }
  .result-header span { color: var(--green); font-size: 0.8rem; font-weight: 700; }
  .copy-btn { background: var(--border); color: var(--muted); border: none; padding: 6px 14px;
    border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-family: inherit;
    width: auto; margin-top: 0; transition: color 0.2s; }
  .copy-btn:hover { color: var(--text); }
  pre { background: #070710; border: 1px solid var(--border); border-radius: 10px;
    padding: 20px; overflow-x: auto; font-size: 0.78rem; line-height: 1.7;
    max-height: 600px; overflow-y: auto; white-space: pre; }
  .error { color: #f87171; margin-top: 16px; font-size: 0.85rem; padding: 12px;
    background: rgba(248,113,113,0.05); border: 1px solid rgba(248,113,113,0.2);
    border-radius: 8px; }
  .loading { display: none; text-align: center; color: var(--muted); font-size: 0.85rem;
    margin-top: 16px; }
</style>
</head>
<body>
<h1>PYC Disassembler</h1>
<p class="sub">Upload .pyc → nhận bytecode disassembly ngay lập tức</p>
<div class="card">
  <div class="drop-zone" id="drop-zone">
    <input type="file" id="file-input" accept=".pyc">
    <div class="drop-icon">🐍</div>
    <p><strong>Kéo thả file .pyc vào đây</strong></p>
    <p class="drop-text">hoặc click để chọn file</p>
    <div id="file-name"></div>
  </div>
  <button id="submit-btn" disabled>Disassemble →</button>
  <div class="loading" id="loading">⏳ Đang xử lý...</div>
  <div id="error-msg"></div>
  <div id="result">
    <div class="result-header">
      <span>✓ DISASSEMBLY OUTPUT</span>
      <button class="copy-btn" id="copy-btn">Copy</button>
    </div>
    <pre id="output"></pre>
  </div>
</div>
<script>
  const input = document.getElementById('file-input');
  const btn = document.getElementById('submit-btn');
  const fileName = document.getElementById('file-name');
  const result = document.getElementById('result');
  const output = document.getElementById('output');
  const errorMsg = document.getElementById('error-msg');
  const loading = document.getElementById('loading');
  const dropZone = document.getElementById('drop-zone');

  input.addEventListener('change', () => {
    if (input.files[0]) {
      fileName.textContent = '📄 ' + input.files[0].name;
      btn.disabled = false;
    }
  });

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if (f && f.name.endsWith('.pyc')) {
      const dt = new DataTransfer(); dt.items.add(f); input.files = dt.files;
      fileName.textContent = '📄 ' + f.name; btn.disabled = false;
    }
  });

  btn.addEventListener('click', async () => {
    const file = input.files[0];
    if (!file) return;
    btn.disabled = true;
    loading.style.display = 'block';
    result.style.display = 'none';
    errorMsg.innerHTML = '';

    const form = new FormData();
    form.append('file', file);

    try {
      const res = await fetch('/disassemble', { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Lỗi không xác định');
      output.textContent = data.disassembly;
      result.style.display = 'block';
    } catch (e) {
      errorMsg.innerHTML = '<div class="error">❌ ' + e.message + '</div>';
    } finally {
      btn.disabled = false;
      loading.style.display = 'none';
    }
  });

  document.getElementById('copy-btn').addEventListener('click', () => {
    navigator.clipboard.writeText(output.textContent);
    document.getElementById('copy-btn').textContent = 'Đã copy!';
    setTimeout(() => document.getElementById('copy-btn').textContent = 'Copy', 1500);
  });
</script>
</body>
</html>"""


@app.post("/disassemble")
async def disassemble(file: UploadFile = File(...)):
    if not file.filename.endswith(".pyc"):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận file .pyc")

    data = await file.read()
    if len(data) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File quá lớn (tối đa 10MB)")

    try:
        code_obj, magic_num = parse_pyc(data)
        disasm = disassemble_code(code_obj)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi xử lý: {e}")

    return JSONResponse({
        "filename": file.filename,
        "magic": magic_num,
        "disassembly": disasm,
    })
