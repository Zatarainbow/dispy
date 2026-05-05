import shutil
import struct
import subprocess
import sys
import tempfile
import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="PYC Disassembler", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAGIC_TO_VERSION: dict = {
    3000:"3.0",3010:"3.0",3020:"3.0",3030:"3.0",3040:"3.0",3050:"3.0",3060:"3.0",3061:"3.0",
    3071:"3.1",3081:"3.1",3091:"3.1",3101:"3.1",3103:"3.1",
    3111:"3.2",3121:"3.2",3131:"3.2",
    3141:"3.3",3151:"3.3",
    3160:"3.4",3170:"3.4",3180:"3.4",
    3190:"3.5",3200:"3.5",3210:"3.5",3220:"3.5",3230:"3.5",
    3250:"3.6",3260:"3.6",3270:"3.6",3280:"3.6",3290:"3.6",3300:"3.6",3310:"3.6",
    3320:"3.7",3330:"3.7",3340:"3.7",3350:"3.7",3360:"3.7",3361:"3.7",
    3370:"3.7",3371:"3.7",3372:"3.7",3373:"3.7",3374:"3.7",3375:"3.7",
    3376:"3.7",3377:"3.7",3378:"3.7",3379:"3.7",
    3400:"3.8",3401:"3.8",3410:"3.8",3411:"3.8",3412:"3.8",3413:"3.8",
    3420:"3.9",3421:"3.9",3422:"3.9",3423:"3.9",3424:"3.9",3425:"3.9",
    3430:"3.10",3431:"3.10",3432:"3.10",3433:"3.10",3434:"3.10",3435:"3.10",
    3450:"3.11",3451:"3.11",3452:"3.11",3453:"3.11",3454:"3.11",3455:"3.11",
    3456:"3.11",3457:"3.11",3458:"3.11",3459:"3.11",3460:"3.11",3461:"3.11",
    3462:"3.11",3463:"3.11",3464:"3.11",3465:"3.11",3466:"3.11",3467:"3.11",
    3468:"3.11",3469:"3.11",3470:"3.11",3471:"3.11",3472:"3.11",3473:"3.11",
    3474:"3.11",3475:"3.11",3476:"3.11",3477:"3.11",3478:"3.11",3479:"3.11",
    3480:"3.11",3481:"3.11",3482:"3.11",3483:"3.11",3484:"3.11",3485:"3.11",
    3486:"3.11",3487:"3.11",3488:"3.11",3489:"3.11",3490:"3.11",3491:"3.11",
    3492:"3.11",3493:"3.11",3494:"3.11",
    3500:"3.12",3501:"3.12",3502:"3.12",3503:"3.12",3504:"3.12",3505:"3.12",
    3506:"3.12",3507:"3.12",3508:"3.12",3509:"3.12",3510:"3.12",3511:"3.12",
    3512:"3.12",3513:"3.12",3514:"3.12",3515:"3.12",3516:"3.12",3517:"3.12",
    3518:"3.12",3519:"3.12",3520:"3.12",3521:"3.12",3522:"3.12",3523:"3.12",
    3524:"3.12",3525:"3.12",3526:"3.12",3527:"3.12",3528:"3.12",3529:"3.12",
    3530:"3.12",3531:"3.12",
    3550:"3.13",3551:"3.13",3552:"3.13",3553:"3.13",3554:"3.13",3555:"3.13",
    3556:"3.13",3557:"3.13",3558:"3.13",3559:"3.13",3560:"3.13",3561:"3.13",
    3562:"3.13",3563:"3.13",3564:"3.13",3565:"3.13",3566:"3.13",3567:"3.13",
    3568:"3.13",3569:"3.13",3570:"3.13",3571:"3.13",3572:"3.13",3573:"3.13",
    3574:"3.13",3575:"3.13",3576:"3.13",3577:"3.13",3578:"3.13",3579:"3.13",
    3580:"3.13",3581:"3.13",3582:"3.13",3583:"3.13",3584:"3.13",3585:"3.13",
}

DISASM_SCRIPT = r"""
import sys, dis, marshal, struct, io
path = sys.argv[1]
with open(path, 'rb') as f:
    data = f.read()
if len(data) < 8:
    print("ERROR: file qua nho", file=sys.stderr); sys.exit(1)
code = None
for hs in [16, 12, 8]:
    try:
        code = marshal.loads(data[hs:]); break
    except Exception:
        pass
if code is None:
    print("ERROR: khong the parse marshal", file=sys.stderr); sys.exit(1)
def dis_code(obj, depth=0):
    indent = "  " * depth
    print(f"{indent}# Code: {obj.co_name}  file={obj.co_filename}  line={obj.co_firstlineno}")
    print(f"{indent}# Args: {obj.co_varnames[:obj.co_argcount]}")
    print()
    buf = io.StringIO()
    old = sys.stdout; sys.stdout = buf
    try:
        dis.dis(obj)
    finally:
        sys.stdout = old
    for line in buf.getvalue().splitlines():
        print(f"{indent}{line}")
    for c in obj.co_consts:
        if hasattr(c, 'co_code'):
            print(f"\n{indent}" + "─"*60)
            dis_code(c, depth + 1)
dis_code(code)
"""

def get_magic(data: bytes) -> int:
    return struct.unpack("<H", data[:2])[0]

def find_interpreter(version: str):
    exact = f"python{version}"
    if shutil.which(exact):
        return exact
    for fallback in [f"python{version.split('.')[0]}", "python3", "python"]:
        if shutil.which(fallback):
            return fallback
    return None

def dispatch_disassemble(data: bytes, version: str) -> str:
    interpreter = find_interpreter(version)
    if interpreter is None:
        raise RuntimeError(f"Khong tim thay interpreter python{version} tren server.")
    with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [interpreter, "-c", DISASM_SCRIPT, tmp_path],
            capture_output=True, text=True, timeout=15,
        )
    finally:
        os.unlink(tmp_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Loi khong xac dinh")
    return result.stdout

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PYC Disassembler</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;--accent:#7c3aed;--accent2:#06b6d4;--text:#e2e8f0;--muted:#64748b;--green:#10b981}
  body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:40px 20px}
  h1{font-family:'Syne',sans-serif;font-size:clamp(2rem,5vw,3.5rem);font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:8px}
  .sub{color:var(--muted);font-size:.85rem;margin-bottom:16px}
  .versions{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 20px;margin-bottom:28px;font-size:.78rem;color:var(--muted);width:100%;max-width:720px}
  .versions strong{color:var(--green)}
  .versions ul{list-style:none;display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
  .versions li{background:#1a1a2e;border:1px solid var(--border);border-radius:6px;padding:3px 10px;color:var(--accent2)}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:32px;width:100%;max-width:720px}
  .drop-zone{border:2px dashed var(--border);border-radius:12px;padding:48px 24px;text-align:center;cursor:pointer;transition:all .2s;position:relative}
  .drop-zone:hover,.drop-zone.drag{border-color:var(--accent);background:rgba(124,58,237,.05)}
  .drop-zone input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
  .drop-icon{font-size:2.5rem;margin-bottom:12px}
  .drop-text{color:var(--muted);font-size:.85rem}
  #file-name{margin-top:16px;color:var(--accent2);font-size:.85rem}
  #py-ver{margin-top:8px;color:var(--green);font-size:.8rem}
  button{margin-top:20px;width:100%;padding:14px;background:var(--accent);color:#fff;border:none;border-radius:10px;font-family:'JetBrains Mono',monospace;font-size:.9rem;font-weight:700;cursor:pointer;transition:opacity .2s;letter-spacing:.05em}
  button:hover:not(:disabled){opacity:.85}
  button:disabled{opacity:.4;cursor:not-allowed}
  #result{margin-top:32px;display:none}
  .result-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
  .result-header span{color:var(--green);font-size:.8rem;font-weight:700}
  .copy-btn{background:var(--border);color:var(--muted);border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.75rem;font-family:inherit;width:auto;margin-top:0;transition:color .2s}
  .copy-btn:hover{color:var(--text)}
  pre{background:#070710;border:1px solid var(--border);border-radius:10px;padding:20px;overflow-x:auto;font-size:.78rem;line-height:1.7;max-height:600px;overflow-y:auto;white-space:pre}
  .error{color:#f87171;margin-top:16px;font-size:.85rem;padding:12px;background:rgba(248,113,113,.05);border:1px solid rgba(248,113,113,.2);border-radius:8px}
  .loading{display:none;text-align:center;color:var(--muted);font-size:.85rem;margin-top:16px}
</style>
</head>
<body>
<h1>PYC Disassembler</h1>
<p class="sub">Detect Python version từ magic number → dispatch đúng interpreter</p>
<div class="versions">
  <strong>Interpreters trên server:</strong>
  <ul>AVAILABLE_LIST</ul>
</div>
<div class="card">
  <div class="drop-zone" id="drop-zone">
    <input type="file" id="file-input" accept=".pyc">
    <div class="drop-icon">🐍</div>
    <p><strong>Kéo thả file .pyc vào đây</strong></p>
    <p class="drop-text">hoặc click để chọn file</p>
    <div id="file-name"></div>
    <div id="py-ver"></div>
  </div>
  <button id="submit-btn" disabled>Disassemble →</button>
  <div class="loading" id="loading">⏳ Đang xử lý...</div>
  <div id="error-msg"></div>
  <div id="result">
    <div class="result-header">
      <span id="result-label">✓ DISASSEMBLY OUTPUT</span>
      <button class="copy-btn" id="copy-btn">Copy</button>
    </div>
    <pre id="output"></pre>
  </div>
</div>
<script>
const MAGIC_MAP = MAGIC_JSON;
const input=document.getElementById('file-input'),btn=document.getElementById('submit-btn'),
  fileName=document.getElementById('file-name'),pyVer=document.getElementById('py-ver'),
  result=document.getElementById('result'),output=document.getElementById('output'),
  errorMsg=document.getElementById('error-msg'),loading=document.getElementById('loading'),
  dropZone=document.getElementById('drop-zone');
function readMagic(file){
  return new Promise(res=>{
    const r=new FileReader();
    r.onload=e=>{const b=new Uint8Array(e.target.result);res(b.length<4?null:(b[0]|(b[1]<<8)))};
    r.readAsArrayBuffer(file.slice(0,4));
  });
}
async function handleFile(f){
  if(!f||!f.name.endsWith('.pyc'))return;
  fileName.textContent='📄 '+f.name; btn.disabled=false;
  const magic=await readMagic(f);
  const ver=MAGIC_MAP[magic];
  pyVer.textContent=ver?`🔍 Python ${ver} (magic ${magic})`:`⚠️ Magic ${magic} — không nhận ra`;
}
input.addEventListener('change',()=>{if(input.files[0])handleFile(input.files[0])});
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('drag')});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('drag'));
dropZone.addEventListener('drop',e=>{
  e.preventDefault();dropZone.classList.remove('drag');
  const f=e.dataTransfer.files[0];
  if(f){const dt=new DataTransfer();dt.items.add(f);input.files=dt.files;handleFile(f);}
});
btn.addEventListener('click',async()=>{
  const file=input.files[0];if(!file)return;
  btn.disabled=true;loading.style.display='block';result.style.display='none';errorMsg.innerHTML='';
  const form=new FormData();form.append('file',file);
  try{
    const res=await fetch('/disassemble',{method:'POST',body:form});
    const data=await res.json();
    if(!res.ok)throw new Error(data.detail||'Lỗi không xác định');
    output.textContent=data.disassembly;
    document.getElementById('result-label').textContent=`✓ Python ${data.python_version} · magic ${data.magic}`;
    result.style.display='block';
  }catch(e){errorMsg.innerHTML='<div class="error">❌ '+e.message+'</div>';}
  finally{btn.disabled=false;loading.style.display='none';}
});
document.getElementById('copy-btn').addEventListener('click',()=>{
  navigator.clipboard.writeText(output.textContent);
  document.getElementById('copy-btn').textContent='Đã copy!';
  setTimeout(()=>document.getElementById('copy-btn').textContent='Copy',1500);
});
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def index():
    available = []
    seen = set()
    for ver in sorted(set(MAGIC_TO_VERSION.values()), key=lambda v: list(map(int, v.split('.')))):
        interp = find_interpreter(ver)
        if interp and interp not in seen:
            seen.add(interp)
            available.append(f"<li>python{ver}</li>")
    available_html = "".join(available) or "<li>(none)</li>"
    import json
    html = HTML_TEMPLATE.replace("AVAILABLE_LIST", available_html)
    html = html.replace("MAGIC_JSON", json.dumps(MAGIC_TO_VERSION))
    return html

@app.get("/interpreters")
async def list_interpreters():
    found = {}
    for ver in sorted(set(MAGIC_TO_VERSION.values())):
        interp = find_interpreter(ver)
        if interp:
            found[ver] = interp
    return {"interpreters": found}

@app.post("/disassemble")
async def disassemble(file: UploadFile = File(...)):
    if not file.filename.endswith(".pyc"):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận file .pyc")
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File quá lớn (tối đa 10MB)")
    if len(data) < 8:
        raise HTTPException(status_code=422, detail="File quá nhỏ, không phải .pyc hợp lệ.")
    magic = get_magic(data)
    version = MAGIC_TO_VERSION.get(magic)
    if version is None:
        raise HTTPException(status_code=422, detail=f"Magic number {magic} không nhận ra.")
    try:
        disasm = dispatch_disassemble(data, version)
    except RuntimeError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi server: {e}")
    return JSONResponse({"filename": file.filename, "magic": magic, "python_version": version, "disassembly": disasm})
