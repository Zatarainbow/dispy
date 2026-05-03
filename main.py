from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import subprocess
import tempfile
import os

app = FastAPI(title="Python Bytecode Disassembler API")

RUNNER_SCRIPT = """
import sys
import marshal
import dis

pyc_file = sys.argv[1]
try:
    with open(pyc_file, 'rb') as f:
        # File .pyc từ Python 3.7 trở lên đều dùng 16 bytes header
        f.read(16)
        code_obj = marshal.load(f)
        
    dis.dis(code_obj)
except Exception as e:
    print(f"DECOMPILE_ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
"""

@app.post("/disassemble")
async def disassemble_pyc(
    file: UploadFile = File(...),
    # Đặt mặc định là 3.11, người dùng có thể đổi khi gửi request
    version: str = Form("3.11") 
):
    if not file.filename.endswith('.pyc'):
        raise HTTPException(status_code=400, detail="Chỉ hỗ trợ file định dạng .pyc")

    # Mở rộng danh sách hỗ trợ từ 3.7 tới 3.14
    allowed_versions = ["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]
    if version not in allowed_versions:
        raise HTTPException(status_code=400, detail=f"Không hỗ trợ Python {version}")

    python_executable = f"python{version}"

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pyc") as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            temp_file_path = tmp_file.name
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi lưu file: {str(e)}")

    try:
        result = subprocess.run(
            [python_executable, "-c", RUNNER_SCRIPT, temp_file_path],
            capture_output=True,
            text=True,
            timeout=10 # Tăng timeout lên 10s cho các file bị obfuscate nặng
        )

        if result.returncode != 0:
            error_msg = result.stderr.replace("DECOMPILE_ERROR: ", "").strip()
            return JSONResponse(
                status_code=400, 
                content={"error": f"Không thể phân tích file .pyc với Python {version}. Lỗi: {error_msg}"}
            )

        return {
            "filename": file.filename,
            "version_used": version,
            "disassembly": result.stdout
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Quá trình phân tích quá thời gian cho phép (Timeout)")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Không tìm thấy trình biên dịch {python_executable} trên server. Hãy kiểm tra lại Dockerfile.")
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
