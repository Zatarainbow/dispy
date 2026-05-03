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
        # Python 3.7 trở lên sử dụng 16 bytes cho header của file .pyc
        # (magic number, bitfield, timestamp, file size)
        f.read(16)
        
        # Đọc phần mã đã được biên dịch
        code_obj = marshal.load(f)
        
    # Phân tích bytecode
    dis.dis(code_obj)
except Exception as e:
    print(f"DECOMPILE_ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
"""

@app.post("/disassemble")
async def disassemble_pyc(
    file: UploadFile = File(...),
    # Cho phép người dùng chọn version (mặc định là 3.11)
    version: str = Form("3.11") 
):
    # 1. Kiểm tra định dạng file
    if not file.filename.endswith('.pyc'):
        raise HTTPException(status_code=400, detail="Chỉ hỗ trợ file định dạng .pyc")

    # Kiểm tra xem version được yêu cầu có hợp lệ/được hỗ trợ không
    allowed_versions = ["3.8", "3.9", "3.10", "3.11"]
    if version not in allowed_versions:
        raise HTTPException(status_code=400, detail=f"Không hỗ trợ Python {version}")

    # Lệnh gọi Python tương ứng (ví dụ: python3.8)
    python_executable = f"python{version}"

    # 2. Lưu file upload vào một thư mục tạm thời
    try:
        # Tạo file tạm với đuôi .pyc
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pyc") as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            temp_file_path = tmp_file.name
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi lưu file: {str(e)}")

    # 3. Chạy subprocess để dis.dis file .pyc bằng đúng version Python
    try:
        result = subprocess.run(
            [python_executable, "-c", RUNNER_SCRIPT, temp_file_path],
            capture_output=True,
            text=True, # Lấy output dạng string thay vì bytes
            timeout=5  # Tránh việc file pyc bị lỗi gây treo hệ thống
        )

        # 4. Kiểm tra kết quả trả về
        if result.returncode != 0:
            error_msg = result.stderr.replace("DECOMPILE_ERROR: ", "").strip()
            return JSONResponse(
                status_code=400, 
                content={"error": f"Không thể phân tích file .pyc với Python {version}. Lỗi: {error_msg}"}
            )

        # Trả về mã bytecode dis.dis()
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
        # Xóa file tạm để tránh rác ổ cứng
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
