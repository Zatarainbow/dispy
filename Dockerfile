# Sử dụng Ubuntu 22.04 làm môi trường gốc
FROM ubuntu:22.04

# Thiết lập biến môi trường
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Cài đặt PPA deadsnakes và các tool cần thiết
RUN apt-get update && apt-get install -y \
    software-properties-common \
    curl \
    && add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update

# Cài đặt toàn bộ các phiên bản Python từ 3.7 đến 3.14
# Dùng bản 3.11 làm bản chính (cài kèm pip và dev tools)
RUN apt-get install -y \
    python3.7 \
    python3.8 \
    python3.9 \
    python3.10 \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3.12 \
    python3.13 \
    python3.14 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Thiết lập Python 3.11 làm bản mặc định cho hệ thống (để chạy FastAPI)
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1

# Cấu hình thư mục làm việc cho App
WORKDIR /app

# Copy tệp cấu hình thư viện vào container
COPY requirements.txt .

# Cài đặt thư viện Python cho FastAPI
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn của bạn vào container
COPY . .

# Mở port 8000
EXPOSE 8000

# Lệnh khởi chạy FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
