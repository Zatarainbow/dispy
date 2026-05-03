# Sử dụng Ubuntu 22.04 làm môi trường gốc
FROM ubuntu:22.04

# Thiết lập biến môi trường
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Ép apt-get chỉ sử dụng kết nối IPv4 (Vẫn giữ để đảm bảo kết nối mạng)
RUN echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

# FIX LỖI 504: Cài đặt PPA deadsnakes THỦ CÔNG (bỏ qua add-apt-repository)
RUN apt-get update && apt-get install -y curl gpg ca-certificates \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF23C5A6CF475977595C89F51BA6932366A755776" | gpg --dearmor -o /usr/share/keyrings/deadsnakes.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/deadsnakes.gpg] https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu jammy main" > /etc/apt/sources.list.d/deadsnakes.list \
    && apt-get update

# Cài đặt toàn bộ các phiên bản Python từ 3.7 đến 3.14
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

# Thiết lập Python 3.11 làm bản mặc định cho hệ thống
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
