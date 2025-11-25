#!/bin/bash
# File: create-selfsigned.sh
# Mô tả: Tạo cert self-signed 10 năm, SAN đầy đủ, đặt vào /etc/ssl/selfsigned/
# Tác giả: Grok (2025)

set -e

TARGET_DIR="/etc/ssl/selfsigned"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

echo "=== Tạo chứng chỉ SSL self-signed (ECDSA P-256 + RSA fallback) ==="
echo "Thư mục đích: $TARGET_DIR"
echo

# Danh sách domain/IP bạn muốn hỗ trợ (thêm/bớt tùy ý)
DOMAINS=(
    "localhost"
    "*.localhost"
    "local.dev"
    "*.local.dev"
    "*.example.test"
    "127.0.0.1"
    "::1"
)

# Tạo chuỗi SAN
SAN=""
for i in "${!DOMAINS[@]}"; do
    SAN="$SAN,DNS:${DOMAINS[$i]}"
    [[ ${DOMAINS[$i]} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && SAN="$SAN,IP:${DOMAINS[$i]}"
    [[ ${DOMAINS[$i]} == "::1" ]] && SAN="$SAN,IP:::1"
done
SAN=${SAN:1}  # bỏ dấu phẩy đầu

# 1. Tạo cert ECDSA P-256 (ưu tiên hiện đại)
openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout ec-key.pem -out ec-cert.pem \
    -days 3650 -nodes -subj "/CN=Local Dev Server/O=Self-Signed 2025/C=VN" \
    -addext "subjectAltName = $SAN" \
    -addext "keyUsage = critical, digitalSignature, keyEncipherment" \
    -addext "extendedKeyUsage = serverAuth, clientAuth"

# 2. Tạo cert RSA 4096 (để tương thích thiết bị cực cũ)
openssl req -x509 -newkey rsa:4096 \
    -keyout rsa-key.pem -out rsa-cert.pem \
    -days 3650 -nodes -subj "/CN=Local Dev Server/O=Self-Signed 2025/C=VN" \
    -addext "subjectAltName = $SAN" \
    -addext "keyUsage = critical, digitalSignature, keyEncipherment" \
    -addext "extendedKeyUsage = serverAuth, clientAuth"

# 3. Tạo file fullchain (cert + chain, tiện dùng cho Nginx/HAProxy)
cat ec-cert.pem > fullchain.pem
cat rsa-cert.pem >> fullchain.pem

# 4. Đặt quyền bảo mật
chmod 644 *.pem
chmod 600 *-key.pem

# 5. Tạo symlink tiện dùng
ln -sf ec-cert.pem  default.crt
ln -sf ec-key.pem   default.key
ln -sf fullchain.pem default-fullchain.pem

echo
echo "=== HOÀN TẤT ==="
echo "Các file đã tạo trong $TARGET_DIR:"
ls -l "$TARGET_DIR"
echo
echo "File nên dùng (hiện đại):"
echo "  Certificate : $TARGET_DIR/ec-cert.pem  hoặc  $TARGET_DIR/default.crt"
echo "  Private key : $TARGET_DIR/ec-key.pem   hoặc  $TARGET_DIR/default.key"
echo "  Fullchain   : $TARGET_DIR/fullchain.pem"
echo
echo "File dự phòng RSA (tương thích cũ): rsa-cert.pem + rsa-key.pem"
echo
echo "Cấu hình Nginx ví dụ:"
echo "    ssl_certificate     /etc/ssl/selfsigned/default.crt;"
echo "    ssl_certificate_key /etc/ssl/selfsigned/default.key;"
