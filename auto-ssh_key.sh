#!/bin/bash

# Dán nội dung Public Key của bạn vào đây
MY_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/11gnUDHAjyPg2SuTvPhZIilxYgarE9NPZVYlo9A32 hainguyen"
TARGET_USER="hhh" # Hoặc user khác ví dụ: "admin"

# Xác định thư mục Home
if [ "$TARGET_USER" = "root" ]; then
    HOME_DIR="/root"
else
    HOME_DIR="/home/$TARGET_USER"
fi

SSH_DIR="$HOME_DIR/.ssh"
AUTH_FILE="$SSH_DIR/authorized_keys"

echo "Dang cau hinh SSH Key cho user: $TARGET_USER"

# Tạo thư mục .ssh nếu chưa có
mkdir -p "$SSH_DIR"

# Thêm key vào file (tránh trùng lặp)
if grep -q "$MY_SSH_KEY" "$AUTH_FILE" 2>/dev/null; then
    echo "Key da ton tai, bo qua."
else
    echo "$MY_SSH_KEY" >> "$AUTH_FILE"
    echo "Da them key."
fi

# CHỐT QUYỀN (Rất quan trọng với Debian 12)
chown -R "$TARGET_USER:$TARGET_USER" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_FILE"

echo "✅ Hoan tat."
