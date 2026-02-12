#!/bin/bash

MY_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/11gnUDHAjyPg2SuTvPhZIilxYgarE9NPZVYlo9A32 hainguyen"

CURRENT_USER=$(whoami)

echo "--- Cau hinh SSH Key ---"
echo "User hien tai la: $CURRENT_USER"
read -p "Ban muon cai dat cho user nao? (Mac dinh: $CURRENT_USER): " TARGET_USER

TARGET_USER=${TARGET_USER:-$CURRENT_USER}

if [ "$TARGET_USER" != "$CURRENT_USER" ] && [ "$EUID" -ne 0 ]; then
    echo "(!) Ban dang muon can thiep vao user '$TARGET_USER'. Vui long chay lai script voi sudo:"
    echo "sudo $0"
    exit 1
fi

if [ "$TARGET_USER" = "root" ]; then
    HOME_DIR="/root"
else
    HOME_DIR=$(getent passwd "$TARGET_USER" | cut -d: -f6)
    
    if [ -z "$HOME_DIR" ]; then
        echo "❌ Loi: User '$TARGET_USER' khong ton tai tren he thong."
        exit 1
    fi
fi

SSH_DIR="$HOME_DIR/.ssh"
AUTH_FILE="$SSH_DIR/authorized_keys"

echo "--> Dang cau hinh cho: $TARGET_USER (Thu muc: $HOME_DIR)"

mkdir -p "$SSH_DIR"

if grep -q "$MY_SSH_KEY" "$AUTH_FILE" 2>/dev/null; then
    echo "📢 Key da ton tai, bo qua."
else
    echo "$MY_SSH_KEY" >> "$AUTH_FILE"
    echo "✅ Da them key moi."
fi

chown -R "$TARGET_USER:$TARGET_USER" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_FILE"

echo "✨ Hoan tat cau hinh cho $TARGET_USER."
