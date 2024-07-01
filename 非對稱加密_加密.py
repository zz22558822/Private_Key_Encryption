import os
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# 設定文件路徑
public_key_path = "公鑰 public_key.pem"

# 載入公鑰
def load_public_key():
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read()
        )
    return public_key

# 加密資料
def encrypt_data(public_key, data):
    message_bytes = data.encode()
    encrypted_message = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# 主程序流程
def main():
    if not os.path.exists(public_key_path):
        print("未找到公鑰，請確保已放置在與程序同級目錄下。")
        print()
        os.system('pause')
        return  # 退出程序

    public_key = load_public_key()

    # 加密資料
    data = input("請輸入要加密的資料: ")
    print()
    encrypted_message = encrypt_data(public_key, data)
    print("加密後:", encrypted_message)
    print()
    result_text = f"資料為: {data}\n加密為: {encrypted_message}\n"

    # 保存為 txt
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"加密_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_file, "w") as f:
        f.write(result_text)

    print("加密結果已保存到文件:", log_file)
    print()
    os.system('pause')

if __name__ == "__main__":
    main()
