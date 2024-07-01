import os
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# 設定文件路徑
private_key_path = "私鑰 private_key.pem"

# 載入私鑰
def load_private_key():
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None  # 如果有密碼加密，這裡需要提供密碼
        )
    return private_key

# 解密資料
def decrypt_data(private_key, encrypted_data):
    decrypted_message = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# 主程序流程
def main():
    if not os.path.exists(private_key_path):
        print("資料夾內未找到私鑰文件。請確保已放置在與程序同級目錄下。")
        print()
        os.system('pause')
        return  # 退出程序

    private_key = load_private_key()

    # 解密資料
    data = input("請輸入要解密的資料(byte格式): ")
    print()
    try:
        encrypted_data = eval(data)  # 將輸入的字節格式資料轉換為實際資料
        decrypted_message = decrypt_data(private_key, encrypted_data)
        print("解密後:", decrypted_message)
        print()
        result_text = f"加密資料為: {data}\n解密為: {decrypted_message}\n"

        # 保存為 txt
        log_dir = "log"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, f"解密_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(log_file, "w") as f:
            f.write(result_text)

        print("解密結果已保存到文件:", log_file)
        print()
        os.system('pause')

    except Exception as e:
        print(f"解密失敗: {e}")
        print()
        os.system('pause')

if __name__ == "__main__":
    main()
