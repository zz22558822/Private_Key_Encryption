import os
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# 設定文件路徑
private_key_path = "私鑰 private_key.pem"
public_key_path = "公鑰 public_key.pem"

# 檢查是否存在私鑰和公鑰文件
def check_key_files():
    return os.path.exists(private_key_path) and os.path.exists(public_key_path)

# 生成新的密鑰對
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 儲存私鑰
    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # 可以使用密碼加密這裡的私鑰
            )
        )

    # 儲存公鑰
    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# 載入現有的密鑰對
def load_key_pair():
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None  # 如果有密碼加密，這裡需要提供密碼
        )

    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read()
        )
    return private_key, public_key

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
    if not check_key_files():
        print("資料夾內未找到密鑰文件。")
        print()
        while True:
            print("是否要生成新的密鑰？")
            choice = input("生成新密鑰 (輸入 0)、用現有密鑰(輸入 1): ")
            print()
            if choice == "0":
                generate_key_pair()
                break
            elif choice == "1":
                print("請確保已將私鑰和公鑰放置在與程序同級目錄下。")
                continue
            else:
                print("請輸入有效的選項。")
                continue

    private_key, public_key = load_key_pair()

    # 選擇加密或解密
    while True:
        print("是否要加密或解密？")
        action = input("加密 (輸入 0)、解密 (輸入 1): ")
        print()
        if action == "0":
            action_name = f'加密'
            data = input("請輸入要加密的資料: ")
            print()
            encrypted_message = encrypt_data(public_key, data)
            print("加密後:", encrypted_message)
            print()
            # 顯示結果並保存到 txt 文件
            result_text = f"資料為: {data}\n加密為: {encrypted_message}\n"
            print('--------------------------------------------------')
            break

        elif action == "1":
            action_name = f'解密'
            data = input("請輸入要解密的資料(byte格式): ")
            print()
            try:
                encrypted_data = eval(data)
                decrypted_message = decrypt_data(private_key, encrypted_data)
                print("解密後:", decrypted_message)
                print('--------------------------------------------------')
                print()
                # 顯示結果並保存到 txt 文件
                result_text = f"加密資料為: {data}\n解密為: {decrypted_message}\n"
            except Exception as e:
                print(f"解密失敗: {e}")
                print('--------------------------------------------------')
                continue
            break

        else:
            print("請輸入有效的選項。")
            print()
            continue

    # 保存為 txt
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"{action_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_file, "w") as f:
        f.write(result_text)


    print("結果已保存到文件:", log_file)
    print()
    os.system('pause')

if __name__ == "__main__":
    main()
