# .tests.py
import argparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def encrypt_with_public_key(data, public_key):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_with_private_key(encrypted_data, private_key):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser()
    parser.add_argument('--encode_code', required=True, help='The encryption password')
    args = parser.parse_args()

    encryption_password = args.encode_code

    # 生成RSA密钥对
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    # 保存密钥对
    with open('.env', 'w') as env_file:
        env_file.write(f"PRIVATE_KEY={private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode()}\n")
        env_file.write(f"PUBLIC_KEY={public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}\n")

    # 读取加密的.env文件
    with open('cookie.env', 'r') as env_file:
        for line in env_file:
            key, encrypted_value = line.strip().split('=')
            if key == 'SESSDATA':
                sessdata = decrypt_with_private_key(encrypted_value, private_key)
                print(sessdata)
            elif key == 'BIILI_JCT':
                bili_jct = decrypt_with_private_key(encrypted_value, private_key)
            elif key == 'REFRESH_TOKEN':
                refresh_token = decrypt_with_private_key(encrypted_value, private_key)
    print(f"sessdata: {sessdata}")
    print(f"bili_jct: {bili_jct}")
    print(f"refresh_token: {refresh_token}")
    return sessdata, bili_jct, refresh_token            

    # 使用解密后的值进行操作（例如执行curl命令）
    # ...

    # 加密解密后的值
    encrypted_sessdata = encrypt_with_public_key(sessdata, public_key)
    encrypted_bili_jct = encrypt_with_public_key(bili_jct, public_key)
    encrypted_refresh_token = encrypt_with_public_key(refresh_token, public_key)
    with open('cookie.env', 'w') as env_file:
      env_file.write(f"SESSDATA={encrypted_sessdata}\n")
      env_file.write(f"BIILI_JCT={encrypted_bili_jct}\n")
      env_file.write(f"REFRESH_TOKEN={encrypted_refresh_token}\n")
      print(f"sessdata: {encrypted_sessdata}")
      print(f"bili_jct: {encrypted_bili_jct}")
      print(f"refresh_token: {encrypted_refresh_token}")  
    return encrypted_sessdata, encrypted_bili_jct, encrypted_refresh_token
# ...之前的代码不变

# 在写入 README.md 之前检查变量是否已定义
with open('README.md', 'w') as readme_file:
    readme_file.write(f"sessdata: {sessdata}\n" if sessdata is not None else "sessdata: NOT_DEFINED\n")
    readme_file.write(f"bili_jct: {bili_jct}\n" if bili_jct is not None else "bili_jct: NOT_DEFINED\n")
    readme_file.write(f"refresh_token: {refresh_token}\n" if refresh_token is not None else "refresh_token: NOT_DEFINED\n")
    # 写入加密后的值
    readme_file.write(f"\nEncrypted sessdata: {encrypted_sessdata}\n" if encrypted_sessdata is not None else "Encrypted sessdata: NOT_DEFINED\n")
    readme_file.write(f"Encrypted bili_jct: {encrypted_bili_jct}\n" if encrypted_bili_jct is not None else "Encrypted bili_jct: NOT_DEFINED\n")
    readme_file.write(f"Encrypted refresh_token: {encrypted_refresh_token}\n" if encrypted_refresh_token is not None else "Encrypted refresh_token: NOT_DEFINED\n")
    readme_file.write(f"\n")  # 写入一个空行作为分隔

# ...后续的代码不变
