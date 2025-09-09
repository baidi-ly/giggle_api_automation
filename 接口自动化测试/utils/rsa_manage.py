import base64
import os

import rsa


def password_rsa(password):
    base_dir = os.getcwd()
    base_dir = str(base_dir).split("test_case")[0].split("test_data")[0]
    base = base_dir + '/test_data'
    with open(base + '/rsa_pub.pem', 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(f.read().encode())
    message = password
    message = message.encode()
    cryptedMessage = rsa.encrypt(message, pubkey)
    cryptedMessage = base64.encodebytes(cryptedMessage)
    return str(cryptedMessage).replace("\\n","").replace("b'","").replace("'","")


def password_base64(password):
    # 将文本转换为字节（Base64 编码是针对字节的）
    password_bytes = password.encode('utf-8')
    # 使用 base64 编码
    encoded_bytes = base64.b64encode(password_bytes)
    # 将编码后的字节转换回字符串
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string