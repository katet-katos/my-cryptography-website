import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import Blowfish, ChaCha20
from os import urandom

# АЛГОРИТМ AES
def generate_key(size=32):
    return os.urandom(size)

def base64_encode(data):
    return base64.b64encode(data).decode()

def base64_decode(data):
    return base64.b64decode(data.encode())

def encrypt_aes(key, plaintext):
    # Проверяем длину ключа
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid key size for AES. Key must be 16, 24, or 32 bytes long.")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64_encode(iv + ct)

def decrypt_aes(key, ciphertext):
    # Проверяем длину ключа
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid key size for AES. Key must be 16, 24, or 32 bytes long.")

    ciphertext = base64_decode(ciphertext)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

# Пример использования

'''key = generate_key(24)
plaintext = "Hello, World!"
ciphertext = encrypt_aes(key, plaintext)
decrypted_text = decrypt_aes(key, ciphertext)

print("Ключ:", base64_encode(key))
print("Зашифрованный текст:", ciphertext)
print("Расшифрованный текст:", decrypted_text)'''

# АЛГОРИТМ DES


from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def encrypt_des(key, plaintext):
    # Проверяем длину ключа
    if len(key) != 8:
        raise ValueError("Длина ключа DES должна быть 8 байт.")
    
    # Создаем объект шифрования DES
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Добавляем padding к открытому тексту
    padded_plaintext = pad(plaintext.encode(), 8)
    
    # Выполняем шифрование
    ciphertext = cipher.encrypt(padded_plaintext)
    
    #выводим в виде байтового объекта
    return ciphertext

def decrypt_des(key, ciphertext):
    # Проверяем длину ключа
    if len(key) != 8:
        raise ValueError("Длина ключа DES должна быть 8 байт.")
    
    # Создаем объект расшифрования DES
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Выполняем расшифрование
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Удаляем padding
    plaintext = unpad(padded_plaintext, 8).decode()
    
    return plaintext
'''
key = b'MyKey134'
plaintext = "Hello, World!"

ciphertext = encrypt_des(key, plaintext)
print("Зашифрованный текст:", ciphertext)

decrypted_text = decrypt_des(key, ciphertext)
print("Расшифрованный текст:", decrypted_text)'''

#Алгоритмом  Blowfish

def encrypt_blowfish(key, plaintext):
    # Проверяем длину ключа
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Длина ключа Blowfish должна быть от 4 до 56 байт.")
    
    # Создаем объект шифрования Blowfish
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    
    # Добавляем padding к открытому тексту
    padded_plaintext = pad(plaintext.encode(), Blowfish.block_size)
    
    # Выполняем шифрование
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def decrypt_blowfish(key, ciphertext):
    # Проверяем длину ключа
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Длина ключа Blowfish должна быть от 4 до 56 байт.")
    
    # Создаем объект расшифрования Blowfish
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    
    # Выполняем расшифрование
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Удаляем padding
    plaintext = unpad(padded_plaintext, Blowfish.block_size).decode()
    
    return plaintext


'''key = b'MySecretKey1234'
plaintext = "Hello, World!"

ciphertext = encrypt_blowfish(key, plaintext)
print("Зашифрованный текст:", ciphertext)

decrypted_text = decrypt_blowfish(key, ciphertext)
print("Расшифрованный текст:", decrypted_text)'''




def encrypt_chacha20(key, plaintext):
    nonce = urandom(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return nonce + ciphertext

def decrypt_chacha20(key, ciphertext):
    nonce = ciphertext[:12]
    encrypted_data = ciphertext[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(encrypted_data)
    return plaintext


key = b'MySecretKey1234567890abcdef55454'
plaintext = b"Hello, World!"

ciphertext = encrypt_chacha20(key, plaintext)
print("Зашифрованный текст:", ciphertext)

decrypted_text = decrypt_chacha20(key, ciphertext)
print("Расшифрованный текст:", decrypted_text)

def caesar(text, k): #шифр цезаря 
    abc="абвгдежзиклмнопрстуфхцчшщъыьэюя"
    itog = ""
    for j in text:
        a = abc.find(j)
        if a + k > 30:
            itog += abc[abs(31 - (a + k))]
        else:
            itog += abc[a + k]
    return itog

def caesar_dec(text, k): #шифр цезаря 
    abc="абвгдежзиклмнопрстуфхцчшщъыьэюя"
    itog = ""
    for j in text:
        a = abc.find(j)
        if a - k < 0:
            itog += abc[31 + (a - k)]
        else:
            itog += abc[a - k]
    return itog
