from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from werkzeug.security import check_password_hash
import os
import base64

# Convertendo a chave hexadecimal para bytes
SECRET_KEY = bytes.fromhex("457462fc5014cc11c6ede3e3bae5adee4a46908a36050b995d0850d4f27241a6")

#Criptografa uma mensagem.
def encrypt_message(message: str) -> str:
    # Verifica se a chave tem tamanho válido
    if len(SECRET_KEY) not in [16, 24, 32]:  
        raise ValueError("Tamanho da chave inválido para AES. Deve ser 16, 24 ou 32 bytes.")
    
    # Gera um vetor de inicialização (IV) único para cada mensagem - usado para o (Cipher Block Chaining)
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Adiciona padding à mensagem para se ajustar ao tamanho do bloco
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Criptografa a mensagem
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Retorna o IV + mensagem criptografada como uma string codificada em base64
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

#Descriptografa uma mensagem criptografada.
def decrypt_message(encrypted_message: str) -> str:
    encrypted_data = base64.b64decode(encrypted_message)

    # Extrai o IV e os dados criptografados
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Descriptografa e remove o padding
    padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode('utf-8')


def verifyPassword(username, password, usuariosCadastrados):
    return check_password_hash(usuariosCadastrados.get(username, ''), password)


def sendFile(client, user):
    receiver = input("Digite o nome de usuário de destino do arquivo:\n").strip()
    path = input("Digite o caminho do arquivo:\n").strip()
    try:
        with open(path, 'rb') as f:
            conteudo = f.read()
        conteudo_codificado = base64.b64encode(conteudo).decode('utf-8')
        encrypted_message = encrypt_message(f'arquivo-{user}:{receiver}-{conteudo_codificado}')
        client.send(encrypted_message.encode('utf-8'))
        print("Arquivo enviado com sucesso.")
    except Exception as e:
        print(f"Erro ao enviar arquivo {e}")
