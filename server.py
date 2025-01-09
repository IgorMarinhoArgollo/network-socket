import socket
import threading
from crypto import encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 12345
NUMERO_DE_CONEXÕES = 5
clients = []
users = {
    "user1": "pass1",
    "user2": "pass2"
}

def validate_login(conn):
    while True:  # Adiciona um loop para permitir tentativas de login
        credentials = conn.recv(1024).decode('utf-8').strip()
        print(f"Credenciais recebidas: {credentials}")  # Log das credenciais

        if ':' in credentials:
            username, password = credentials.split(':', 1)
            if username in users and users[username] == password:
                print('Conectando com o usuário')
                conn.send("true".encode('utf-8'))
                return True
            else:
                conn.send("false".encode('utf-8'))
                print(f"Falha no login para o usuário: {username}")  # Log de falha
        else:
            conn.send("Formato inválido. Tente novamente.".encode('utf-8'))


def handle_client(conn, addr):
    print(f"Nova conexão: {addr}")
    if validate_login(conn):
        clients.append(conn)
    else:
        conn.send("Usuário ou senha inválido".encode('utf-8'))
        conn.close()
        return
    while True:
        try:
            encrypted_message = conn.recv(1024).decode('utf-8')
            if not encrypted_message:
                break

            # Descriptografa a mensagem recebida
            message = decrypt_message(encrypted_message)
            print(f"Mensagem de {addr}: {message}")

            # Reencaminha para outros clientes
            broadcast(message, conn)
        except Exception as e:
            print(f"Erro: {e}")
            clients.remove(conn)
            conn.close()
            break

def broadcast(message, sender_conn):
    encrypted_message = encrypt_message(message)
    for client in clients:
        if client != sender_conn:
            try:
                client.send(encrypted_message.encode('utf-8'))
            except:
                clients.remove(client)
                client.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(NUMERO_DE_CONEXÕES)
    print(f"Servidor escutando em {HOST}:{PORT}")
    print(f"Permitindo: {NUMERO_DE_CONEXÕES} conexões.")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()
