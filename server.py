import socket
import threading
from crypto import encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 12345
NUMERO_DE_CONEXOES = 5
clients = []


def validate_login(conn):
    while True:
        solicitacao = conn.recv(1024).decode('utf-8').strip()
        print(f"Solicitação recebida: {solicitacao}")

        if solicitacao.startswith("login-") and ':' in solicitacao:
            _, user_pass = solicitacao.split('-', 1)
            username, password = user_pass.split(':', 1)
            if any(user[0] == username and user[1] == password for user in usuariosCadastrados.items()):
                print('Conectando com o usuário')
                print(f'Usuário conectado: {username}')
                conn.send("true".encode('utf-8'))
                return True
            else:
                print(solicitacao)
                conn.send("false".encode('utf-8'))
                print(f"Falha no login para o usuário: {username}")
                return False
        elif solicitacao.startswith("cadastro-") and ':' in solicitacao:
            _, user_pass = solicitacao.split('-', 1)
            username, password = user_pass.split(':', 1)
            usuariosCadastrados.append((username, password))
            print("Cadastro realizado com sucesso.")
            conn.send("true".encode('utf-8'))
            return True
        else:
            print("Formato inválido. Tente novamente.")
            conn.send("false".encode('utf-8'))


def handle_client(conn, addr):
    print(f"Nova solicitação de conexão: {addr}")

    if not validate_login(conn):  # Verifica se o login foi bem-sucedido
        conn.send("Usuário ou senha inválido".encode('utf-8'))
        conn.close()
        return
    clients.append(conn)  # Adiciona o cliente apenas após login bem-sucedido
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
            if conn in clients:  # Verifica se a conexão ainda está na lista
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
    global usuariosCadastrados # Declara a variável como global
    usuariosCadastrados = {"user1": "pass1", "user2": "pass2"} # Armazena lista de usuários e senhas

    # cria o socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Associa o socket no endereço e porta
    server.bind((HOST, PORT))
    # Limita número de conexões
    server.listen(NUMERO_DE_CONEXOES)

    print(f"Servidor escutando em {HOST}:{PORT}")
    print(f"Permitindo: {NUMERO_DE_CONEXOES} conexões.")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()
