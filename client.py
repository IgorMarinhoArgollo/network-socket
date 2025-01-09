import socket
import threading
from crypto import encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 12345

def receive_messages(client):
    while True:
        try:
            encrypted_message = client.recv(1024).decode('utf-8')
            if not encrypted_message:
                break

            # Descriptografa a mensagem recebida
            message = decrypt_message(encrypted_message)
            print(f"Mensagem recebida: {message}")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            client.close()
            break

def login(client):
    print("Digite seu usuário: ")
    user = input().strip()
    print("Digite sua senha: ")
    password = input().strip()
    if user != '' and password != '':
        print("Solicitando conexão ao servidor")
        client.send(f"{user}:{password}".encode('utf-8'))
        result = client.recv(1024).decode('utf-8').strip().lower()
        print(result)
        conected =  result == 'true'
        return conected
    else:
        print('Não foi possível realizar a conexão - verifique o usuário e senha e rode novamente o cliente')
        return False

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))  # Conecte-se ao servidor
    conected = login(client)  # Chame a função login e armazene o resultado
    if conected:
        thread = threading.Thread(target=receive_messages, args=(client,))
        thread.start()

        while True:
            try:
                message = input("Você: ")
                if message.lower() == 'sair':
                    client.close()
                    break
                if not message:  # Verifica se a mensagem não está vazia
                    print("Mensagem não pode ser vazia.")
                    continue

                # Criptografa a mensagem antes de enviar
                encrypted_message = encrypt_message(message)
                client.send(encrypted_message.encode('utf-8'))
            except Exception as e:
                print(f"Erro ao enviar mensagem: {e}")
                client.close()
                break

if __name__ == "__main__":
    main()
