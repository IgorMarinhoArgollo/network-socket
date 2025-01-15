import socket
import threading
import pickle
import logging
import getpass
from crypto import encrypt_message, decrypt_message

# Recebe o user atual
log_user = getpass.getuser()

# Configurações de logging
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] [{log_user}]: %(message)s",
)

credenciais = {} # Salva as credenciais dos usuários cadastrados
clients = [] # Controla o número de conexões
authenticated_clients = {} # Controla os clientes autenticados

HOST = '127.0.0.1'
PORT = 12345
NUMERO_DE_CONEXOES = 5

def handle_auth(client_socket: socket, addr):
  while True:
    try:
        client_socket.send(b"Bem vindo! Digite 'login' ou 'cadastro': ")

        try:
          option, username, password = client_socket.recv(1024).decode('utf-8').split("-") # TODO: Decriptografar

        except Exception as e: # Geralmente em caso de desconexao do client
          logging.error("Erro ao receber opção de autenticação: {e}")
          clients.remove(client_socket)
          client_socket.close()
          return

        if option == 'cadastro':
            if username in credenciais:
                client_socket.send(b"USERTAKEN") 
                logging.info(f"Usuário {username} já possui cadastro")
                continue
            else:
                credenciais[username] = password # Adiciona as credenciais à lista
                logging.info(f"Novo usuário cadastrado: {username}")
                client_socket.send(b"SUCCESSCAD")
                continue

        elif option == 'login':
            if username in credenciais and credenciais[username] == password:
                logging.info(f"Novo usuário autenticado: {username}")
                authenticated_clients[username] = client_socket
                client_socket.send(b"SUCCESSLOG")
                handle_client(client_socket, username)
            else:
                client_socket.send(b"INVALIDCREDENTIALS")
        
        else:
            client_socket.send(b"Invalid option. Disconnecting.\n")
    
    except BrokenPipeError:
      logging.warning(f"Perda de conexão com client: {addr}")
      clients.remove(client_socket)
      client_socket.close()
      return 

    except Exception as e:
      print(f"Error: {e}")

def handle_client(client_socket: socket, username: str):
  while True:
    try:
        message = client_socket.recv(1024).decode('utf-8').split("-") # TODO: Criptografar 

        if message[0] == "privada":
          sender, recipient, text = message[1:]

          if recipient in authenticated_clients:
            recipient_socket = authenticated_clients[recipient]
            recipient_socket.send(f"{sender}: {text}".encode('utf-8'))

    except Exception as e:
      logging.error(e)
      break


def handle_messages(client_socket, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                recipient, msg_content = message.split("-", 1)
                if recipient in authenticated_clients:
                    recipient_socket = authenticated_clients[recipient]
                    recipient_socket.send(f"{username}: {msg_content}".encode('utf-8'))
                else:
                    client_socket.send(b"Recipient not found.")
        except (ConnectionResetError, BrokenPipeError):
            break
        except Exception as e:
            logging.error(f"Error: {e}")
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    logging.info(f"Server ouvindo em {HOST}:{PORT}")
    logging.info(f"Permitindo {NUMERO_DE_CONEXOES} conexões")

    try:
      while True:
          # Verifica conexões disponíveis
          if len(clients) < NUMERO_DE_CONEXOES:
            client_socket, addr = server.accept()
            logging.info(f"Conexão aceita de {addr}")
            clients.append(client_socket)

            client_handler = threading.Thread(target=handle_auth, args=(client_socket, addr))
            client_handler.start()
          else:
            logging.warning(
                "Limite de conexões atingido. Aguardando conexões livres."
            )
    except KeyboardInterrupt:
        logging.info("Encerrando o servidor.")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()
