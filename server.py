import socket
import tqdm
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
PORT = 1234
NUMERO_DE_CONEXOES = 5

def handle_auth(client_socket: socket, addr):
  while True:
    try:
        encrypted_welcome = encrypt_message("Bem vindo! Digite 'login' ou 'cadastro': ")
        client_socket.send(encrypted_welcome.encode('utf-8'))

        try:
          decrypted_message = decrypt_message(client_socket.recv(1024).decode('utf-8'))
          option, username, password = decrypted_message.split("-") 

        except Exception as e: # Geralmente em caso de desconexao do client
          logging.error("Erro ao receber opção de autenticação: {e}")
          clients.remove(client_socket)
          client_socket.close()
          return

        if option == 'cadastro':
            if username in credenciais:
                encrypted_response = encrypt_message("USERTAKEN")
                client_socket.send(encrypted_response.encode('utf-8'))
                logging.info(f"Usuário {username} já possui cadastro")
                continue
            else:
                credenciais[username] = password # Adiciona as credenciais à lista
                logging.info(f"Novo usuário cadastrado: {username}")
                encrypted_response = encrypt_message("SUCCESSCAD") 
                client_socket.send(encrypted_response.encode('utf-8'))
                continue

        elif option == 'login':
            if username in credenciais and credenciais[username] == password:
                logging.info(f"Novo usuário autenticado: {username}")
                authenticated_clients[username] = client_socket
                encrypted_response = encrypt_message("SUCCESSLOG")
                client_socket.send(encrypted_response.encode('utf-8'))
                handle_client(client_socket, username)
            else:
                encrypted_response = encrypt_message("INVALIDCREDENTIALS")
                client_socket.send(encrypted_response.encode('utf-8'))
        
        else:
          encrypted_response = encrypt_message("Invalid option. Disconnecting.")
          client_socket.send(encrypted_response.encode('utf-8'))
    
    except BrokenPipeError:
      logging.warning(f"Perda de conexão com client: {addr}")
      clients.remove(client_socket)
      client_socket.close()
      return 

    except Exception as e:
      print(f"Error: {e}")

######################################################################################3

def handle_client(client_socket: socket, username: str):
  while True:
    try:
        message = client_socket.recv(1024).decode('utf-8').split("-") # TODO: Criptografar 

        if message[0] == "privada":
          sender, recipient, text = message[1:]

          if recipient in authenticated_clients:
            recipient_socket = authenticated_clients[recipient]
            recipient_socket.send(f"{sender}: {text}".encode('utf-8'))
            client_socket.send(b"SUCCESS")
            logging.info(f"Mensagem privada enviada de {sender} para {recipient} com sucesso")
          else:
            client_socket.send(b"INVALID")
        
        if message[0] == "multicast":
          sender, text = message[1:]

          for user in authenticated_clients:
            _success = True # Controla se todos os usuários receberam a mensagem
            if user != sender:
              try:
                recipient_socket = authenticated_clients[user]
                recipient_socket.send(f"{sender}: {text}".encode('utf-8'))
              except:
                logging.error(f"Falha ao enviar multicast para user: {user}")
                _success = False

          if _success:
            client_socket.send(b"SUCCESS")
            logging.info(f"Mensagem multicast de {sender} enviada com sucesso")
          else:
            client_socket.send(b"FAIL")

        if message[0] == "arquivo":
          sender, recipient, filename, file_size = message[1:]
          file_size = int(file_size)

          if recipient in authenticated_clients:
            client_socket.send(b"READY")

            # Open a file to save the incoming data
            with open(f"received_{filename}", "wb") as file:
                logging.info(f"Recebendo arquivo {filename} de {sender} ...")
                received = 0
                with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Receiving {filename}") as pbar:
                  while received < file_size:
                      file_data = client_socket.recv(1024)
                      file.write(file_data)
                      received += len(file_data)
                      pbar.update(len(file_data))

            # Send acknowledgment after the file is received
            client_socket.send(b"File received successfully.")
            logging.info(f"File {filename} received successfully.")

            # recipient_socket = authenticated_clients[recipient]
            # recipient_socket.send(f"{sender}-{file_name}-{file_size}".encode('utf-8'))
          else:
            client_socket.send(f"Destinatário não está autenticado".encode("utf-8"))

    except Exception as e:
      logging.error(e)
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
    credenciais = {
        'user1': '123',
        'user2': '123',
        'user3': '123'
    }
    start_server()
