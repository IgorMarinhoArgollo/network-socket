import os
import tqdm
import socket
import getpass
import logging
import threading
from crypto import encrypt_message, decrypt_message

# Recebe o user atual
log_user = getpass.getuser()

# Configurações de logging
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] [{log_user}]: %(message)s",
)

HOST = '127.0.0.1'
PORT = 1234

def autenticar(client: socket) -> str:
    while True:
      try:
        encrypted_welcome_message = client.recv(1024).decode('utf-8')
        welcome_message = decrypt_message(encrypted_welcome_message)
        option = input(welcome_message).lower()

        if option != "login" and option != "cadastro":
            logging.warning("Opção inválida. Tente novamente.")
            continue
        
        user = input("Digite seu usuário: ").strip()
        password = input("Digite sua senha: ").strip()

        message = f"{option}-{user}-{password}"
        encrypted_message = encrypt_message(message)
        client.send(encrypted_message.encode('utf-8'))


        encrypted_response = client.recv(1024).decode('utf-8') # Possiveis respostas: USERTAKEN e SUCCESS
        response = decrypt_message(encrypted_response)

        # --- Respostas para CADASTRO ---
        if response == "USERTAKEN":
            logging.error("Usuário já existe! Tente novamente") 
            continue

        elif response == "SUCCESSCAD":
            logging.info("Usuário cadastrado com sucesso!")
            continue
        
        # --- Respostas para LOGIN ---
        elif response == "INVALIDCREDENTIALS":
            logging.error("Credenciais inválidas! Tente novamente")
            continue

        elif response == "SUCCESSLOG":
            logging.info("Usuário autenticado com sucesso!")
            return user

        # --- DEFAULT ---
        else:
            raise Exception("Resposta inesperada do servidor durante autenticação.")
      
      except KeyboardInterrupt:
        client.close()
        break

######################################################

def receberMensagens(client: socket):
  while True:
    try:
      encrypted_message = client.recv(1024).decode('utf-8')
      message = decrypt_message(encrypted_message)
      print("\n", message, "\n")

    except Exception as e:
        logging.error(f"Erro ao receber mensagem: {e}")
        client.close()
        break

def receberArquivos(client: socket):
  while True:
    try:
        message = client.recv(1024).decode('utf-8')
        try:
          decrypted_message = decrypt_message(message)
          print("\n", decrypted_message, "\n")
        except:
          print("\n", message, "\n")

    except Exception as e:
        logging.error(f"Erro ao receber mensagem: {e}")
        client.close()
        break

def enviarPrivada(client: socket, user: str):
  recipient = input("Digite o destinatário da mensagem: ").strip() 
  text = input("Digite a mensagem: ")

  if not text:
     logging.error("A mensagem não pode ser vazia")
     return
  
  message = f'privada-{user}-{recipient}-{text}'
  encrypted_message = encrypt_message(message)
  client.send(encrypted_message.encode('utf-8'))

  encrypted_response = client.recv(1024).decode('utf-8') # Possiveis respostas: INVALID e SUCCESS
  response = decrypt_message(encrypted_response)


  if response == "SUCCESS":
     logging.info("Mensagem enviada com sucesso")
  elif response == "INVALID":
     logging.error("Destinatário não encontrado. Tente novamente")

def enviarMulticast(client: socket, user: str):
  text = input("Digite a mensagem: ")

  if not text:
     logging.error("A mensagem não pode ser vazia")
     return
  
  message = f'multicast-{user}-{text}'
  encrypted_message = encrypt_message(message)
  client.send(encrypted_message.encode('utf-8'))

  encrypted_response = client.recv(1024).decode('utf-8') # Possiveis respostas: FAIL e SUCCESS
  response = decrypt_message(encrypted_response) 

  if response == "SUCCESS":
     logging.info("Mensagem enviada com sucesso")
  elif response == "FAIL":
     logging.error("Erro ao enviar mensagem. Tente novamente")

def enviarArquivo(client: socket, user:str):
  recipient = input("Digite o destinatário da mensagem: ").strip() 
  filename = input("Digite o caminho do arquivo: ").strip()

  if not os.path.exists(filename):
     logging.error("O caminho para o arquivo não existe")
     return

  with open(filename, "rb") as file:
      file_name = filename.split("/")[-1]  # Extrai o nome
      file_size = len(file.read())  # Tamanho do arquivo
      file.seek(0)  # Reseta o arquivo para o inicio

      # Envia o nome do arquivo e tamanho primeiro
      decrypted_message = f'arquivo-{user}-{recipient}-{file_name}-{file_size}'
      message=encrypt_message(decrypted_message)

      client.send(message.encode("utf-8"))
      response = client.recv(1024).decode('utf-8')

      """ if response != "READY":
          logging.error("Server não está pronto para receber o arquivo")
          return """

      # Send the file in chunks
      logging.info(f"Enviando arquivo {file_name}...")
      with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Sending {file_name}") as pbar:
        chunk = file.read(1024)  # Envia 1KB por batch
        while chunk:
            client.send(chunk)
            pbar.update(len(chunk))  # Barra de progresso
            chunk = file.read(1024)
      server_ack = client.recv(1024).decode('utf-8')
      logging.info(server_ack)  

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    user = autenticar(client)

    # Inicia thread para recebimento de mensagens 
    threading.Thread(target=receberMensagens, args=(client,)).start() 

    # Inicia thread para recebimento de arquivos
    threading.Thread(target=receberArquivos, args=(client,)).start() 

    # Loop para escolha de tipo de mensagem, destinatário e input de mensagem
    while True:
      try:
        option = input("Digite o tipo de mensagem a ser enviada ('privada', 'multicast', 'arquivo') ou 'sair': ").strip()
        
        # Processamento de envio de mensagens privadas
        if option.lower() == 'privada':
          enviarPrivada(client, user)
            
        # Processamento de envio de mensagens multicast
        if option.lower() == 'multicast':
          enviarMulticast(client, user)
        
        # Processamento de envio arquivo para destinatário único
        if option.lower() == 'arquivo':
          enviarArquivo(client, user)
        
        # Encerramento de conexão
        if option.lower() == 'sair':
          client.close()
          return
            
      except Exception as e:
        logging.error(e)
        client.close()
        break

if __name__ == "__main__":
    start_client()
