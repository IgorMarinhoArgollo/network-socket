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
PORT = 12345

def autenticar(client: socket) -> str:
    while True:
      try:
        welcome_message = client.recv(1024).decode('utf-8')
        option = input(welcome_message).lower()

        if option != "login" and option != "cadastro":
            logging.warning("Opção inválida. Tente novamente.")
            continue
        
        user = input("Digite seu usuário: ").strip()
        password = input("Digite sua senha: ").strip()

        message = f"{option}-{user}-{password}"
        client.send(message.encode('utf-8')) # TODO: Criptografar

        response = client.recv(1024).decode('utf-8') # Possiveis respostas: USERTAKEN e SUCCESS

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

def receberMensagens(client: socket):
  while True:
    try:
        message = client.recv(1024).decode('utf-8') # TODO: Decriptografar
        print(message)

    except Exception as e:
        logging.error(f"Erro ao receber mensagem: {e}")
        client.close()
        break

def enviarPrivada(client: socket, user: str):
  recipient = input("Digite o destinatário da mensagem: ").strip() 
  text = input("Digite a mensagem: ")

  if not text:
     logging.error("A mensagem não pode ser vazia!")
     return
  
  message = f'privada-{user}-{recipient}-{text}'
  client.send(message.encode('utf-8'))

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    user = autenticar(client)

    # Inicia thread para recebimento de mensagens 
    threading.Thread(target=receberMensagens, args=(client,)).start() 

    # Loop para escolha de tipo de mensagem, destinatário e input de mensagem
    while True:
      try:
        option = input("Digite o tipo de mensagem a ser enviada ('privada', 'multicast', 'arquivo') ou 'sair': ").strip()
        
        # Processamento de envio de mensagens privadas
        if option.lower() == 'privada':
          enviarPrivada(client, user)
            
        # Processamento de envio de mensagens multicast
        if option.lower() == 'multicast':
          # enviarMensagemMulticast(cliente)
          pass
        
        # Processamento de envio arquivo para destinatário único
        if option.lower() == 'arquivo':
          # enviarArquivo(cliente)
          pass
        
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
