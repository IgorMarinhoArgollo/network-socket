import socket
import getpass
import logging
import threading
from crypto import encrypt_message, decrypt_message

# Recebe o user atual
username = getpass.getuser()

# Configurações de logging
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] [{username}]: %(message)s",
)

HOST = '127.0.0.1'
PORT = 1234

def receberMensagem(cliente):
    while True:
      try:
        encrypted_message = cliente.recv(1024).decode('utf-8') # Recebe mensagem criptografada
        if not encrypted_message: # Verifica se a mensagem está realmente criptografada
          break

        # Decriptografa a mensagem recebida
        message = decrypt_message(encrypted_message)
        print(f"{message}")
          
      except Exception as e:
        print(f"Erro ao receber mensagem: {e}")
        cliente.close()
        break

def cadastro(cliente):
  usuario = input("Digite seu usuário: ").strip()  # Captura o usuário
  senha = input("Digite sua senha: ").strip()  # Captura a senha
  # encrypted_data = encrypt_message(f"cadastrar-{username}-{password}")

  if usuario and senha:
      # Envia os dados de Cadastro para o servidor
      cliente.send(f"cadastro-{usuario}-{senha}".encode("utf-8"))
      # Recebe resposta do servidor
      result = cliente.recv(1024).decode("utf-8").strip().lower()
      if result == "true":
          logging.info(f"Cadastro do usuário '{usuario}' efetuado.")
      else:
          logging.error("Erro ao efetuar cadastro.")
  else:
      logging.error(
          "Não foi possível realizar a conexão - verifique o usuário e senha."
      )

def login(cliente):
  usuario = input("Digite seu usuário: ").strip()  # Captura o usuário
  password = input("Digite sua senha: ").strip()  # Captura a senha

  if usuario and password:
      logging.info("Solicitando login ao servidor.")
      cliente.send(f"login-{usuario}-{password}".encode("utf-8"))
      result = cliente.recv(1024).decode("utf-8").strip().lower()
      connected = True if result == "true" else False
      if connected:
          logging.info("Login efetuado!")
      return connected
  else:
      logging.error(
          "Não foi possível realizar a conexão - verifique o usuário e senha"
      )

def enviarMensagemPrivada(cliente):
  destinatario = input("Digite o destinatario da mensagem:\n").strip() # Captura o destinatário
  print('Digite sua mensagem:')
  message = input(f"{usuario}: ") # Captura a mensagem
  if not message:  # Verifica se a mensagem não está vazia
    logging.error("Mensagem não pode ser vazia.")
    return
  encrypted_message = encrypt_message(f'privada-{usuario}:{destinatario}-{message}') # Criptografa a mensagem antes de enviar
  cliente.send(encrypted_message.encode('utf-8')) # Envia a mensagem para o servidor

def enviarMensagemMulticast(cliente):
  print('Digite sua mensagem:\n')
  message = input(f"{usuario}: ") # Captura a mensagem
  if not message:  # Verifica se a mensagem não está vazia
    logging.error("Mensagem não pode ser vazia.")
    return
  encrypted_message = encrypt_message(f'multicast-{usuario}:{message}') # Criptografa a mensagem antes de enviar
  cliente.send(encrypted_message.encode('utf-8'))  # Envia a mensagem para o servidor

def enviarArquivo(cliente):
    destinatario = input("Digite o destinatario do arquivo:\n").strip()
    print('Escolha o arquivo:\n')
    # encrypted_message = encrypt_message(f'arquivo-{usuario}:{destinatario}-{file_data}')
    # cliente.send(encrypted_message.encode('utf-8'))

def main():
    global connected  # Declara a variável como global
    global usuario    # Declara a variável como global
    connected = 'false'  # Inicializa a variável de controle
    usuario = ''  # Inicializa a variável usuario

    # cria o socket
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conecte-se ao servidor
    cliente.connect((HOST, PORT))
    
    # loop para login ou cadastro
    print("Caso deseje fazer o Login, digite 'login', caso deseje se cadastrar digite 'cadastro'\n")
    while connected == 'false':
      tipoDeLogin = input().strip() # Captura o tipo de autenticação
      if tipoDeLogin == 'cadastro':
        connected = cadastro(cliente)
              
      if tipoDeLogin == 'login':
        connected = login(cliente)

    # Conexão com o socket do server
    if connected:
      thread = threading.Thread(target=receberMensagem, args=(cliente,)) # Habilita o conexão com o servidor, caso conectado
      thread.start()

      # Loop para escolha de tipo de mensagem, destinatário e input de mensagem
      print("Digite o tipo de mensagem a ser enviada (privada, multicast, arquivo) ou 'sair' para encerrar:\n")
      while True:
        try:
          tipoDeMensagem = input().strip()
          
          # Processamento de envio de mensagens privadas
          if tipoDeMensagem == 'privada':
            enviarMensagemPrivada(cliente)
              
          # Processamento de envio de mensagens multicast
          if tipoDeMensagem == 'multicast':
            enviarMensagemMulticast(cliente)
          
          # Processamento de envio arquivo para destinatário único
          if tipoDeMensagem == 'arquivo':
            enviarArquivo(cliente)
          
          # Encerramento de conexão
          if tipoDeMensagem.lower() == 'sair':
            cliente.close()
            return
              
        except Exception as e:
          print(f"Algo deu errado: {e}")
          cliente.close()
          break

if __name__ == "__main__":
    main()
