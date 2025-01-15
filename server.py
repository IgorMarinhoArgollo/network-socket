import socket
import threading
import getpass
import logging
from crypto import encrypt_message, decrypt_message, verifyPassword
from werkzeug.security import generate_password_hash, check_password_hash

# Recebe o user atual
username = getpass.getuser()

# Configurações de logging
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] [{username}]: %(message)s",
)

HOST = '127.0.0.1'
PORT = 1234
NUMERO_DE_CONEXOES = 5

clients = []  # Lista para gerenciar conexões
credenciais = {}  # Dicionário para mapear usuários autenticados às conexões

# Faz o gerenciamento de login
def gerenciadorDeLogin(conn, solicitacao):
  username = solicitacao[1]
  password = solicitacao[2]

  # Verifica se já existe usuário cadastrado com esse username
  if username in credenciais and credenciais[username] == password:
    # Adiciona o usuário e senha na lista de usuários
    logging.info(f"Usuário autenticado: {username}")
    conn.send(
        "true".encode("utf-8")
    )  # Envia para o cliente a confirmação de login
    return username  # Retorna o nome do usuário autenticado
  else:
      logging.error(f"Falha no login para o usuário: {username}.")
      conn.send("false".encode("utf-8"))
      return None

# Faz o gerenciamento de cadastro
def gerenciadorDeCadastro(conn, solicitacao):
  username = solicitacao[1]
  password = solicitacao[2]

  # Verifica se já existe usuário cadastrado com esse username
  if username not in credenciais:
      # Adiciona o usuário e senha na lista de usuários
      credenciais[username] = password
      logging.info("Cadastro realizado com sucesso.")
      conn.send("true".encode("utf-8"))
      return username
  else:
      logging.info("Usuário já cadastrado.")
      conn.send("false".encode("utf-8"))
      return None

# Validação de login ou cadastro
def gerenciadorDeAutenticacao(conn):
  try:
    while True:
      # Recebe a solicitação de autenticação
      # A solicitação é no formato "FUNCAO-USER-PASSWORD"
      solicitacao = conn.recv(1024).decode("utf-8").split("-")
      logging.info(f"Solicitação recebida: {solicitacao}")

      # Verifica se a solicitação é do tipo login
      if solicitacao[0] == "login":
          return gerenciadorDeLogin(conn, solicitacao)

      # Verifica se a solicitação é do tipo cadastro
      elif solicitacao[0] == "cadastro":
          return gerenciadorDeCadastro(conn, solicitacao)

      else:
          logging.error("Entrada inválida. Tente novamente.")
          conn.send("false".encode("utf-8"))

  except BrokenPipeError:
      logging.warning(f"Conexão perdida (BrokenPipeError).")
      clients.remove(conn)
      conn.close()

  except Exception as e:
      logging.error(f"Erro ao gerenciar a conexão: {e}")
      clients.remove(conn)
      conn.close()

# Envio de mensagens privadas
def mensagemPrivada(remetente, destinatario, mensagem, conn):
    try:
        if destinatario in credenciais: # Verifica se o destinatário está conectado
          destinatario_conn = credenciais[destinatario] # Armazena o destinatário
          
          # Re-criptografa a mensagem
          encrypted_message = encrypt_message(f"{remetente}: {mensagem}")
          # Envia para o destinatário específico
          destinatario_conn.send(encrypted_message.encode('utf-8'))

        else:
          conn.send(f"Erro: O usuário '{destinatario}' não está conectado.".encode('utf-8'))
    except Exception as e:
      logging.error(f"Erro ao enviar mensagem privada: {e}")
      conn.send(f"Erro ao enviar mensagem para {destinatario}.".encode('utf-8'))

# Envio de mensagens multicast
def multicast(remetente, mensagem, conn):
    encrypted_message = encrypt_message(f"{remetente}:{mensagem}") # Re-criptografa a mensagem
    for client in clients:
      if client != conn:
        try:
          client.send(encrypted_message.encode('utf-8')) # Envia a mensagem no formato multicast
        except:
          clients.remove(client)
          client.close()

# Gerenciador de cliente
def gerenciadorDeCliente(conn, addr):
  logging.info(f"Nova solicitação de conexão: {addr}")
  username = gerenciadorDeAutenticacao(conn)

  if not username:
    conn.send("Usuário ou senha inválido".encode('utf-8'))
    conn.close()
    return

  credenciais[username] = conn  # Mapeia o usuário autenticado à conexão
  clients.append(conn)  # Adiciona o cliente à lista global

  while True:
    try:
      encrypted_message = conn.recv(1024).decode('utf-8') # Recebe um conteúdo criptografada
      if not encrypted_message: # verifica se a mensagem está realmente criptografada
        break

      message = decrypt_message(encrypted_message) # Decriptografa o conteúdo para obter dados tipo de envio, remetente, destinatário e conteúdo da mensagem ou arquivo
      logging.info(f"Mensagem de {addr}: {message}")

      # Divisão segura da mensagem
      parts = message.split('-', 1)
      if len(parts) != 2:
        logging.info("Mensagem malformada. Ignorando...")
        continue

      tipoDeMensagem, mensagemCompleta = parts

      # Verifica o tipo de mensagem - multicast
      if tipoDeMensagem == 'multicast':
        remetente, mensagem = mensagemCompleta.split(':', 1)
        multicast(remetente, mensagem, conn)

      # Verifica o tipo de mensagem - privado
      elif tipoDeMensagem == 'privada':
        remetente, destinatarioEMensagem = mensagemCompleta.split(':', 1)
        destinatario, mensagem = destinatarioEMensagem.split('-', 1)
        mensagemPrivada(remetente, destinatario, mensagem, conn)

      # Verifica o tipo de mensagem - arquivo
      elif tipoDeMensagem == 'arquivo':
         # para implementar
         break

      else:
        logging.info(f"Tipo de mensagem desconhecido: {tipoDeMensagem}")

    except Exception as e:
      logging.error(f"Erro: {e}")
      if conn in clients:
          clients.remove(conn)
      if username in credenciais:
          del credenciais[username]
      conn.close()
      break


# Função principal
def main():
    global usuariosCadastrados
    usuariosCadastrados = {
        'user1': generate_password_hash('pass1'),
        'user2': generate_password_hash('pass2'),
        'user3': generate_password_hash('pass3')
    }

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(NUMERO_DE_CONEXOES)

    logging.info(f"Server ouvindo em {HOST}:{PORT}.")
    logging.info(f"Permitindo {NUMERO_DE_CONEXOES} conexões.")

    try:
      while True:
          # Verifica conexões disponíveis
          if len(clients) < NUMERO_DE_CONEXOES:
              conn, addr = (
                  server.accept()
              )  # Aguarda até conexão ser estabelecida
              clients.append(conn)  # Adiciona o client na lista controlada

              threading.Thread(
                  target=gerenciadorDeAutenticacao, args=(conn,)
              ).start()
              logging.info(
                  f"Nova conexão estabelecida no endereço {addr}. {NUMERO_DE_CONEXOES - len(clients)} conexões restantes."
              )
          else:
              logging.warning(
                  "Limite de conexões atingido. Aguardando conexões livres."
              )
    except KeyboardInterrupt:
        logging.info("Encerrando o servidor.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
