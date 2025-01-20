import socket
import threading
from crypto import encrypt_message, decrypt_message

<<<<<<< Updated upstream
=======
#tese

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

>>>>>>> Stashed changes
HOST = '127.0.0.1'
PORT = 12345
NUMERO_DE_CONEXOES = 5

clients = []  # Lista para gerenciar conexões
clientesConectados = {}  # Dicionário para mapear usuários autenticados às conexões

# Faz o gerenciamento de login
def gerenciadorDeLogin(conn, solicitacao):
  _, user_pass = solicitacao.split('-', 1) # Separa a solicitação no tipo de login + usuárioEpassword
  username, password = user_pass.split(':', 1) # Separa usuárioEpassword em usuário e password
  if username in usuariosCadastrados and usuariosCadastrados[username] == password: # Verifica se o usuário está cadastrado
    print(f"Usuário conectado: {username}")
    conn.send("true".encode('utf-8')) # Envia para o cliente a confirmação de login 
    return username  # Retorna o nome do usuário autenticado
  else:
    print(f"Falha no login para o usuário: {username}")
    conn.send("false".encode('utf-8'))
    return None

# Faz o gerenciamento de cadastro
def gerenciadorDeCadastro(conn, solicitacao):
    _, user_pass = solicitacao.split('-', 1) # Separa a solicitação no tipo de login + usuárioEpassword
    username, password = user_pass.split(':', 1) # Separa usuárioEpassword em usuário e password
    if username not in usuariosCadastrados: # Verifica se já existe usuário cadastrado com esse username
        usuariosCadastrados[username] = password # Adiciona o usuário e senha na lista de usuários
        print("Cadastro realizado com sucesso.")
        conn.send("true".encode('utf-8')) # Envia a confirmação de cadastro para o cliente
        return username
    else:
        print("Usuário já cadastrado.")
        conn.send("false".encode('utf-8'))
        return None

# Validação de login ou cadastro
def gerenciadorDeAutenticacao(conn):
  while True:
    solicitacao = conn.recv(1024).decode('utf-8').strip() # Recebe a solicitação de autenticação
    print(f"Solicitação recebida: {solicitacao}")

    # Verifica se a solicitação é do tipo Login
    if solicitacao.startswith("login-") and ':' in solicitacao:
      return gerenciadorDeLogin(conn, solicitacao)
    
    # Verifica se a solicitação é do tipo Cadastro
    elif solicitacao.startswith("cadastro-") and ':' in solicitacao:
      return gerenciadorDeCadastro(conn, solicitacao)
    
    else:
      print("Formato inválido. Tente novamente.")
      conn.send("false".encode('utf-8'))

# Envio de mensagens privadas
def mensagemPrivada(remetente, destinatario, mensagem, conn):
    try:
        if destinatario in clientesConectados: # Verifica se o destinatário está conectado
          destinatario_conn = clientesConectados[destinatario] # Armazena o destinatário
          
          # Re-criptografa a mensagem
          encrypted_message = encrypt_message(f"{remetente}: {mensagem}")
          # Envia para o destinatário específico
          destinatario_conn.send(encrypted_message.encode('utf-8'))

        else:
          conn.send(f"Erro: O usuário '{destinatario}' não está conectado.".encode('utf-8'))
    except Exception as e:
      print(f"Erro ao enviar mensagem privada: {e}")
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
  print(f"Nova solicitação de conexão: {addr}")
  username = gerenciadorDeAutenticacao(conn)

  if not username:
    conn.send("Usuário ou senha inválido".encode('utf-8'))
    conn.close()
    return

  clientesConectados[username] = conn  # Mapeia o usuário autenticado à conexão
  clients.append(conn)  # Adiciona o cliente à lista global

  while True:
    try:
      encrypted_message = conn.recv(1024).decode('utf-8') # Recebe um conteúdo criptografada
      if not encrypted_message: # verifica se a mensagem está realmente criptografada
        break

      message = decrypt_message(encrypted_message) # Decriptografa o conteúdo para obter dados tipo de envio, remetente, destinatário e conteúdo da mensagem ou arquivo
      print(f"Mensagem de {addr}: {message}")

      # Divisão segura da mensagem
      parts = message.split('-', 1)
      if len(parts) != 2:
        print("Mensagem malformada. Ignorando...")
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
        print(f"Tipo de mensagem desconhecido: {tipoDeMensagem}")

    except Exception as e:
      print(f"Erro: {e}")
      if conn in clients:
          clients.remove(conn)
      if username in clientesConectados:
          del clientesConectados[username]
      conn.close()
      break


# Função principal
def main():
    global usuariosCadastrados
    usuariosCadastrados = {
        'user1': 'pass1',
        'user2': 'pass2',
        'user3': 'pass3'
    }

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(NUMERO_DE_CONEXOES)

    print(f"Servidor escutando em {HOST}:{PORT}")
    print(f"Permitindo: {NUMERO_DE_CONEXOES} conexões.")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=gerenciadorDeCliente, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()
