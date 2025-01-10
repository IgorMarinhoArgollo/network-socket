import socket
import threading
from crypto import encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 12345

def receberMensagem(cliente):
    while True:
        try:
            encrypted_message = cliente.recv(1024).decode('utf-8')
            if not encrypted_message:
                break

            # Descriptografa a mensagem recebida
            message = decrypt_message(encrypted_message)
            print(f"Mensagem recebida: {message}")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            cliente.close()
            break

def login(cliente):
    global usuario  # Declara a variável como global
    global connected  # Declara a variável como global
    while connected == 'false':
        usuario = input("Digite seu usuário:\n").strip()
        password = input("Digite sua senha:\n").strip()
        if usuario != '' and password != '':
            print("Solicitando conexão ao servidor\n")
            cliente.send(f"login-{usuario}:{password}".encode('utf-8'))
            result = cliente.recv(1024).decode('utf-8').strip().lower()
            connected = result == 'true'
            if connected:
                print('Usuário conectado')
            return connected
        else:
            print('Não foi possível realizar a conexão - verifique o usuário e senha')
            break

def cadastro(cliente):
    global usuario  # Declara a variável como global
    global connected  # Declara a variável como global
    while connected == 'false':
        usuario = input("Digite seu usuário: ").strip()
        password = input("Digite sua senha: ").strip()
        if usuario != '' and password != '':
            print("Solicitando conexão ao servidor\n")
            cliente.send(f"cadastro-{usuario}:{password}".encode('utf-8'))
            result = cliente.recv(1024).decode('utf-8').strip().lower()
            print(result)
            connected = result == 'true'
            return connected
        else:
            print('Não foi possível realizar a conexão - verifique o usuário e senha')
            break

def enviarMensagemPrivada(cliente):
    destinatario = input("Digite o destinatario da mensagem:\n").strip()
    print('Digite sua mensagem:')
    message = input(f"{usuario}: ")
    if not message:  # Verifica se a mensagem não está vazia
        print("Mensagem não pode ser vazia.")
        return
    # Criptografa a mensagem antes de enviar
    encrypted_message = encrypt_message(f'privada-{usuario}:{destinatario}-{message}')
    cliente.send(encrypted_message.encode('utf-8'))

def enviarMensagemMulticast(cliente):
    print('Digite sua mensagem:\n')
    message = input(f"{usuario}: ")
    if not message:  # Verifica se a mensagem não está vazia
        print("Mensagem não pode ser vazia.")
        return

    # Criptografa a mensagem antes de enviar
    encrypted_message = encrypt_message(f'multicast-{usuario}:{message}')
    cliente.send(encrypted_message.encode('utf-8'))

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
    while connected == 'false':
        tipoDeLogin = input("Caso deseje fazer o Login, digite 'login', caso deseje se cadastrar digite 'cadastro'\n").strip()
        if tipoDeLogin == 'cadastro':
          connected = cadastro(cliente)
               
        if tipoDeLogin == 'login':
          connected = login(cliente)

    # Conexão com o socket do server
    if connected:
        thread = threading.Thread(target=receberMensagem, args=(cliente,))
        thread.start()

        # Loop para escolha de tipo de mensagem, destinatário e input de mensagem
        while True:
            try:
                tipoDeMensagem = input("Digite o tipo de mensagem a ser enviada (privada, multicast, arquivo) ou 'sair' para encerrar:\n").strip()
                
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
