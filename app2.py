from flask import Flask, request, jsonify
import requests
import threading
import time
from datetime import datetime
import json
import sys 
import os 

# Adiciona o diretório pai (rsa) ao sys.path para encontrar rsa_lib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from rsa_lib import generate_keypair, encrypt, decrypt # Importa da sua lib

app = Flask(__name__)

# --- Configurações ---
MY_PORT = 5001
PEER_PORT = 5000
PEER_URL = f'http://localhost:{PEER_PORT}'
USERNAME = "Bob"
PEER_USERNAME = "Alice"
LOG_FILE = f"{USERNAME.lower()}_chat.log"

# Primos para a chave de Bob (devem ser diferentes dos de Alice para chaves distintas)
P_BOB = 67 
Q_BOB = 71

# Gera par de chaves usando sua rsa_lib
public_key, private_key = generate_keypair(P_BOB, Q_BOB)
# public_key é (e, n), private_key é (d, n)

# Armazena chave pública do outro (agora como tupla (e,n))
peer_public_key = None
peer_key_received = threading.Event()

def log_message(message_direction, original_message, processed_data_representation=None):
    """Registra mensagens no arquivo de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        log_entry = f"[{timestamp}] {message_direction}: {original_message}"
        if processed_data_representation:
            log_entry += f" -> Dados Processados: {processed_data_representation}"
        f.write(log_entry + "\n")

@app.route('/key', methods=['POST'])
def receive_key_route(): # Renomeado para evitar conflito com a variável global
    global peer_public_key
    try:
        data = request.json
        peer_public_key = (data['e'], data['n']) # Chave como tupla
        peer_key_received.set()
        print(f"\n[Sistema] Chave pública de {PEER_USERNAME} recebida: e={data['e']}, n={data['n']}")
        log_message("[Sistema]", f"Chave pública de {PEER_USERNAME} recebida.", str(data))
        return jsonify({"message": "Chave recebida"}), 200
    except Exception as e:
        error_msg = f"Erro ao receber chave: {e}, Data: {request.data}"
        print(f"\n[Sistema] {error_msg}")
        log_message("[Sistema]", error_msg)
        return jsonify({"error": "Erro ao processar chave"}), 400

@app.route('/msg', methods=['POST'])
def receive_msg_route(): # Renomeado
    if not peer_public_key:
        print("\n[Sistema] Chave pública do peer não recebida ainda. Mensagem ignorada.")
        return jsonify({"error": "Chave pública não recebida ainda"}), 400
    try:
        encrypted_int_list = request.json # Espera uma lista de inteiros via JSON
        decrypted_message_str = decrypt(private_key, encrypted_int_list)
        print(f"\n[{PEER_USERNAME}] {decrypted_message_str}")
        log_message(f"Recebida de {PEER_USERNAME}", decrypted_message_str, str(encrypted_int_list))
        return jsonify({"message": "Mensagem recebida"}), 200
    except Exception as e:
        error_msg = f"Erro ao descriptografar mensagem: {e}, Data: {request.data}"
        print(f"\n[Sistema] {error_msg}")
        log_message(f"Erro ao descriptografar de {PEER_USERNAME}", f"Dados brutos: {str(request.json if request.is_json else request.data)}", f"Erro: {e}")
        return jsonify({"error": "Erro ao processar mensagem"}), 400

@app.route('/webhook', methods=['POST'])
def external_webhook():
    data = request.json
    mensagem = data.get("mensagem", "")
    print(f"[Webhook] Mensagem recebida de sistema externo: {mensagem}")
    log_message("[Webhook]", mensagem)
    return jsonify({"status": "recebido"}), 200

def send_key_to_peer():
    max_retries = 5
    retry_delay = 3
    key_payload = {"e": public_key[0], "n": public_key[1]}
    for attempt in range(max_retries):
        try:
            print(f"[Sistema] Enviando chave pública para {PEER_USERNAME}...")
            response = requests.post(f'{PEER_URL}/key', json=key_payload, timeout=5) # Envia como JSON
            if response.status_code == 200:
                print(f"[Sistema] Chave pública enviada com sucesso para {PEER_USERNAME}.")
                log_message("[Sistema]", f"Chave pública enviada para {PEER_USERNAME}.", str(key_payload))
                return True
        except requests.exceptions.ConnectionError:
            print(f"[Sistema] Falha ao conectar com {PEER_USERNAME} na tentativa {attempt + 1}/{max_retries}. Tentando novamente em {retry_delay}s...")
            if attempt == max_retries - 1:
                log_message("[Sistema]", f"Falha ao conectar com {PEER_USERNAME} para enviar chave após {max_retries} tentativas.")
            time.sleep(retry_delay)
        except Exception as e:
            error_msg = f"Erro ao enviar chave para {PEER_USERNAME}: {e}"
            print(f"[Sistema] {error_msg}")
            log_message("[Sistema]", error_msg)
            return False
    print(f"[Sistema] Não foi possível enviar a chave pública para {PEER_USERNAME} após {max_retries} tentativas.")
    return False

def send_msg_to_peer(message_text):
    if not peer_key_received.is_set():
        print("[Sistema] Aguardando chave pública do peer antes de enviar mensagens.")
        return

    try:
        encrypted_int_list = encrypt(peer_public_key, message_text) # Sua função encrypt
        requests.post(f'{PEER_URL}/msg', json=encrypted_int_list, timeout=5) # Envia lista de inteiros como JSON
        log_message(f"Enviada para {PEER_USERNAME}", message_text, str(encrypted_int_list))
    except requests.exceptions.ConnectionError:
        error_msg = f"Falha ao conectar com {PEER_USERNAME} para enviar mensagem."
        print(f"[Sistema] {error_msg}")
        log_message(f"Falha ao enviar para {PEER_USERNAME}", message_text, "Erro de conexão")
    except Exception as e:
        error_msg = f"Erro ao enviar mensagem: {e}"
        print(f"[Sistema] {error_msg}")
        log_message(f"Erro ao enviar para {PEER_USERNAME}", message_text, f"Erro: {e}")

def start_chat_interface():
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"--- Log de Chat para {USERNAME} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---\n")

    print(f"\n--- Chat iniciado como {USERNAME} ---")
    print(f"Log de mensagens será salvo em: {LOG_FILE}")
    print(f"Usando chave pública: e={public_key[0]}, n={public_key[1]}")
    print(f"Aguardando conexão e chave de {PEER_USERNAME}...")

    if not send_key_to_peer():
        print(f"[Sistema] Não foi possível estabelecer comunicação inicial com {PEER_USERNAME}. Encerrando.")
        log_message("[Sistema]", f"Não foi possível estabelecer comunicação inicial com {PEER_USERNAME}. Encerrando.")
        return

    print(f"[Sistema] Aguardando {PEER_USERNAME} enviar a chave pública...")
    if not peer_key_received.wait(timeout=30):
        timeout_msg = f"Timeout: {PEER_USERNAME} não enviou a chave pública. Tente reiniciar as aplicações."
        print(f"[Sistema] {timeout_msg}")
        log_message("[Sistema]", timeout_msg)
        return

    print(f"[Sistema] Chave de {PEER_USERNAME} recebida. Você pode começar a enviar mensagens.")
    log_message("[Sistema]", f"Comunicação estabelecida com {PEER_USERNAME}.")
    while True:
        message = input(f"[{USERNAME}] ")
        if message.lower() == 'sair':
            print("[Sistema] Encerrando chat...")
            log_message("[Sistema]", "Chat encerrado pelo usuário.")
            break
        send_msg_to_peer(message)

if __name__ == '__main__':
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=MY_PORT, debug=False), daemon=True)
    flask_thread.start()
    start_chat_interface()