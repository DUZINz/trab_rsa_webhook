import sys
import os

# Add the project root directory (parent of libs_cripto_security) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from flask import Flask, request, jsonify
from rsa_lib import generate_keypair, encrypt, decrypt

app = Flask(__name__)

# Inicializa as chaves RSA com dois primos pequenos para demonstração
p = 61
q = 53
public_key, private_key = generate_keypair(p, q)

# Endpoint raiz para testar se o servidor está rodando
@app.route('/')
def index():
    return jsonify({
        "message": "Servidor RSA com Webhook funcionando.",
        "endpoints": ["/encrypt", "/decrypt"]
    })

# Endpoint para criptografar mensagem recebida via POST JSON
@app.route('/encrypt', methods=['POST'])
def webhook_encrypt():
    data = request.json
    message = data.get("message")  # obtém o campo 'message' do JSON
    if not message:
        return jsonify({"error": "Campo 'message' ausente"}), 400
    try:
        encrypted = encrypt(public_key, message)  # usa função RSA para criptografar
        return jsonify({
            "encrypted": encrypted,  # retorna lista de inteiros criptografados
            "public_key": {"e": public_key[0], "n": public_key[1]}  # retorna chave pública
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para descriptografar lista de inteiros recebida via POST JSON
@app.route('/decrypt', methods=['POST'])
def webhook_decrypt():
    data = request.json
    ciphertext = data.get("ciphertext")  # obtém lista do campo 'ciphertext'
    if not isinstance(ciphertext, list):
        return jsonify({"error": "Campo 'ciphertext' deve ser uma lista de inteiros"}), 400
    try:
        decrypted = decrypt(private_key, ciphertext)  # usa função RSA para descriptografar
        return jsonify({
            "decrypted": decrypted  # retorna mensagem original em texto
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Inicializa o servidor Flask na porta 5000 com debug ativo (recarrega ao salvar)
if __name__ == '__main__':
    app.run(port=5000, debug=True)
