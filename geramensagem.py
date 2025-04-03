# -*- coding: utf-8 -*-
import requests
import json
import warnings
import sys
import time # Adicionado para um pequeno delay opcional

# --- Configurações ---
BASE_URL = "https://localhost:8777"
QUEUE_NAME = "minha-fila-teste" # A fila que queremos usar/criar
MESSAGE_CONTENT = "hello world" # Mensagem específica
USERNAME = "admin"
PASSWORD = "admin"
# --- Fim das Configurações ---

# Ignorar avisos sobre certificados SSL autoassinados (APENAS PARA DESENVOLVIMENTO)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def get_access_token(base_url, username, password):
    """Faz login na API para obter um token de acesso."""
    login_url = f"{base_url}/login"
    try:
        print(f"🔑 Tentando fazer login como '{username}' em {login_url}...")
        response = requests.post(
            login_url,
            data={"username": username, "password": password},
            verify=False, # Ignora verificação SSL
            timeout=10
        )
        response.raise_for_status()
        token_data = response.json()
        print("✅ Login bem-sucedido!")
        return token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão ou HTTP ao tentar fazer login: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try: print(f"   Detalhe da API: {e.response.json()}")
            except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.text[:200]}...")
        return None
    except json.JSONDecodeError:
        print(f"❌ Erro ao decodificar a resposta JSON do login.")
        return None

def check_or_create_queue(base_url, queue_name, token):
    """Verifica se a fila existe. Se não, tenta criá-la."""
    get_queue_url = f"{base_url}/queues/{queue_name}"
    create_queue_url = f"{base_url}/queues"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        print(f"ℹ️  Verificando se a fila '{queue_name}' existe...")
        response_get = requests.get(get_queue_url, headers=headers, verify=False, timeout=5)

        if response_get.status_code == 200:
            print(f"👍 Fila '{queue_name}' já existe.")
            return True # Fila existe

        elif response_get.status_code == 404:
            print(f"⚠️  Fila '{queue_name}' não encontrada. Tentando criar...")
            payload = {"name": queue_name}
            headers_post = {**headers, "Content-Type": "application/json"} # Adiciona Content-Type
            response_post = requests.post(
                create_queue_url,
                headers=headers_post,
                json=payload,
                verify=False,
                timeout=10
            )

            if response_post.status_code == 201: # 201 Created
                print(f"✅ Fila '{queue_name}' criada com sucesso!")
                # Pequeno delay opcional para garantir que a fila esteja pronta no DB
                time.sleep(0.5)
                return True # Fila criada
            elif response_post.status_code == 409: # 409 Conflict
                 print(f"⚠️  A fila '{queue_name}' foi criada por outro processo enquanto verificávamos (Erro 409). Considerando como sucesso.")
                 return True # Fila já existe (provavelmente criada entre o GET e o POST)
            else:
                # Outro erro durante a criação
                response_post.raise_for_status() # Lança exceção para outros erros HTTP
                return False # Falha inesperada na criação (nunca deve chegar aqui se raise_for_status funcionar)

        else:
            # Erro inesperado ao verificar a fila
            response_get.raise_for_status()
            return False # Falha inesperada na verificação

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao verificar ou criar a fila '{queue_name}': {e}")
        if hasattr(e, 'response') and e.response is not None:
            try: print(f"   Detalhe da API: {e.response.json()}")
            except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.text[:200]}...")
        return False # Falha

def publish_message_to_queue(base_url, queue_name, message, token):
    """Publica uma mensagem na fila especificada usando o token."""
    publish_url = f"{base_url}/queues/{queue_name}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {"content": message}
    try:
        print(f"📤 Publicando mensagem na fila '{queue_name}'...")
        print(f"   Conteúdo: '{message}'")
        response = requests.post(
            publish_url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )
        response.raise_for_status() # Lança exceção para erros HTTP (4xx, 5xx)
        response_data = response.json()
        print(f"✅ Mensagem publicada com sucesso!")
        print(f"   ID da Mensagem: {response_data.get('message_id')}")
        return response_data
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão ou HTTP ao publicar mensagem:")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe da API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.text[:200]}...")
        else: print(f"   Erro: {e}")
        return None
    except json.JSONDecodeError:
        print(f"❌ Erro ao decodificar a resposta JSON da publicação.")
        return None

# --- Execução Principal ---
if __name__ == "__main__":
    print("--- Cliente da API Message Broker (v2: Cria Fila se não existir) ---")

    # 1. Obter token de acesso
    access_token = get_access_token(BASE_URL, USERNAME, PASSWORD)

    if not access_token:
        print("\n--- Falha no Login. Abortando. ---")
        sys.exit(1)

    print("\n--- Preparação da Fila ---")
    # 2. Verificar se a fila existe e criar se necessário
    queue_is_ready = check_or_create_queue(BASE_URL, QUEUE_NAME, access_token)

    if not queue_is_ready:
        print(f"\n--- Falha ao garantir a existência da fila '{QUEUE_NAME}'. Abortando. ---")
        sys.exit(1)

    print("\n--- Publicação da Mensagem ---")
    # 3. Publicar a mensagem
    result = publish_message_to_queue(BASE_URL, QUEUE_NAME, MESSAGE_CONTENT, access_token)

    if result:
        print("\n--- Operação Concluída com Sucesso ---")
    else:
        print("\n--- Falha na Publicação da Mensagem ---")
        sys.exit(1) # Sair com código de erro se a publicação falhar