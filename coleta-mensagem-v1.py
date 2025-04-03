# -*- coding: utf-8 -*-
import requests
import json
import warnings
import sys
import time
import datetime
import os
import hashlib
import signal # Para lidar com Ctrl+C de forma mais explícita se necessário



# --- Configurações ---
BASE_URL = "https://localhost:8777"
QUEUE_NAME = "minha-fila-teste-stress" # <<< IMPORTANTE: Use a mesma fila do teste de stress
USERNAME = "admin"
PASSWORD = "admin"
OUTPUT_DIR = "test-json-data-collector-validation" # Pasta para salvar os JSONs
EMPTY_QUEUE_DELAY_SECONDS = 0.5 # Tempo de espera se a fila estiver vazia
REQUEST_TIMEOUT = 10 # Timeout para requisições API
# --- Fim das Configurações ---

# Ignorar avisos sobre certificados SSL autoassinados
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --- Globais ---
collected_message_contents = [] # Lista para armazenar o conteúdo das mensagens
session = requests.Session() # Usar sessão para reutilizar conexões
session.verify = False # Ignora verificação SSL para toda a sessão
keep_running = True # Flag para controlar o loop principal
# --- Fim Globais ---

def setup_output_directory():
    """Cria o diretório de saída se não existir."""
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"📂 Diretório de saída '{OUTPUT_DIR}' verificado/criado.")
        return True
    except OSError as e:
        print(f"❌ Erro crítico: Não foi possível criar o diretório de saída '{OUTPUT_DIR}': {e}")
        return False

def generate_output_filename() -> str:
    """Gera um nome de arquivo JSON único."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_hash = hashlib.sha1(str(os.getpid()).encode() + str(time.time()).encode()).hexdigest()[:8]
    filename = f"collected_data_{QUEUE_NAME}_{timestamp}_{unique_hash}.json"
    return os.path.join(OUTPUT_DIR, filename)

def save_data_to_json(filename: str):
    """Salva os dados coletados em um arquivo JSON."""
    global collected_message_contents
    print(f"\n💾 Salvando {len(collected_message_contents)} mensagens coletadas em '{filename}'...")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(collected_message_contents, f, indent=2, ensure_ascii=False)
        print(f"✅ Dados salvos com sucesso.")
    except IOError as e:
        print(f"❌ Erro ao salvar dados no arquivo '{filename}': {e}")
    except Exception as e:
        print(f"💥 Erro inesperado ao salvar JSON: {e}")

def handle_shutdown(signum=None, frame=None):
    """Função chamada ao receber sinal de parada (como Ctrl+C)."""
    global keep_running
    if not keep_running: # Evita chamadas múltiplas
        return
    print("\n🚦 Recebido sinal de parada. Iniciando desligamento gracioso...")
    keep_running = False # Sinaliza para o loop principal parar

def get_access_token(base_url, username, password):
    """Faz login usando a sessão para obter um token e configura na sessão."""
    login_url = f"{base_url}/login"
    try:
        print(f"🔑 Tentando fazer login como '{username}'...")
        response = session.post(
            login_url,
            data={"username": username, "password": password},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            print("❌ Token não encontrado na resposta do login.")
            return False
        session.headers.update({"Authorization": f"Bearer {access_token}"})
        print("✅ Login bem-sucedido e token configurado na sessão.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão ou HTTP ao tentar fazer login: {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta: {e.response.text[:200]}...")
        return False
    except json.JSONDecodeError:
        print(f"❌ Erro ao decodificar a resposta JSON do login.")
        return False

def check_queue_exists(base_url, queue_name):
    """Verifica se a fila alvo existe."""
    get_queue_url = f"{base_url}/queues/{queue_name}"
    try:
        print(f"ℹ️  Verificando se a fila '{queue_name}' existe...")
        response_get = session.get(get_queue_url, timeout=REQUEST_TIMEOUT)
        if response_get.status_code == 200:
            print(f"👍 Fila '{queue_name}' encontrada.")
            return True
        elif response_get.status_code == 404:
            print(f"❌ Erro Crítico: Fila '{queue_name}' não encontrada. Verifique o nome.")
            return False
        else:
            response_get.raise_for_status() # Lança erro para outros status
            return False # Não deve chegar aqui
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao verificar a fila '{queue_name}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta: {e.response.text[:200]}...")
        return False

def consume_and_ack_message(base_url, queue_name):
    """Tenta consumir uma mensagem e, se bem-sucedido, faz o ACK."""
    global collected_message_contents
    consume_url = f"{base_url}/queues/{queue_name}/messages/consume"
    message_data = None

    # 1. Tentar Consumir
    try:
        response_consume = session.get(consume_url, timeout=REQUEST_TIMEOUT)

        if response_consume.status_code == 200:
            message_data = response_consume.json()
            if message_data is None:
                # Fila vazia, não é um erro, apenas informativo
                # print("E", end="", flush=True) # 'E' para Empty
                return "empty" # Sinaliza que a fila está vazia
            # Temos uma mensagem!
            message_id = message_data.get('message_id')
            content = message_data.get('content')
            if message_id is None or content is None:
                print(f"\n❗️ Resposta de consumo inválida recebida: {message_data}")
                return "error" # Erro inesperado no formato da resposta

        elif response_consume.status_code == 404: # Fila não existe mais?
             print(f"\n❌ Erro: Fila '{queue_name}' não encontrada durante consumo. Foi deletada?")
             return "fatal_error" # Erro que deve parar o consumidor
        else:
             response_consume.raise_for_status() # Levanta erro para outros status HTTP

    except requests.exceptions.Timeout:
        print("T", end="", flush=True) # Timeout
        return "error"
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Erro de rede/HTTP ao consumir: {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta: {e.response.text[:100]}...")
        return "error"
    except json.JSONDecodeError:
        print(f"\n❌ Erro ao decodificar JSON da resposta de consumo.")
        return "error"
    except Exception as e:
        print(f"\n💥 Erro inesperado durante consumo: {e}")
        return "error"

    # 2. Tentar Acknowledger (ACK) - Somente se consumimos com sucesso
    if message_data and message_id:
        ack_url = f"{base_url}/messages/{message_id}/ack"
        try:
            response_ack = session.post(ack_url, timeout=REQUEST_TIMEOUT)
            response_ack.raise_for_status() # Levanta erro para 4xx/5xx no ACK

            # ACK bem-sucedido!
            collected_message_contents.append(content) # Salva o conteúdo na lista
            print(".", end="", flush=True) # "." para sucesso
            return "success"

        except requests.exceptions.Timeout:
            print("A", end="", flush=True) # Ack Timeout
            # O que fazer aqui? A mensagem foi consumida mas não ack'd.
            # Poderia tentar NACK ou apenas logar por enquanto.
            print(f"\n⚠️ Timeout ao tentar ACK msg {message_id}. Mensagem pode ser reprocessada por outro consumidor.")
            return "ack_error"
        except requests.exceptions.RequestException as e:
            status_code = getattr(e.response, 'status_code', 'N/A')
            print("F", end="", flush=True) # Failed Ack
            print(f"\n❌ Falha ({status_code}) ao tentar ACK msg {message_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try: print(f"   Detalhe API: {e.response.json()}")
                except json.JSONDecodeError: print(f"   Resposta: {e.response.text[:100]}...")
            # Mensagem foi consumida mas não ack'd.
            return "ack_error"
        except Exception as e:
            print(f"\n💥 Erro inesperado durante ACK da msg {message_id}: {e}")
            return "ack_error"

    # Se chegamos aqui, algo deu errado antes do ACK
    return "error"

# --- Execução Principal ---
if __name__ == "__main__":
    print("--- Consumidor e Coletor de Dados da Fila ---")
    print(f"Alvo: {BASE_URL}")
    print(f"Fila: {QUEUE_NAME}")
    print(f"Pasta de Saída: {OUTPUT_DIR}")

    # Configura manipulador de sinal para Ctrl+C
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    if not setup_output_directory():
        sys.exit(1)

    # 1. Autenticar
    if not get_access_token(BASE_URL, USERNAME, PASSWORD):
        print("\n--- Falha no Login. Abortando. ---")
        session.close()
        sys.exit(1)

    # 2. Verificar se a fila existe
    if not check_queue_exists(BASE_URL, QUEUE_NAME):
        print(f"\n--- Fila '{QUEUE_NAME}' não existe ou inacessível. Abortando. ---")
        session.close()
        sys.exit(1)

    print(f"\n--- Iniciando consumo da fila '{QUEUE_NAME}' ---")
    print("Pressione Ctrl+C para parar e salvar os dados.")
    print("Legenda: [.] Sucesso | [E] Fila Vazia (pausando) | [T] Timeout Consumo | [A] Timeout ACK | [F] Falha ACK | [X] Erro")

    processed_count = 0
    error_count = 0
    start_time = time.time()

    try:
        while keep_running:
            result = consume_and_ack_message(BASE_URL, QUEUE_NAME)

            if result == "success":
                processed_count += 1
                # Adiciona nova linha a cada 50 sucessos para melhor visualização
                if processed_count % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = processed_count / elapsed if elapsed > 0 else 0
                    print(f" | {processed_count} msgs processadas ({rate:.1f} msg/s)")

            elif result == "empty":
                print("E", end="", flush=True)
                # Pausa antes de tentar novamente se a fila estiver vazia
                # Usa wait do Event se estiver usando threading, ou sleep simples
                try:
                   time.sleep(EMPTY_QUEUE_DELAY_SECONDS)
                except InterruptedError: # Pode acontecer se Ctrl+C for pressionado durante o sleep
                   handle_shutdown()
                   break # Sai do loop se interrompido

            elif result == "ack_error":
                error_count += 1
                # Pausa curta após erro de ACK para evitar spam
                time.sleep(0.2)

            elif result == "error":
                print("X", end="", flush=True)
                error_count += 1
                # Pausa um pouco maior após erro genérico ou de rede
                time.sleep(1.0)

            elif result == "fatal_error":
                print("\n⛔ Erro fatal detectado. Parando o consumidor.")
                keep_running = False # Para o loop
                break

            # Verificação adicional para o caso de handle_shutdown ter sido chamado por um sinal
            if not keep_running:
                break

    # except KeyboardInterrupt: # Redundante se o signal handler funcionar bem
    #     handle_shutdown()

    finally:
        # Esta parte será executada quando o loop terminar (normalmente ou por sinal)
        print("\n--- Finalizando ---")
        output_filename = generate_output_filename()
        save_data_to_json(output_filename)

        # Imprimir estatísticas finais
        end_time = time.time()
        total_time = end_time - start_time
        print("\n--- Resumo da Coleta ---")
        print(f"Tempo total de execução: {total_time:.2f} segundos")
        print(f"Total de mensagens processadas e salvas: {processed_count}")
        print(f"Total de erros (consumo/ack/outros): {error_count}")
        if total_time > 0 and processed_count > 0:
            average_rate = processed_count / total_time
            print(f"Taxa média de processamento: {average_rate:.2f} mensagens/segundo")
        print(f"Dados salvos em: {output_filename}")
        print("--------------------------")

        # Fecha a sessão de requests
        session.close()
        print("🔌 Sessão HTTP fechada.")
        sys.exit(0)