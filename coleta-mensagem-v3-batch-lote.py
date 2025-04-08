import requests
import json
import warnings
import sys
import time
import datetime
import os
import hashlib
import signal

# --- Configurações ---
BASE_URL = "https://localhost:8777"
QUEUE_NAME = "minha-fila-teste-stress"
USERNAME = "admin"
PASSWORD = "admin"
OUTPUT_DIR = "test-json-data-collector-validation_batched" # Nome de diretório sugerido para lotes
EMPTY_QUEUE_DELAY_SECONDS = 0.5
REQUEST_TIMEOUT = 10
SAVE_BATCH_SIZE = 10  # <<< NOVO: Salvar a cada X mensagens

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --- Globais ---
current_batch = [] # <<< ALTERADO: Armazena o lote atual
total_saved_count = 0 # <<< NOVO: Contagem total de mensagens salvas em todos os lotes
session = requests.Session()
session.verify = False
keep_running = True

def setup_output_directory():
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"📂 Diretório de saída '{OUTPUT_DIR}' verificado/criado.")
        return True
    except OSError as e:
        print(f"❌ Erro crítico: Não foi possível criar o diretório de saída '{OUTPUT_DIR}': {e}")
        return False

def generate_batch_filename() -> str: # Renomeado para clareza
    """Gera um nome de arquivo JSON único para um lote."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") # Adiciona microsegundos para maior unicidade
    unique_hash = hashlib.sha1(str(os.getpid()).encode() + str(time.time_ns()).encode()).hexdigest()[:8]
    filename = f"collected_batch_{QUEUE_NAME}_{timestamp}_{unique_hash}.json"
    return os.path.join(OUTPUT_DIR, filename)

def save_batch_to_json(filename: str, batch_data: list): # Modificado para aceitar dados
    """Salva um lote de dados coletados em um arquivo JSON."""
    global total_saved_count
    batch_size = len(batch_data)
    if batch_size == 0:
        print("\n⚠️ Tentativa de salvar lote vazio. Ignorando.")
        return

    print(f"\n💾 Salvando lote de {batch_size} mensagens em '{filename}'...")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)
        total_saved_count += batch_size # Incrementa contador global
        print(f"✅ Lote salvo com sucesso. Total salvo até agora: {total_saved_count}")
    except IOError as e:
        print(f"❌ Erro ao salvar lote no arquivo '{filename}': {e}")
    except Exception as e:
        print(f"💥 Erro inesperado ao salvar lote JSON: {e}")

def handle_shutdown(signum=None, frame=None):
    global keep_running
    if not keep_running:
        return
    print("\n🚦 Recebido sinal de parada. Processando último lote e finalizando...")
    keep_running = False

def get_access_token(base_url, username, password):
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
            response_get.raise_for_status()
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao verificar a fila '{queue_name}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta: {e.response.text[:200]}...")
        return False

def consume_and_ack_message(base_url, queue_name):
    global current_batch # Modificado para usar current_batch
    consume_url = f"{base_url}/queues/{queue_name}/messages/consume"
    message_data = None
    message_id = None

    try:
        response_consume = session.get(consume_url, timeout=REQUEST_TIMEOUT)

        if response_consume.status_code == 200:
            message_data = response_consume.json()
            if message_data is None:
                return "empty"

            message_id = message_data.get('id')
            content = message_data.get('content')

            if message_id is None or content is None:
                print(f"\n❗️ Resposta de consumo inválida (faltando 'id' ou 'content'): {message_data}")
                return "error"

        elif response_consume.status_code == 204:
             # Fila vazia, não imprime 'E' aqui, será tratado no loop principal
             return "empty"

        elif response_consume.status_code == 404:
             print(f"\n❌ Erro: Fila '{queue_name}' não encontrada durante consumo. Foi deletada?")
             return "fatal_error"
        else:
             response_consume.raise_for_status()

    except requests.exceptions.Timeout:
        print("T", end="", flush=True)
        return "error"
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Erro de rede/HTTP ao consumir: {e}")
        if hasattr(e, 'response') and e.response is not None:
             try:
                 print(f"   Detalhe API: {e.response.json()}")
             except json.JSONDecodeError:
                 print(f"   Resposta: {e.response.text[:100]}...")
        return "error"
    except json.JSONDecodeError:
        status_code_info = getattr(response_consume, 'status_code', 'N/A')
        body_info = getattr(response_consume, 'text', '')[:100]
        print(f"\n❌ Erro ao decodificar JSON da resposta de consumo (Status {status_code_info}). Corpo: {body_info}...")
        return "error"
    except Exception as e:
        print(f"\n💥 Erro inesperado durante consumo: {type(e).__name__} - {e}")
        return "error"

    # ACK só acontece se o consumo foi bem-sucedido (message_id e message_data existem)
    if message_id and message_data:
        ack_url = f"{base_url}/messages/{message_id}/ack"
        try:
            response_ack = session.post(ack_url, timeout=REQUEST_TIMEOUT)
            response_ack.raise_for_status()

            # ACK OK - Adiciona ao lote atual
            content = message_data.get('content')
            current_batch.append(content) # Adiciona ao lote
            print(".", end="", flush=True)
            return "success" # Retorna sucesso para o loop principal

        except requests.exceptions.Timeout:
            print("A", end="", flush=True)
            print(f"\n⚠️ Timeout ao tentar ACK msg {message_id}. Mensagem pode ser reprocessada.")
            return "ack_error"
        except requests.exceptions.RequestException as e:
            status_code = getattr(e.response, 'status_code', 'N/A')
            print("F", end="", flush=True)
            print(f"\n❌ Falha ({status_code}) ao tentar ACK msg {message_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    print(f"   Detalhe API: {e.response.json()}")
                except json.JSONDecodeError:
                    print(f"   Resposta: {e.response.text[:100]}...")
            return "ack_error"
        except Exception as e:
            print(f"\n💥 Erro inesperado durante ACK da msg {message_id}: {type(e).__name__} - {e}")
            return "ack_error"

    # Se chegou aqui, algo deu errado antes do ACK (fila vazia, erro de consumo, resposta inválida)
    return "error"

# --- Execução Principal ---
if __name__ == "__main__":
    print("--- Consumidor e Coletor de Dados da Fila (Salvando em Lotes) ---")
    print(f"Alvo: {BASE_URL}")
    print(f"Fila: {QUEUE_NAME}")
    print(f"Pasta de Saída: {OUTPUT_DIR}")
    print(f"Tamanho do Lote para Salvar: {SAVE_BATCH_SIZE}")

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    if not setup_output_directory():
        sys.exit(1)

    if not get_access_token(BASE_URL, USERNAME, PASSWORD):
        print("\n--- Falha no Login. Abortando. ---")
        session.close()
        sys.exit(1)

    if not check_queue_exists(BASE_URL, QUEUE_NAME):
        print(f"\n--- Fila '{QUEUE_NAME}' não existe ou inacessível. Abortando. ---")
        session.close()
        sys.exit(1)

    print(f"\n--- Iniciando consumo da fila '{QUEUE_NAME}' ---")
    print("Pressione Ctrl+C para parar e salvar os dados restantes.")
    print("Legenda: [.] Sucesso | [E] Fila Vazia | [S] Lote Salvo | [T] Timeout Consumo | [A] Timeout ACK | [F] Falha ACK | [X] Erro")

    processed_in_run = 0 # Conta mensagens processadas nesta execução
    error_count = 0
    start_time = time.time()
    last_empty_print_time = 0

    try:
        while keep_running:
            result = consume_and_ack_message(BASE_URL, QUEUE_NAME)

            if result == "success":
                processed_in_run += 1
                # Verifica se o lote está cheio para salvar
                if len(current_batch) >= SAVE_BATCH_SIZE:
                    batch_filename = generate_batch_filename()
                    save_batch_to_json(batch_filename, current_batch)
                    current_batch = [] # Limpa o lote para o próximo
                    print("S", end="", flush=True) # Indica que um lote foi salvo

                # Opcional: Imprimir taxa a cada X mensagens, independente do lote
                if processed_in_run % 100 == 0: # Ex: a cada 100 mensagens
                     elapsed = time.time() - start_time
                     rate = processed_in_run / elapsed if elapsed > 0 else 0
                     print(f" | {processed_in_run} msgs processadas nesta execução ({rate:.1f} msg/s)")


            elif result == "empty":
                 # Imprime 'E' apenas uma vez a cada segundo para não poluir
                 current_time = time.time()
                 if current_time - last_empty_print_time >= 1.0:
                      print("E", end="", flush=True)
                      last_empty_print_time = current_time
                 try:
                    time.sleep(EMPTY_QUEUE_DELAY_SECONDS)
                 except InterruptedError:
                    handle_shutdown()
                    break

            elif result == "ack_error":
                error_count += 1
                # Considerar não pausar ou pausar muito pouco após erro de ACK,
                # pois a mensagem pode ser reprocessada rapidamente por outro consumidor.
                # time.sleep(0.1)

            elif result == "error":
                print("X", end="", flush=True)
                error_count += 1
                time.sleep(0.5) # Pausa menor após erro genérico

            elif result == "fatal_error":
                print("\n⛔ Erro fatal detectado. Parando o consumidor.")
                keep_running = False # Sinaliza para parar
                break # Sai do loop imediatamente

            # Verificação explícita caso o handle_shutdown tenha sido chamado
            if not keep_running:
                break

    finally:
        print("\n--- Finalizando ---")
        # Salva qualquer mensagem restante no lote atual
        if current_batch:
            print(f"\nSalvando lote final com {len(current_batch)} mensagens...")
            final_batch_filename = generate_batch_filename()
            save_batch_to_json(final_batch_filename, current_batch)
        else:
            print("\nNenhuma mensagem pendente no lote final para salvar.")

        end_time = time.time()
        total_time = end_time - start_time
        print("\n--- Resumo da Execução ---")
        print(f"Tempo total de execução: {total_time:.2f} segundos")
        print(f"Total de mensagens processadas nesta execução: {processed_in_run}")
        print(f"Total de mensagens salvas (acumulado): {total_saved_count}")
        print(f"Total de erros (consumo/ack/outros): {error_count}")
        if total_time > 0 and processed_in_run > 0:
            average_rate = processed_in_run / total_time
            print(f"Taxa média de processamento: {average_rate:.2f} mensagens/segundo")
        print(f"Dados salvos em lotes no diretório: {OUTPUT_DIR}")
        print("--------------------------")

        session.close()
        print("🔌 Sessão HTTP fechada.")
        # Sai com código 0 indicando sucesso (mesmo que erros tenham ocorrido durante a execução)
        # ou 1 se houve erro fatal ou interrupção não graciosa.
        exit_code = 0 if keep_running else 1 # Se keep_running for False por sinal, saída graciosa (0). Se por erro fatal, também é False. Ajustar se necessário.
        sys.exit(exit_code)