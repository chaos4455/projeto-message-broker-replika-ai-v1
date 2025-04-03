# -*- coding: utf-8 -*-
import requests
import json
import warnings
import sys
import time
import datetime
import threading
import queue # Embora não usemos uma Queue do módulo, o conceito é similar
from concurrent.futures import ThreadPoolExecutor # Alternativa mais moderna para gerenciar threads

# --- Configurações ---
BASE_URL = "https://localhost:8777"
QUEUE_NAME = "minha-fila-teste-stress" # Fila para teste de stress
MESSAGE_BASE_CONTENT = "Stress Test Msg"
USERNAME = "admin"
PASSWORD = "admin"
NUM_WORKERS = 60  # <<< NÚMERO DE THREADS CONCORRENTES >>> Ajuste conforme necessário
REPORT_INTERVAL = 5 # Segundos entre relatórios de status
# --- Fim das Configurações ---

# Ignorar avisos sobre certificados SSL autoassinados
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --- Globais e Sincronização ---
message_counter = 0
success_count = 0
fail_count = 0
counter_lock = threading.Lock() # Para proteger acesso aos contadores
stop_event = threading.Event() # Para sinalizar parada para as threads
start_time = 0.0
# --- Fim Globais ---

def get_access_token(session, base_url, username, password):
    """Faz login usando a sessão para obter um token."""
    login_url = f"{base_url}/login"
    try:
        print(f"🔑 Tentando fazer login como '{username}' em {login_url}...")
        response = session.post( # Usa a sessão
            login_url,
            data={"username": username, "password": password},
            verify=False,
            timeout=15 # Timeout um pouco maior para login
        )
        response.raise_for_status()
        token_data = response.json()
        print("✅ Login bem-sucedido!")
        # Define o header de autorização na sessão para todas as requisições futuras
        access_token = token_data.get("access_token")
        if access_token:
            session.headers.update({"Authorization": f"Bearer {access_token}"})
            return access_token # Retorna o token caso seja necessário fora da sessão
        else:
             print("❌ Token não encontrado na resposta do login.")
             return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão ou HTTP ao tentar fazer login: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try: print(f"   Detalhe da API: {e.response.json()}")
            except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.text[:200]}...")
        return None
    except json.JSONDecodeError:
        print(f"❌ Erro ao decodificar a resposta JSON do login.")
        return None

def check_or_create_queue(session, base_url, queue_name):
    """Verifica/cria a fila usando a sessão."""
    get_queue_url = f"{base_url}/queues/{queue_name}"
    create_queue_url = f"{base_url}/queues"
    # Headers já estão na sessão (Authorization)

    try:
        print(f"ℹ️  Verificando se a fila '{queue_name}' existe...")
        response_get = session.get(get_queue_url, verify=False, timeout=10) # Usa sessão

        if response_get.status_code == 200:
            print(f"👍 Fila '{queue_name}' já existe.")
            return True

        elif response_get.status_code == 404:
            print(f"⚠️  Fila '{queue_name}' não encontrada. Tentando criar...")
            payload = {"name": queue_name}
            # Adiciona Content-Type especificamente para esta requisição POST JSON
            headers_post = {"Content-Type": "application/json"}
            response_post = session.post( # Usa sessão
                create_queue_url,
                headers=headers_post, # Adiciona o Content-Type aqui
                json=payload,
                verify=False,
                timeout=10
            )

            if response_post.status_code == 201:
                print(f"✅ Fila '{queue_name}' criada com sucesso!")
                time.sleep(0.5)
                return True
            elif response_post.status_code == 409:
                 print(f"⚠️  A fila '{queue_name}' foi criada por outro processo (Erro 409). OK.")
                 return True
            else:
                response_post.raise_for_status() # Levanta erro para outros status
                return False # Não deve chegar aqui

        else:
            response_get.raise_for_status() # Levanta erro para outros status no GET
            return False # Não deve chegar aqui

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao verificar ou criar a fila '{queue_name}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe da API: {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.text[:200]}...")
        return False

def message_sender_worker(session, base_url, queue_name, worker_id):
    """Função executada por cada thread worker."""
    global message_counter, success_count, fail_count
    publish_url = f"{base_url}/queues/{queue_name}/messages"
    headers_post = {"Content-Type": "application/json"} # Content-Type para o POST

    while not stop_event.is_set(): # Continua enquanto o evento de parada não for setado
        with counter_lock: # Adquire o lock para obter um ID único
            current_msg_id = message_counter
            message_counter += 1
        # O lock é liberado aqui

        full_message = f"{MESSAGE_BASE_CONTENT} Worker {worker_id} Msg #{current_msg_id} ({datetime.datetime.now().isoformat()})"
        payload = {"content": full_message}

        try:
            response = session.post(
                publish_url,
                headers=headers_post, # Adiciona Content-Type (Auth já está na sessão)
                json=payload,
                verify=False,
                timeout=5 # Timeout curto para não prender a thread por muito tempo
            )
            response.raise_for_status() # Lança exceção para erros 4xx/5xx

            # Se chegou aqui, foi sucesso
            with counter_lock: # Adquire o lock para atualizar contador de sucesso
                success_count += 1
            # Lock liberado

        except requests.exceptions.Timeout:
            with counter_lock: fail_count += 1
            # print(f"T{worker_id}:T", end="", flush=True) # Timeout
        except requests.exceptions.RequestException as e:
            with counter_lock: fail_count += 1
            # Opcional: Logar o erro, mas pode poluir muito
            # status = e.response.status_code if hasattr(e, 'response') and e.response else 'N/A'
            # print(f"T{worker_id}:E{status}", end="", flush=True) # Erro com status
        except Exception as e: # Captura outras exceções inesperadas
             with counter_lock: fail_count += 1
             # print(f"T{worker_id}:X", end="", flush=True) # Erro genérico
        # REMOVEMOS O time.sleep() DAQUI PARA MÁXIMA VELOCIDADE

def status_reporter():
    """Thread separada para reportar o status periodicamente."""
    global start_time
    last_report_time = time.time()
    last_success_count = 0

    while not stop_event.wait(REPORT_INTERVAL): # Espera pelo intervalo ou pelo evento de parada
        now = time.time()
        elapsed_interval = now - last_report_time
        
        with counter_lock: # Lê contadores com segurança
            current_success = success_count
            current_fail = fail_count
            current_total = message_counter

        interval_success = current_success - last_success_count
        rate = interval_success / elapsed_interval if elapsed_interval > 0 else 0
        total_elapsed = now - start_time
        overall_rate = current_success / total_elapsed if total_elapsed > 0 else 0

        print(f"\n[Status {time.strftime('%H:%M:%S')}] Total: {current_total} | Sucesso: {current_success} ({interval_success} no intervalo) | Falhas: {current_fail} | Taxa Intervalo: {rate:.1f} msg/s | Taxa Média: {overall_rate:.1f} msg/s")
        
        last_report_time = now
        last_success_count = current_success


# --- Execução Principal ---
if __name__ == "__main__":
    print("--- Cliente de Teste de Stress (Máxima Velocidade) ---")
    print(f"Alvo: {BASE_URL}")
    print(f"Fila: {QUEUE_NAME}")
    print(f"Workers: {NUM_WORKERS}")

    # Cria uma única sessão para ser compartilhada por todas as threads
    # A sessão gerencia o pool de conexões e headers comuns
    session = requests.Session()
    session.verify = False # Ignora verificação SSL para toda a sessão

    # 1. Obter token de acesso e configurar na sessão
    token = get_access_token(session, BASE_URL, USERNAME, PASSWORD)
    if not token:
        print("\n--- Falha no Login. Abortando. ---")
        sys.exit(1)

    print("\n--- Preparação da Fila ---")
    # 2. Verificar/Criar a fila usando a sessão
    queue_is_ready = check_or_create_queue(session, BASE_URL, QUEUE_NAME)
    if not queue_is_ready:
        print(f"\n--- Falha ao preparar a fila '{QUEUE_NAME}'. Abortando. ---")
        session.close() # Fecha a sessão
        sys.exit(1)

    print(f"\n--- Iniciando {NUM_WORKERS} workers para stress na fila '{QUEUE_NAME}' ---")
    print("Pressione Ctrl+C para parar...")

    start_time = time.time() # Marca o tempo de início

    threads = []
    # Inicia a thread de relatório
    reporter_thread = threading.Thread(target=status_reporter, daemon=True) # Daemon=True para não impedir saída
    reporter_thread.start()

    # Cria e inicia as threads worker
    for i in range(NUM_WORKERS):
        thread = threading.Thread(target=message_sender_worker, args=(session, BASE_URL, QUEUE_NAME, i + 1))
        thread.start()
        threads.append(thread)

    try:
        # Mantém a thread principal viva esperando as workers terminarem (o que só acontece com Ctrl+C)
        # Ou poderíamos simplesmente esperar pelo Ctrl+C aqui
        while not stop_event.is_set():
             time.sleep(0.5) # Evita que a thread principal consuma 100% CPU apenas esperando

    except KeyboardInterrupt:
        print("\n\n🛑 Interrupção pelo usuário recebida. Sinalizando parada para as threads...")
        stop_event.set() # Sinaliza para todas as threads pararem

    finally:
        print("Aguardando workers finalizarem...")
        # Espera todas as threads worker terminarem
        for thread in threads:
            thread.join(timeout=10) # Dá um tempo para as threads terminarem

        # A thread reporter é daemon, então não precisamos esperar por ela explicitamente se o programa sair

        # Fecha a sessão de requests para liberar conexões
        session.close()

        # 5. Imprimir estatísticas finais
        end_time = time.time()
        total_time = end_time - start_time
        # Lê os contadores finais (o lock não é estritamente necessário aqui,
        # pois as threads já pararam, mas é boa prática)
        with counter_lock:
            final_total = message_counter
            final_success = success_count
            final_fail = fail_count

        print("\n--- Resumo Final do Teste de Stress ---")
        print(f"Tempo total de execução: {total_time:.2f} segundos")
        print(f"Total de mensagens tentadas: {final_total}")
        print(f"Total de mensagens publicadas com sucesso: {final_success}")
        print(f"Total de falhas na publicação: {final_fail}")
        if total_time > 0:
            average_rate = final_success / total_time
            print(f"Taxa média de publicação (sucesso): {average_rate:.2f} mensagens/segundo")
        else:
            print("Taxa média de publicação: N/A (tempo de execução muito curto)")
        print("--------------------------------------")
        sys.exit(0)