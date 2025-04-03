# -*- coding: utf-8 -*-
import requests
import json
import warnings
import sys
import time
import datetime

# --- Configurações ---
BASE_URL = "https://localhost:8777"
QUEUE_NAME = "minha-fila-teste-stress" # <<< A MESMA FILA USADA NO SCRIPT DE ENVIO >>>
USERNAME = "admin"
PASSWORD = "admin"
POLL_INTERVAL = 1 # Segundos para esperar se a fila estiver vazia (reduzido para testes)
REQUEST_TIMEOUT = 15 # Timeout para requisições GET/POST
# --- Fim das Configurações ---

# Ignorar avisos sobre certificados SSL autoassinados
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# --- Globais ---
messages_processed = 0
consume_attempts = 0
ack_failures = 0
last_message_time = None
# --- Fim Globais ---

def get_access_token(session, base_url, username, password):
    """Faz login usando a sessão para obter um token."""
    login_url = f"{base_url}/login"
    try:
        print(f"🔑 Tentando fazer login como '{username}' em {login_url}...")
        response = session.post(
            login_url,
            data={"username": username, "password": password},
            verify=False,
            timeout=20 # Timeout maior para login
        )
        response.raise_for_status()
        token_data = response.json()
        print("✅ Login bem-sucedido!")
        access_token = token_data.get("access_token")
        if access_token:
            session.headers.update({"Authorization": f"Bearer {access_token}"})
            print("🔑 Token de acesso configurado na sessão.")
            return access_token
        else:
             print("❌ Token não encontrado na resposta do login.")
             return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão ou HTTP ao tentar fazer login: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try: print(f"   Detalhe da API: {e.response.status_code} {e.response.reason} - {e.response.json()}")
            except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.status_code} {e.response.reason} - {e.response.text[:200]}...")
        return None
    except json.JSONDecodeError:
        print(f"❌ Erro ao decodificar a resposta JSON do login.")
        return None

def acknowledge_message(session, base_url, message_id):
    """Envia um ACK para o servidor para confirmar o processamento."""
    global ack_failures
    ack_url = f"{base_url}/messages/{message_id}/ack"
    try:
        # print(f"  -> Enviando ACK para {ack_url}...") # Debug verboso
        response_ack = session.post(
            ack_url,
            verify=False,
            timeout=REQUEST_TIMEOUT
        )

        if response_ack.status_code == 200:
            # print(f"  ✅ ACK bem-sucedido para mensagem {message_id}.") # Debug verboso
            return True
        elif response_ack.status_code == 404:
             print(f"  ⚠️ ACK falhou (404): Mensagem {message_id} não encontrada (provavelmente já processada/deletada).")
             # Consideramos sucesso pois a mensagem não está mais pendente para nós
             return True
        elif response_ack.status_code == 409:
             print(f"  ⚠️ ACK falhou (409): Mensagem {message_id} não estava no estado 'processing'. Status: {response_ack.json().get('detail', '')}")
             ack_failures += 1
             return False # Falha real, a mensagem pode ter sido NACK'd ou ainda está pendente
        else:
            response_ack.raise_for_status() # Levanta erro para outros status inesperados

    except requests.exceptions.Timeout:
        print(f"  ⏳ Timeout ao enviar ACK para mensagem {message_id}.")
        ack_failures += 1
        return False
    except requests.exceptions.RequestException as e:
        print(f"  ❌ Erro ao enviar ACK para mensagem {message_id}: {e}")
        ack_failures += 1
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"     Detalhe da API: {e.response.status_code} {e.response.reason} - {e.response.json()}")
             except json.JSONDecodeError: print(f"     Resposta (não JSON): {e.response.status_code} {e.response.reason} - {e.response.text[:200]}...")
        return False
    return False # Se chegou aqui por algum motivo

def consume_and_ack_message(session, base_url, queue_name):
    """Tenta consumir uma mensagem e envia ACK se bem-sucedido."""
    global messages_processed, last_message_time, consume_attempts
    consume_url = f"{base_url}/queues/{queue_name}/messages/consume" # <<< URL CORRIGIDA >>>
    message_data = None
    message_id = None
    consume_attempts += 1

    # 1. Tentar obter (consumir) uma mensagem
    try:
        # print(f" Tentando consumir de {consume_url}...") # Debug verboso
        response_get = session.get(
            consume_url,
            verify=False,
            timeout=REQUEST_TIMEOUT
        )

        # --- Tratamento da Resposta do Consumo ---
        if response_get.status_code == 200:
            # Tenta decodificar o JSON. Se o corpo for 'null', json() pode retornar None ou dar erro
            try:
                message_data = response_get.json()
            except json.JSONDecodeError:
                 # Isso pode acontecer se a resposta for 'null' literal ou outro texto não-JSON
                 if response_get.text == 'null':
                     message_data = None # Tratar 'null' como fila vazia
                 else:
                    print(f"❌ Erro ao decodificar JSON da resposta de consumo (não era 'null'): {response_get.text[:100]}...")
                    return False # Falha inesperada

            # --- Checa se a mensagem foi recebida (message_data não é None) ---
            if message_data:
                message_id = message_data.get("message_id") # <<< NOME DO CAMPO CORRIGIDO >>>
                content = message_data.get("content", "*Conteúdo não encontrado*")
                status = message_data.get("status", "*Status não encontrado*")
                queue_recv = message_data.get("queue", queue_name) # Usa o nome da fila retornado se disponível

                if not message_id:
                     print(f"❌ Resposta de consumo recebida, mas sem 'message_id'. Dados: {message_data}")
                     return False # Algo deu errado na API

                print(f"📩 [{datetime.datetime.now().strftime('%H:%M:%S')}] Msg Recebida (ID: {message_id}, Fila: {queue_recv}, Status: {status}): '{content[:80]}{'...' if len(content)>80 else ''}'")

                # --- 2. Enviar ACK imediatamente (após receber a mensagem) ---
                # Em uma aplicação real, o processamento do 'content' iria aqui
                ack_successful = acknowledge_message(session, base_url, message_id)

                if ack_successful:
                    messages_processed += 1
                    last_message_time = time.time()
                    return True # Consumo E ACK bem-sucedidos
                else:
                    # O ACK falhou. A mensagem permanecerá como 'processing' no servidor.
                    # Poderíamos tentar um NACK aqui, mas por simplicidade vamos apenas registrar
                    print(f"‼️ Falha ao enviar ACK para msg {message_id} após consumo bem-sucedido.")
                    return False # Processamento completo falhou devido ao ACK

            else:
                # Status 200 mas message_data é None (corpo 'null'), significa fila vazia
                # print(f" Fila '{queue_name}' vazia (200 OK com null).") # Debug verboso
                return False # Indica que não havia mensagem

        elif response_get.status_code == 404:
            # Este 404 geralmente significa que a *fila* em si não foi encontrada
            print(f"❓ Fila '{queue_name}' não encontrada no servidor (Erro 404 no GET .../consume). Verifique o nome da fila.")
            # Espera um pouco mais se a fila não for encontrada para não spammar logs
            time.sleep(POLL_INTERVAL * 5)
            return False # Indica que a fila não existe

        else:
            # Outros erros HTTP inesperados
            print(f"‼️ Erro HTTP inesperado ao consumir de '{queue_name}': {response_get.status_code} {response_get.reason}")
            response_get.raise_for_status() # Levanta erro para análise detalhada

    except requests.exceptions.Timeout:
        print(f"⏳ Timeout ao tentar consumir mensagem da fila '{queue_name}'.")
        return False # Falha temporária, tentar novamente depois
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de requisição ao consumir mensagem da fila '{queue_name}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             try: print(f"   Detalhe da API: {e.response.status_code} {e.response.reason} - {e.response.json()}")
             except json.JSONDecodeError: print(f"   Resposta (não JSON): {e.response.status_code} {e.response.reason} - {e.response.text[:200]}...")
        return False # Falha, tentar novamente depois
    except Exception as e:
         print(f"💥 Erro inesperado na função consume_and_ack_message: {type(e).__name__}: {e}")
         # Considerar logar traceback aqui para depuração
         return False

    # Retorno padrão caso nenhum caminho anterior retorne
    return False


# --- Execução Principal ---
if __name__ == "__main__":
    print(f"--- Consumidor de Mensagens (com ACK) da Fila '{QUEUE_NAME}' ---")
    print(f"Alvo: {BASE_URL}")
    print(f"Intervalo de polling (fila vazia): {POLL_INTERVAL}s")

    session = requests.Session()
    session.verify = False # Ignora verificação SSL para toda a sessão

    # 1. Obter token de acesso e configurar na sessão
    token = get_access_token(session, BASE_URL, USERNAME, PASSWORD)
    if not token:
        print("\n--- Falha no Login. Abortando. ---")
        sys.exit(1)

    print(f"\n--- Iniciando consumo da fila '{QUEUE_NAME}' ---")
    print("Pressione Ctrl+C para parar...")

    start_time = time.time()
    running = True

    try:
        while running:
            try:
                # Tenta consumir E fazer o ACK
                message_processed_successfully = consume_and_ack_message(session, BASE_URL, QUEUE_NAME)

                if not message_processed_successfully:
                    # Se não processou mensagem (fila vazia, erro, falha no ACK), esperar
                    # print(".", end="", flush=True) # Indicador visual de polling
                    time.sleep(POLL_INTERVAL)
                # else:
                    # Se consumiu e ACK foi OK, tenta ler a próxima imediatamente (sem sleep)
                    # Pequeno sleep opcional para não sobrecarregar CPU em loop muito rápido
                    # time.sleep(0.01)
                    pass # Tenta consumir a próxima imediatamente

            except Exception as e:
                # Captura exceções inesperadas no loop principal
                print(f"\n💥 Erro inesperado no loop principal: {e}")
                print("Aguardando antes de tentar novamente...")
                time.sleep(POLL_INTERVAL * 2) # Espera um pouco mais após um erro grave

    except KeyboardInterrupt:
        print("\n\n🛑 Interrupção pelo usuário recebida. Parando o consumidor...")
        running = False

    finally:
        # Fecha a sessão de requests para liberar conexões
        print("Fechando a sessão HTTP...")
        session.close()

        # Imprimir estatísticas finais
        end_time = time.time()
        total_time = end_time - start_time

        print("\n--- Resumo Final do Consumo ---")
        print(f"Tempo total de execução: {total_time:.2f} segundos")
        print(f"Tentativas de consumo: {consume_attempts}")
        print(f"Mensagens processadas (consumo + ACK OK): {messages_processed}")
        print(f"Falhas no ACK (após consumo OK): {ack_failures}")
        if messages_processed > 0 and total_time > 0:
            average_rate = messages_processed / total_time
            print(f"Taxa média de consumo efetivo: {average_rate:.2f} mensagens/segundo")
        if last_message_time:
             print(f"Última mensagem processada com sucesso em: {datetime.datetime.fromtimestamp(last_message_time).strftime('%Y-%m-%d %H:%M:%S')}")
        else:
             print("Nenhuma mensagem foi processada com sucesso durante esta execução.")
        print("---------------------------------")
        sys.exit(0)