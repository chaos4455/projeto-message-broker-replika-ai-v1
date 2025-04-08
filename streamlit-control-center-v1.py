import streamlit as st
import paramiko
import time
import io

# --- Configuração da Página Streamlit ---
st.set_page_config(
    page_title="Gerenciador Container SSH",
    page_icon="🐳",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Estilização Customizada (Opcional) ---
# Você pode adicionar CSS customizado aqui se desejar
st.markdown("""
<style>
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        padding: 8px;
    }
    .stTextArea [data-baseweb="textarea"] {
        min-height: 100px;
    }
    .stCodeBlock {
        border: 1px solid #2d333b; /* Cor da borda para modo escuro */
        border-radius: 5px;
        padding: 10px;
    }
    /* Ajuste a cor da borda se usar tema claro */
    [data-theme="light"] .stCodeBlock {
         border: 1px solid #cccccc;
    }
</style>
""", unsafe_allow_html=True)

# --- Funções Auxiliares SSH ---

# Cacheia o cliente SSH para evitar reconexões desnecessárias
# ttl = 3600 # Cache por 1 hora (opcional)
# @st.cache_resource(ttl=3600)
# Cache de recurso pode ser complexo com Paramiko, vamos usar session_state
def get_ssh_client():
    """Retorna o cliente SSH armazenado no session state."""
    if 'ssh_client' in st.session_state and st.session_state.ssh_client:
        try:
            # Testa se a conexão ainda está ativa
            st.session_state.ssh_client.exec_command('echo test', timeout=5)
            return st.session_state.ssh_client
        except Exception:
            st.session_state.ssh_client.close()
            del st.session_state.ssh_client
            st.warning("Sessão SSH expirada ou desconectada. Por favor, reconecte.")
            return None
    return None

def connect_ssh(hostname, port, username, password):
    """Estabelece uma conexão SSH e armazena no session state."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Menos seguro, bom para dev local
        # Alternativa mais segura (requer chave no known_hosts):
        # client.load_system_host_keys()
        # client.set_missing_host_key_policy(paramiko.WarningPolicy())
        st.info(f"Tentando conectar a {username}@{hostname}:{port}...")
        client.connect(hostname, port=port, username=username, password=password, timeout=10)
        st.session_state.ssh_client = client
        st.session_state.connection_info = f"{username}@{hostname}:{port}"
        st.success(f"Conectado com sucesso a {st.session_state.connection_info}!")
        return client
    except paramiko.AuthenticationException:
        st.error("Erro de Autenticação: Verifique usuário e senha.")
        return None
    except paramiko.SSHException as e:
        st.error(f"Erro SSH: {e}")
        return None
    except Exception as e:
        st.error(f"Erro de conexão: {e}")
        return None

def disconnect_ssh():
    """Fecha a conexão SSH e limpa o session state."""
    client = get_ssh_client()
    if client:
        client.close()
        del st.session_state.ssh_client
        if 'connection_info' in st.session_state:
            del st.session_state.connection_info
        st.info("Desconectado.")

def execute_command(command, client=None, show_spinner=True):
    """Executa um comando no cliente SSH conectado."""
    if client is None:
        client = get_ssh_client()

    if not client:
        st.warning("Não conectado. Por favor, conecte-se primeiro.")
        return None, None

    output = ""
    error = ""
    exit_code = -1

    spinner_msg = f"Executando: `{command}`..."
    if show_spinner:
        with st.spinner(spinner_msg):
            try:
                stdin, stdout, stderr = client.exec_command(command, timeout=30) # Timeout de 30s
                output = stdout.read().decode('utf-8', errors='replace')
                error = stderr.read().decode('utf-8', errors='replace')
                exit_code = stdout.channel.recv_exit_status() # Pega o código de saída
                time.sleep(0.1) # Pequena pausa para garantir que o spinner apareça
            except Exception as e:
                error = f"Erro ao executar comando: {e}"
                st.error(error)
                return None, error
    else:
         try:
            stdin, stdout, stderr = client.exec_command(command, timeout=30) # Timeout de 30s
            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status() # Pega o código de saída
         except Exception as e:
            error = f"Erro ao executar comando: {e}"
            st.error(error)
            return None, error


    return output, error, exit_code

# --- Interface Streamlit ---

st.title("🐳 Gerenciador de Container via SSH")
st.caption("Interface para executar comandos comuns em um container Linux.")

# --- Barra Lateral: Conexão ---
with st.sidebar:
    st.header("🔌 Conexão SSH")
    host = st.text_input("Hostname / IP", value="localhost")
    port = st.number_input("Porta SSH", value=22, min_value=1, max_value=65535)
    user = st.text_input("Usuário", value="admin")
    password = st.text_input("Senha", value="admin", type="password")

    col1_connect, col2_disconnect = st.columns(2)

    with col1_connect:
        if st.button("Conectar", key="connect_btn"):
            # Limpa o estado anterior antes de tentar conectar
            if 'ssh_client' in st.session_state:
                disconnect_ssh()
                time.sleep(0.1) # Pausa para garantir que o estado seja atualizado
            connect_ssh(host, port, user, password)

    with col2_disconnect:
        # Só mostra Desconectar se estiver conectado
        if get_ssh_client():
            if st.button("Desconectar", key="disconnect_btn"):
                disconnect_ssh()

    st.divider()
    # Exibe status da conexão na barra lateral
    if get_ssh_client() and 'connection_info' in st.session_state:
         st.success(f"Conectado a: **{st.session_state.connection_info}**")
    else:
         st.warning("Status: Não conectado")

# --- Área Principal: Comandos e Output ---
if not get_ssh_client():
    st.info("ℹ️ Insira os detalhes de conexão na barra lateral e clique em 'Conectar'.")
else:
    st.header("🚀 Executar Comandos")

    # Inicializa o estado para o output se não existir
    if 'last_output' not in st.session_state:
        st.session_state.last_output = ""
    if 'last_error' not in st.session_state:
        st.session_state.last_error = ""
    if 'last_command' not in st.session_state:
        st.session_state.last_command = ""

    # --- Seção de Comandos Pré-definidos ---
    with st.expander("Comandos Comuns", expanded=True):
        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Rede & Processos")
            if st.button("Verificar Portas (8777, 8333)"):
                # Tenta com 'ss' primeiro, depois 'netstat' como fallback
                command = "ss -tlpn | grep -E ':(8777|8333).*LISTEN' || netstat -tlpn | grep -E ':(8777|8333).*LISTEN'"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err
                # Se code != 0 e não achou nada, informa que não está rodando
                if code != 0 and not out and not err:
                     st.session_state.last_output = "Nenhuma das portas 8777 ou 8333 encontrada em estado LISTEN."
                elif code != 0 and err:
                     st.session_state.last_error += "\n(Comando 'ss' ou 'netstat' pode não estar disponível ou falhou)"


            if st.button("Listar Processos Python"):
                command = "ps aux | grep '[pP]ython' | grep -v grep" # [pP]ython evita pegar o próprio grep
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err

            if st.button("`iftop` (Snapshot)"):
                 # Executa por 1 segundo, modo texto, sem barras, 100 linhas max
                 # Requer sudo ou root normalmente
                command = "sudo iftop -t -s 1 -L 100 -n -N"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err
                if code != 0 and "sudo" in err:
                     st.session_state.last_error += "\nℹ️ `iftop` pode requerer `sudo`. Verifique permissões ou senha sudo."
                elif code != 0 and not err:
                     st.session_state.last_error = f"Comando iftop falhou (código {code}). Está instalado e no PATH?"

        with col2:
            st.subheader("Performance")
            if st.button("`htop` (Snapshot)"):
                # Modo batch (-b), 1 iteração (-n 1)
                command = "htop -b -n 1"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err
                if code != 0 and not err:
                     st.session_state.last_error = f"Comando htop falhou (código {code}). Está instalado e no PATH?"


            if st.button("Uso de Memória (`free -h`)"):
                command = "free -h"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err

            if st.button("Status VM (`vmstat`)"):
                command = "vmstat -S M 1 3" # Unidades em MB, 1 seg intervalo, 3 vezes
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err


        with col3:
            st.subheader("Supervisor")
            if st.button("Supervisor Status"):
                command = "supervisorctl status"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err
                if code != 0 and not err:
                    st.session_state.last_error = f"Comando supervisorctl falhou (código {code}). O Supervisor está rodando e o socket acessível?"

            if st.button("Reiniciar Todos (Supervisor)"):
                command = "supervisorctl restart all"
                st.session_state.last_command = command
                out, err, code = execute_command(command)
                st.session_state.last_output = out
                st.session_state.last_error = err

            # Opção para reiniciar serviço específico
            st.markdown("---") # Divisor visual
            supervisor_service = st.text_input("Nome do Serviço Supervisor", placeholder="ex: my_app_name")
            if st.button("Reiniciar Serviço Específico"):
                if supervisor_service:
                    command = f"supervisorctl restart {supervisor_service.strip()}"
                    st.session_state.last_command = command
                    out, err, code = execute_command(command)
                    st.session_state.last_output = out
                    st.session_state.last_error = err
                else:
                    st.warning("Por favor, insira o nome do serviço Supervisor.")


    # --- Seção de Comando Customizado ---
    st.header("⌨️ Comando Customizado")
    custom_command = st.text_area("Digite seu comando Linux aqui:", height=100)
    if st.button("Executar Comando Customizado"):
        if custom_command:
            st.session_state.last_command = custom_command
            out, err, code = execute_command(custom_command)
            st.session_state.last_output = out
            st.session_state.last_error = err
        else:
            st.warning("Por favor, digite um comando.")

    # --- Área de Output ---
    st.divider()
    st.header("📋 Output do Último Comando")

    if st.session_state.last_command:
        st.info(f"**Comando Executado:** `{st.session_state.last_command}`")

        if st.session_state.last_output:
            st.subheader("Saída Padrão (stdout):")
            st.code(st.session_state.last_output, language='bash')
        else:
            st.caption("Nenhuma saída padrão (stdout).")

        if st.session_state.last_error:
            st.subheader("Saída de Erro (stderr):")
            st.error(f"```{st.session_state.last_error}```") # Usar st.error para destacar
        else:
             st.caption("Nenhuma saída de erro (stderr).")
    else:
        st.info("Nenhum comando foi executado ainda nesta sessão.")

# --- Rodapé (Opcional) ---
st.divider()
st.caption("Desenvolvido com Streamlit e Paramiko")

# --- Lógica para rodar o app (se executado diretamente) ---
# Normalmente você rodaria com 'streamlit run app.py --server.port 8555'
# Este bloco é mais para entendimento
if __name__ == "__main__":
    # Esta parte não será executada quando rodar com 'streamlit run'
    # mas pode ser útil para debug ou se você integrar com outra coisa.
    # Para rodar na porta 8555, use o comando no terminal.
    pass
