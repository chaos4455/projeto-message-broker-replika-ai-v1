# -*- coding: utf-8 -*-
import os
import platform
import datetime
import google.generativeai as genai
from colorama import init, Fore, Style
import inquirer
from typing import List, Dict, Any
import time

# Inicializa o Colorama (sempre reinicia a cor após cada print)
init(autoreset=True)

# --- Configurações ---
# !!! ATENÇÃO MUITO IMPORTANTE !!!
# ==========================================================================
# NUNCA coloque sua API Key diretamente no código em produção ou compartilhado.
# Use variáveis de ambiente (recomendado) ou um sistema seguro de gerenciamento
# de segredos. Expor sua chave pode levar ao uso indevido e custos inesperados.
# Este código é um EXEMPLO, substitua pela sua chave APENAS para teste local
# e ISOLADO, ciente dos riscos.
# Exemplo usando variável de ambiente (preferível):
# API_KEY = os.environ.get("GOOGLE_API_KEY")
# if not API_KEY:
#    print(Fore.RED + Style.BRIGHT + "Erro: Variável de ambiente GOOGLE_API_KEY não definida.")
#    exit()
# ==========================================================================
API_KEY = 'AIzaSyC7dAwSyLKaVO2E-PA6UaacLZ4aLGtrXbY'  # <--- SUBSTITUA AQUI COM MUITO CUIDADO!!!

# Configuração da API do Google Generative AI
try:
    genai.configure(api_key=API_KEY)
    # Verifique modelos disponíveis se necessário:
    # for m in genai.list_models():
    #   if 'generateContent' in m.supported_generation_methods:
    #     print(m.name)
    NOME_MODELO = "gemini-1.5-flash" # Modelo mais recente e geralmente capaz

    # Configurações de geração (ajuste conforme necessário)
    generation_config = {
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 64,
        "max_output_tokens": 8192,
        # CORREÇÃO: A API espera 'text/plain' para respostas de texto genéricas.
        # A *instrução* dentro do prompt pedirá formatação Markdown.
        "response_mime_type": "text/plain",
    }
    model = genai.GenerativeModel(
        model_name=NOME_MODELO,
        generation_config=generation_config,
        # safety_settings = Ajuste as configurações de segurança se necessário
        # Exemplo:
        # safety_settings=[
        #    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        #    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        #    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        #    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        # ]
    )
    print(Fore.GREEN + f"Modelo Generative AI '{NOME_MODELO}' configurado com sucesso.")

except ValueError as ve:
    if "API_KEY" in str(ve):
        print(Fore.RED + Style.BRIGHT + "Erro: API Key inválida ou não configurada corretamente.")
        print(Fore.YELLOW + "Verifique se a API Key foi substituída corretamente no código ou configurada via variável de ambiente.")
    else:
        print(Fore.RED + Style.BRIGHT + f"Erro de valor ao configurar a API: {ve}")
    exit()
except Exception as e:
    print(Fore.RED + Style.BRIGHT + f"Erro inesperado ao configurar a API Generative AI: {e}")
    exit()


# Ícones para UI
PYTHON_ICON = "🐍"
FOLDER_ICON = "📁"
DOC_ICON = "📄"
ERROR_ICON = "❌"
SUCCESS_ICON = "✅"
QUESTION_ICON = "❓"
WAIT_ICON = "⏳"
ROCKET_ICON = "🚀"
WARNING_ICON = "⚠️"

# Nome da pasta onde os documentos serão salvos (na raiz do script)
OUTPUT_FOLDER_NAME = "documenta-projeto"

# --- Funções Auxiliares ---

def get_script_directory() -> str:
    """Retorna o diretório onde o script está sendo executado."""
    # Usa __file__ que é o caminho do script atual
    return os.path.dirname(os.path.abspath(__file__))

def create_output_directory(base_dir: str) -> str:
    """Cria a pasta de saída na base_dir se ela não existir."""
    output_path = os.path.join(base_dir, OUTPUT_FOLDER_NAME)
    try:
        os.makedirs(output_path, exist_ok=True)
        return output_path
    except OSError as e:
        print(Fore.RED + f"{ERROR_ICON} Erro ao criar o diretório de saída '{output_path}': {e}")
        return "" # Retorna vazio em caso de erro

def get_python_files_from_dir(directory_path: str) -> List[str]:
    """Lista todos os arquivos .py em um diretório e subdiretórios, retornando caminhos relativos."""
    python_files = []
    if not os.path.isdir(directory_path):
        print(Fore.YELLOW + f"{WARNING_ICON} Aviso: O caminho '{directory_path}' não é um diretório válido.")
        return []
    try:
        # Normaliza o path de entrada para evitar problemas com barras
        start_path = os.path.abspath(directory_path)
        for root, _, files in os.walk(start_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    # Calcula o caminho relativo a partir do diretório fornecido pelo usuário
                    relative_path = os.path.relpath(full_path, start_path)
                    python_files.append(relative_path)
        return sorted(python_files) # Ordena para consistência
    except Exception as e:
        print(Fore.RED + f"{ERROR_ICON} Erro ao listar arquivos Python em '{directory_path}': {e}")
        return []

def select_files_interactive(file_list: List[str], base_path: str) -> List[str]:
    """Permite ao usuário selecionar arquivos de uma lista usando inquirer. Retorna caminhos completos."""
    if not file_list:
        print(Fore.YELLOW + f"{WARNING_ICON} Nenhum arquivo Python encontrado no diretório para selecionar.")
        return []

    # Mostra caminhos relativos na interface, mas armazena caminhos completos
    choices = [(f"{PYTHON_ICON} {relative_f}", os.path.join(base_path, relative_f)) for relative_f in file_list]

    questions = [
        inquirer.Checkbox('selected_files',
                          message=Fore.CYAN + f"{QUESTION_ICON} Selecione os arquivos .py para incluir na documentação (use ESPAÇO para marcar, ENTER para confirmar):",
                          choices=choices,
                          )
    ]
    try:
        answers = inquirer.prompt(questions, theme=inquirer.themes.Default()) # Usar tema padrão
        if answers and 'selected_files' in answers:
            # Retorna a lista de caminhos *completos* dos arquivos selecionados
            return answers['selected_files']
        else:
            # Caso o usuário cancele (Ctrl+C) ou não selecione nada
             print(Fore.YELLOW + f"{WARNING_ICON} Nenhum arquivo selecionado.")
             return []
    except Exception as e:
        print(Fore.RED + f"{ERROR_ICON} Ocorreu um erro durante a seleção de arquivos: {e}")
        return []
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nSeleção cancelada pelo usuário.")
        return []


def read_file_content(file_path: str) -> str:
    """Lê o conteúdo de um arquivo de texto (raw)."""
    try:
        # Tenta detectar a codificação, mas usa utf-8 como fallback robusto
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252']
        content = None
        for enc in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    content = f.read()
                break # Sai do loop se a leitura for bem-sucedida
            except UnicodeDecodeError:
                continue # Tenta a próxima codificação
            except Exception as inner_e:
                 # Captura outros erros de leitura aqui para não falhar silenciosamente
                 print(Fore.YELLOW + f"{WARNING_ICON} Erro ao ler {os.path.basename(file_path)} com encoding {enc}: {inner_e}")
                 continue

        if content is None:
             print(Fore.RED + f"{ERROR_ICON} Não foi possível ler o arquivo {os.path.basename(file_path)} com as codificações testadas.")
             return ""
        return content

    except FileNotFoundError:
        print(Fore.RED + f"{ERROR_ICON} Arquivo não encontrado: {file_path}")
        return ""
    except Exception as e:
        # Erro genérico se algo mais der errado
        print(Fore.RED + f"{ERROR_ICON} Erro inesperado ao ler o arquivo {file_path}: {e}")
        return ""

def ask_for_user_prompt() -> str:
    """Pede ao usuário um prompt adicional opcional."""
    print(Fore.CYAN + f"\n{QUESTION_ICON} Deseja adicionar alguma instrução específica para a IA sobre como gerar a documentação?")
    user_input = input(Fore.CYAN + Style.DIM + " (Ex: Foque na API pública, explique a lógica de negócios, ignore testes. Deixe em branco para usar o prompt padrão): " + Style.RESET_ALL)
    return user_input.strip()

def generate_documentation(code_snippets: Dict[str, str], user_prompt: str) -> str:
    """Envia o código (como texto bruto) e os prompts para a IA e retorna a documentação."""
    if not code_snippets:
        print(Fore.YELLOW + f"{WARNING_ICON} Nenhum conteúdo de código para enviar à IA.")
        # Ainda pode gerar documentação se houver um prompt do usuário
        if not user_prompt:
             return "Nenhum código ou instrução fornecida para documentação."

    # Constrói o contexto com os trechos de código (texto bruto)
    # Usa o caminho relativo como identificador para a IA
    code_context = "\n\n".join(
        f"--- INÍCIO ARQUIVO: {relative_path} ---\n"
        f"```python\n"
        f"{content}\n" # Conteúdo bruto do arquivo .py
        f"```\n"
        f"--- FIM ARQUIVO: {relative_path} ---"
        for relative_path, content in code_snippets.items()
    ) if code_snippets else "Nenhum código foi fornecido." # Mensagem se não houver snippets

    # Prompt base para guiar a IA
    # Instruindo explicitamente para usar formato Markdown na *resposta*
    base_prompt = f"""
    **Tarefa:** Gerar documentação técnica abrangente em formato Markdown para um projeto Python, com base nos arquivos de código fornecidos (como texto bruto) e nas instruções do usuário.


        responda longo, altamente detalhado, em mais de 1200 linhas, use icones, emojis, altamente completo, técnico, em nivel de engenharia de software e arquitetura de softeware, 
    **Foco Principal:**
    *   **Visão Geral e Propósito:** Descreva o objetivo central do projeto. Que problema ele resolve?
    *   **Funcionalidades Chave:** Liste e explique as principais capacidades e o que o software faz.
    *   **Estrutura do Projeto (Inferida):** Com base nos arquivos fornecidos, descreva como eles parecem se conectar. Qual o fluxo de dados ou controle principal? (Seja cauteloso se poucos arquivos foram fornecidos).
    *   **Componentes Importantes:** Identifique classes, funções ou módulos cruciais e explique seu papel.
    *   **Como Usar/Executar (se aplicável/inferível):** Forneça um guia básico sobre como iniciar ou interagir com o projeto. Mencione pontos de entrada principais (como blocos `if __name__ == '__main__':`).
    *   **Dependências Externas:** Liste as bibliotecas externas importantes identificadas nos `import` statements.

    **Instruções de Geração:**
    *   **Foco em Funcionalidade:** Priorize explicar *o que* o código faz e *por quê*, em vez de apenas descrever *como* linha por linha.
    *   **Clareza e Concisão:** Use linguagem clara e objetiva.
    *   **Formato Markdown:** Organize a documentação usando cabeçalhos (##, ###), listas (marcadores ou numeradas), e blocos de código (\`\`\`python ... \`\`\`) para exemplos curtos ou referências, *mas evite apenas copiar grandes blocos do código fonte fornecido*.
    *   **Interpretação vs. Repetição:** Vá além de simplesmente parafrasear o código; explique o propósito no contexto do projeto.
    *   **Evite Especulação Excessiva:** Se a informação não está clara no código, mencione isso ou evite fazer suposições infundadas.

    **Instrução Adicional do Usuário:**
    {user_prompt if user_prompt else "Nenhuma instrução adicional fornecida."}

    **Código Fonte Fornecido (Texto Bruto):**
    {code_context}

    **SAÍDA ESPERADA:** Documentação completa e bem estruturada em formato **Markdown**.
    """

    print(Fore.MAGENTA + f"\n{WAIT_ICON} Enviando solicitação para a IA ({NOME_MODELO}). Isso pode levar alguns segundos ou minutos dependendo do tamanho do código...")

    # Adiciona um pequeno delay antes de enviar, pode ajudar em algumas situações de rede/API
    time.sleep(1)

    try:
        # Inicia um novo chat para cada documentação para evitar misturar contextos antigos
        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(base_prompt)

        # Pequena pausa após receber a resposta, caso haja processamento assíncrono
        time.sleep(1)

        # Verifica se a resposta contém texto
        if response and hasattr(response, 'text') and response.text:
            print(Fore.GREEN + f"{SUCCESS_ICON} Resposta recebida da IA!")
            return response.text
        elif response and hasattr(response, 'parts'): # Modelos mais novos podem usar 'parts'
             full_text = "".join(part.text for part in response.parts if hasattr(part, 'text'))
             if full_text:
                 print(Fore.GREEN + f"{SUCCESS_ICON} Resposta (via 'parts') recebida da IA!")
                 return full_text
             else:
                 print(Fore.YELLOW + f"{WARNING_ICON} Resposta da IA recebida, mas sem conteúdo textual nos 'parts'.")
                 # Tenta obter o conteúdo bruto da resposta para depuração
                 try:
                     print(Fore.YELLOW + f"Conteúdo bruto da resposta: {response}")
                 except Exception:
                      pass # Ignora se não conseguir imprimir a resposta bruta
                 return "Erro: A IA retornou uma resposta sem conteúdo textual."
        else:
            print(Fore.YELLOW + f"{WARNING_ICON} A IA retornou uma resposta vazia ou inesperada.")
            # Tenta obter o conteúdo bruto da resposta para depuração
            try:
                 print(Fore.YELLOW + f"Conteúdo bruto da resposta: {response}")
            except Exception:
                 pass # Ignora se não conseguir imprimir a resposta bruta
            return "Erro: A IA retornou uma resposta vazia ou em formato inesperado."

    except google.api_core.exceptions.InvalidArgument as e:
        print(Fore.RED + Style.BRIGHT + f"{ERROR_ICON} Erro de Argumento Inválido ao comunicar com a API: {e}")
        if "response_mime_type" in str(e):
            print(Fore.RED + "   -> Verifique se o 'response_mime_type' ('text/plain') é suportado pelo modelo/API.")
        return f"Erro de Argumento Inválido na API: {e}"
    except google.generativeai.types.generation_types.BlockedPromptException as bpe:
         print(Fore.RED + Style.BRIGHT + f"{ERROR_ICON} O prompt foi bloqueado pela API devido a políticas de segurança.")
         print(Fore.YELLOW + "   -> Revise o código ou o prompt adicional para remover conteúdo potencialmente problemático.")
         # Pode ser útil imprimir as razões do bloqueio, se disponíveis
         # print(f"Block reasons: {bpe.block_reason}") # Depende da versão da lib
         return "Erro: Prompt bloqueado por razões de segurança."
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"{ERROR_ICON} Erro inesperado ao comunicar com a API Generative AI: {e}")
        # Tenta extrair detalhes do erro, se disponíveis (útil para erros 4xx, 5xx)
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
             print(Fore.RED + f"Detalhes da resposta da API (se houver): {e.response.text}")
        return f"Erro ao gerar documentação: {e}"
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nGeração de documentação cancelada pelo usuário durante a comunicação com a IA.")
        return "Geração cancelada."


def save_documentation(content: str, output_dir: str, project_name: str, selected_files: List[str]) -> bool:
    """Salva o conteúdo da documentação em um arquivo Markdown (.md)."""
    if not content or content.startswith("Erro:") or content == "Geração cancelada.":
         print(Fore.YELLOW + f"{WARNING_ICON} Nenhuma documentação válida para salvar.")
         return False

    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Limpa um pouco o nome do projeto para o nome do arquivo
        safe_project_name = "".join(c if c.isalnum() else "_" for c in project_name)
        filename = f"doc_{safe_project_name}_{timestamp}.md" # Garante extensão .md
        filepath = os.path.join(output_dir, filename)

        print(f"\n{WAIT_ICON} Preparando para salvar o arquivo: {filepath}")

        with open(filepath, 'w', encoding='utf-8') as f:
            # Cabeçalho do Arquivo Markdown
            f.write(f"# {DOC_ICON} Documentação do Projeto: {project_name}\n\n")
            f.write(f"**Gerado em:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Plataforma:** {platform.system()} {platform.release()}\n")
            f.write(f"**Modelo IA:** {NOME_MODELO}\n")

            if selected_files:
                 f.write(f"**Arquivos Analisados:**\n")
                 # Lista os arquivos relativos que foram usados
                 base_dir = os.path.dirname(selected_files[0]) # Pega o dir base do primeiro arquivo
                 for full_path in selected_files:
                    relative_p = os.path.relpath(full_path, os.path.dirname(base_dir)) # Caminho relativo ao pai do dir do projeto
                    f.write(f"- `{relative_p}`\n")
            else:
                 f.write("**Arquivos Analisados:** Nenhum código fonte foi incluído na análise.\n")

            f.write("\n---\n\n") # Separador

            # Escreve o conteúdo gerado pela IA
            f.write(content)

        print(Fore.GREEN + Style.BRIGHT + f"{SUCCESS_ICON} Documentação salva com sucesso em: {filepath}")
        return True
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"{ERROR_ICON} Erro ao salvar o arquivo de documentação '{filepath}': {e}")
        return False

def ask_to_repeat() -> bool:
    """Pergunta ao usuário se deseja executar o processo novamente."""
    questions = [
        inquirer.Confirm('repeat',
                         message=Fore.YELLOW + f"\n{QUESTION_ICON} Deseja documentar outro projeto ou conjunto de arquivos?",
                         default=False)
    ]
    try:
        answers = inquirer.prompt(questions, theme=inquirer.themes.Default())
        # Retorna False se answers for None (acontece com Ctrl+C no prompt)
        return answers['repeat'] if answers else False
    except KeyboardInterrupt:
         print(Fore.YELLOW + "\nOperação finalizada pelo usuário.")
         return False
    except Exception as e:
        # Pode acontecer se o terminal não suportar inquirer bem
        print(Fore.RED + f"{ERROR_ICON} Erro ao tentar exibir a confirmação: {e}")
        # Fallback para input simples
        try:
            response = input(Fore.YELLOW + f"\n{QUESTION_ICON} Deseja documentar outro projeto? (s/N): ").lower()
            return response == 's'
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nOperação finalizada pelo usuário.")
            return False
        except Exception as fallback_e:
             print(Fore.RED + f"{ERROR_ICON} Erro no input de fallback: {fallback_e}")
             return False


# --- Função Principal ---
def main_documentation_loop():
    """Controla o fluxo principal de documentação."""
    print(Fore.BLUE + Style.BRIGHT + f"\n{ROCKET_ICON} Bem-vindo ao Documentador de Projetos com IA! {ROCKET_ICON}")
    print(Fore.WHITE + Style.DIM + "Usando modelo: " + NOME_MODELO)

    script_dir = get_script_directory()
    output_dir = create_output_directory(script_dir)

    if not output_dir:
        print(Fore.RED + Style.BRIGHT + "Não foi possível criar ou acessar o diretório de saída. Encerrando.")
        return

    print(Fore.GREEN + f"Os arquivos de documentação (.md) serão salvos em: {output_dir}")

    while True:
        # 1. Obter Diretório do Projeto
        project_dir_input = input(Fore.CYAN + f"\n{FOLDER_ICON} Digite o caminho para a pasta do projeto que deseja documentar (ou deixe em branco para usar o diretório atual): ").strip()

        if not project_dir_input:
            project_dir = script_dir # Usa o diretório do script se nada for digitado
            print(Fore.WHITE + f"Usando o diretório atual do script: '{project_dir}'")
        else:
            project_dir = os.path.abspath(project_dir_input) # Garante caminho absoluto

        if not os.path.isdir(project_dir):
            print(Fore.RED + f"{ERROR_ICON} Caminho fornecido não é um diretório válido: '{project_dir}'. Tente novamente.")
            continue # Pede o diretório novamente

        # Tenta pegar um nome significativo para o projeto (nome da pasta)
        project_name = os.path.basename(project_dir)
        if not project_name: # Pode acontecer se for a raiz (ex: C:\)
            project_name = "projeto_raiz"
        print(Fore.WHITE + f"Analisando o projeto: '{project_name}' em '{project_dir}'")

        # 2. Listar Arquivos .py
        py_files_relative = get_python_files_from_dir(project_dir)

        # 3. Selecionar Arquivos Interativamente
        # selected_full_paths contém os caminhos *completos* dos arquivos selecionados
        selected_full_paths = select_files_interactive(py_files_relative, project_dir)

        # 4. Ler Conteúdo dos Arquivos Selecionados (Texto Bruto)
        code_snippets = {} # Dicionário para guardar {caminho_relativo: conteudo}
        if selected_full_paths:
            print(Fore.WHITE + f"\n{WAIT_ICON} Lendo o conteúdo de {len(selected_full_paths)} arquivo(s) selecionado(s)...")
            files_read_count = 0
            files_error_count = 0
            for full_file_path in selected_full_paths:
                 # Garante que o caminho completo esteja normalizado
                 normalized_path = os.path.normpath(full_file_path)
                 content = read_file_content(normalized_path)
                 if content is not None: # Verifica se a leitura foi bem sucedida (não None)
                     # Calcula o caminho relativo *a partir do diretório do projeto* para usar como chave
                     relative_path_for_key = os.path.relpath(normalized_path, project_dir)
                     code_snippets[relative_path_for_key] = content
                     files_read_count += 1
                     # print(Fore.GREEN + f"  + Lido: {relative_path_for_key}") # Opcional: verbosidade
                 else:
                     # read_file_content já imprime o erro/aviso
                     files_error_count += 1
                     print(Fore.YELLOW + f"  - Aviso: Falha ao ler ou conteúdo vazio para {os.path.basename(normalized_path)}")

            if files_read_count > 0:
                print(Fore.GREEN + f"Leitura concluída: {files_read_count} arquivo(s) lido(s).")
            if files_error_count > 0:
                print(Fore.YELLOW + f"{WARNING_ICON} {files_error_count} arquivo(s) não puderam ser lidos ou estavam vazios.")
        else:
            print(Fore.YELLOW + f"{WARNING_ICON} Nenhum arquivo Python selecionado para incluir o código na análise.")
            # Pergunta se ainda quer continuar apenas com o prompt
            continue_without_code_q = [
                 inquirer.Confirm('continue_no_code',
                                  message=Fore.YELLOW + f"{QUESTION_ICON} Nenhum código será enviado à IA. Deseja continuar assim mesmo (apenas com instruções adicionais, se houver)?",
                                  default=False)
            ]
            try:
                answers = inquirer.prompt(continue_without_code_q, theme=inquirer.themes.Default())
                if not answers or not answers['continue_no_code']:
                     print(Fore.BLUE + "Ok, processo de documentação cancelado para este projeto.")
                     if not ask_to_repeat():
                         break # Sai do loop principal (while True)
                     else:
                         continue # Volta para o início do loop while (pedir novo projeto)
            except Exception as ie:
                 print(Fore.RED + f"{ERROR_ICON} Erro no prompt de confirmação: {ie}. Cancelando.")
                 if not ask_to_repeat():
                    break
                 else:
                    continue
            except KeyboardInterrupt:
                 print(Fore.YELLOW + "\nOperação cancelada pelo usuário.")
                 break # Sai do loop principal

        # 5. Obter Prompt Adicional do Usuário
        user_prompt = ask_for_user_prompt()

        # 6. Gerar Documentação com a IA
        # Passa os snippets de código (dict) e o prompt do usuário
        documentation_content = generate_documentation(code_snippets, user_prompt)

        # 7. Salvar Documentação (como .md)
        # Passa também a lista de arquivos que foram efetivamente lidos e enviados
        files_actually_sent_paths = [os.path.join(project_dir, rel_path) for rel_path in code_snippets.keys()]
        save_documentation(documentation_content, output_dir, project_name, files_actually_sent_paths)

        # 8. Perguntar se deseja repetir
        if not ask_to_repeat():
            break # Sai do loop principal (while True)

    print(Fore.BLUE + Style.BRIGHT + "\nObrigado por usar o Documentador de Projetos! Até logo! 👋")

# --- Ponto de Entrada ---
if __name__ == "__main__":
    try:
        main_documentation_loop()
    except KeyboardInterrupt:
        # Captura Ctrl+C no nível mais alto para uma saída graciosa
        print(Fore.YELLOW + Style.BRIGHT + "\n\nPrograma interrompido pelo usuário (Ctrl+C). Encerrando.")
    except Exception as e:
        # Captura qualquer outra exceção não tratada no loop principal
        print(Fore.RED + Style.BRIGHT + f"\n{ERROR_ICON} Ocorreu um erro fatal inesperado no fluxo principal:")
        import traceback
        traceback.print_exc() # Imprime o traceback completo para depuração
    finally:
        print(Style.RESET_ALL) # Garante que as cores sejam resetadas ao sair