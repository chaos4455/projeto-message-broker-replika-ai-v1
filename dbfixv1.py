# -*- coding: utf-8 -*-
import sqlite3
import os
import sys

# --- Configurações (Ajuste se necessário) ---
DB_DIR = 'databases'
DB_FILENAME = 'message_broker_v3.db'
DB_PATH = os.path.abspath(os.path.join(DB_DIR, DB_FILENAME))
# --- Fim das Configurações ---

def add_updated_at_column_direct():
    """Conecta diretamente ao SQLite e adiciona a coluna 'updated_at'."""

    print(f"--- Iniciando Script de Correção Direta (sqlite3): Adicionar Coluna 'updated_at' ---")
    print(f"Banco de dados alvo: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print(f"❌ Erro: Arquivo de banco de dados não encontrado em '{DB_PATH}'.")
        print("   O script da API precisa ser executado pelo menos uma vez para criar o DB inicial.")
        sys.exit(1)

    # Comando SQL para adicionar a coluna (SQLite)
    # Adicionamos como NULLABLE para não dar erro em linhas existentes
    # e IF NOT EXISTS para segurança, embora a verificação de erro seja mais robusta
    sql_command = "ALTER TABLE queues ADD COLUMN updated_at DATETIME NULL;"
    # SQL para verificar se a coluna já existe (específico do SQLite)
    sql_check_column = "SELECT COUNT(*) FROM pragma_table_info('queues') WHERE name='updated_at';"


    conn = None # Inicializa a conexão fora do try para poder usar no finally
    try:
        print("🔌 Conectando diretamente ao banco de dados SQLite...")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        print("   Conectado.")

        # 1. Verificar se a coluna já existe
        print("🔍 Verificando se a coluna 'updated_at' já existe...")
        cursor.execute(sql_check_column)
        result = cursor.fetchone()
        column_exists = result[0] > 0

        if column_exists:
            print("✅ A coluna 'updated_at' já existe na tabela 'queues'. Nenhuma alteração necessária.")
        else:
            # 2. Se não existe, tentar adicionar
            print(" कॉलम 'updated_at' não encontrada. Tentando adicionar...") # (Coluna em Hindi, mantido por consistência se foi erro de digitação)
            print(f"🚀 Executando comando SQL: {sql_command}")
            cursor.execute(sql_command)
            # Commit é necessário para ALTER TABLE no sqlite3
            conn.commit()
            print("✅ Sucesso! Coluna 'updated_at' adicionada à tabela 'queues'.")

    except sqlite3.Error as e:
        # O erro "duplicate column name" pode ocorrer se a verificação falhar por algum motivo
        if "duplicate column name: updated_at" in str(e).lower():
             print(f"ℹ️  Aviso: A coluna 'updated_at' já existe (detectado via erro). Nenhuma alteração feita.")
        else:
            print(f"❌ Erro do SQLite ao tentar modificar a tabela:")
            print(f"   Tipo de Erro: {type(e).__name__}")
            print(f"   Mensagem: {e}")
            print("   Verifique se a tabela 'queues' existe e se o comando SQL está correto.")
            # Rollback pode ser útil se outras operações estivessem na transação
            if conn:
                conn.rollback()
    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado:")
        print(e)
    finally:
        if conn:
            print("🔒 Fechando a conexão com o banco de dados SQLite...")
            conn.close()
            print("   Conexão fechada.")
        print("--- Script de Correção Direta Concluído ---")

# Executa a função
if __name__ == "__main__":
    print("*********************************************************************")
    print("* IMPORTANTE:                                                       *")
    print("* 1. PARE o servidor da API ANTES de executar este script.          *")
    print("* 2. FAÇA UM BACKUP do arquivo .db como precaução.                  *")
    print("*    Arquivo: databases/message_broker_v3.db                        *")
    print("*********************************************************************")
    try:
      input("Pressione Enter para continuar ou Ctrl+C para cancelar...")
    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
        sys.exit(0)

    add_updated_at_column_direct()