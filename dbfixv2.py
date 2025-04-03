# -*- coding: utf-8 -*-
import sqlite3
import os
import sys

# --- Configurações (Ajuste se necessário) ---
DB_DIR = 'databases'
DB_FILENAME = 'message_broker_v3.db'
DB_PATH = os.path.abspath(os.path.join(DB_DIR, DB_FILENAME))
# --- Fim das Configurações ---

# Lista de correções a serem aplicadas: (table_name, column_name, column_type_sql)
corrections = [
    ('queues',   'updated_at', 'DATETIME NULL'),
    ('messages', 'updated_at', 'DATETIME NULL'),
    # Adicione outras correções aqui se necessário no futuro
    # Ex: ('messages', 'retry_count', 'INTEGER DEFAULT 0')
]

def apply_schema_corrections():
    """Conecta diretamente ao SQLite e aplica as correções de esquema necessárias."""

    print(f"--- Iniciando Script de Correção de Esquema (sqlite3) ---")
    print(f"Banco de dados alvo: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print(f"❌ Erro: Arquivo de banco de dados não encontrado em '{DB_PATH}'.")
        print("   Execute o script da API principal primeiro para criar o DB.")
        sys.exit(1)

    conn = None
    all_successful = True # Flag para rastrear o sucesso geral

    try:
        print("🔌 Conectando diretamente ao banco de dados SQLite...")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        print("   Conectado.")

        print("\n--- Verificando e Aplicando Correções ---")
        for table_name, column_name, column_type in corrections:
            print(f"\n -> Verificando Tabela: '{table_name}', Coluna: '{column_name}'")

            # SQL para verificar se a coluna já existe
            sql_check_column = f"SELECT COUNT(*) FROM pragma_table_info('{table_name}') WHERE name='{column_name}';"
            # Comando SQL para adicionar a coluna
            sql_add_column = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type};"

            try:
                cursor.execute(sql_check_column)
                result = cursor.fetchone()
                column_exists = result[0] > 0

                if column_exists:
                    print(f"    ✅ Coluna '{column_name}' já existe em '{table_name}'.")
                else:
                    print(f"    ⚠️ Coluna '{column_name}' não encontrada em '{table_name}'. Tentando adicionar...")
                    print(f"       Executando: {sql_add_column}")
                    cursor.execute(sql_add_column)
                    # Commit APÓS CADA ALTER TABLE bem-sucedido é mais seguro
                    conn.commit()
                    print(f"    ✅ Sucesso! Coluna '{column_name}' adicionada a '{table_name}'.")

            except sqlite3.Error as e_inner:
                 # Verifica erro específico de coluna duplicada
                if f"duplicate column name: {column_name}" in str(e_inner).lower():
                     print(f"    ℹ️ Aviso: Coluna '{column_name}' já existe em '{table_name}' (detectado via erro).")
                else:
                    print(f"    ❌ Erro do SQLite ao processar '{table_name}'.'{column_name}':")
                    print(f"       {type(e_inner).__name__}: {e_inner}")
                    all_successful = False
                    # Interrompe em caso de erro inesperado para esta correção específica
                    break

    except sqlite3.Error as e_outer:
        print(f"\n❌ Erro Crítico do SQLite durante a conexão ou operação geral:")
        print(f"   {type(e_outer).__name__}: {e_outer}")
        all_successful = False
        if conn:
            conn.rollback() # Desfaz qualquer alteração pendente na transação atual
    except Exception as e_generic:
        print(f"\n❌ Ocorreu um erro inesperado:")
        print(e_generic)
        all_successful = False
    finally:
        if conn:
            print("\n🔒 Fechando a conexão com o banco de dados SQLite...")
            conn.close()
            print("   Conexão fechada.")

        print("\n--- Script de Correção de Esquema Concluído ---")
        if all_successful:
            print("🎉 Todas as verificações/correções foram concluídas (ou não foram necessárias).")
        else:
            print("🛑 Ocorreram erros durante o processo. Verifique os logs acima.")


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

    apply_schema_corrections()