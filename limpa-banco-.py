import sqlite3
import os

def limpar_tabelas_blockchain_mantendo_duas_linhas(db_path):
    """
    Limpa os dados das tabelas 'blockchain_blocos', 'transacao' e 'pool_mineracao'
    no banco de dados SQLite especificado, mantendo apenas as duas primeiras linhas de cada tabela.
    As outras linhas serão completamente removidas.
    Após a limpeza, executa VACUUM para reduzir o tamanho do arquivo DB.

    Args:
        db_path (str): Caminho para o arquivo do banco de dados SQLite.
    """
    conn = None  # Inicializa conn fora do bloco try para usar no finally
    try:
        # Conecta ao banco de dados SQLite
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        tabelas_para_limpar = ['blockchain_blocos', 'transacao', 'pool_mineracao']

        for tabela in tabelas_para_limpar:
            # Conta o número de linhas antes da limpeza
            cursor.execute(f"SELECT COUNT(*) FROM {tabela}")
            linhas_antes = cursor.fetchone()[0]
            print(f"Tabela '{tabela}': Linhas antes da limpeza: {linhas_antes}")

            # Deleta todos os dados da tabela, exceto as duas primeiras linhas ordenadas por ID
            cursor.execute(f"""
                DELETE FROM {tabela}
                WHERE id NOT IN (SELECT id FROM {tabela} ORDER BY id ASC LIMIT 2)
            """)
            print(f"Dados da tabela '{tabela}' limpos, mantendo as 2 primeiras linhas.")

            # Conta o número de linhas após a limpeza
            cursor.execute(f"SELECT COUNT(*) FROM {tabela}")
            linhas_depois = cursor.fetchone()[0]
            print(f"Tabela '{tabela}': Linhas após a limpeza: {linhas_depois}")

        # Commita as alterações (IMPORTANTE: Commitar antes do VACUUM)
        conn.commit()
        print("Alterações commitadas.")

        # Executa VACUUM para reduzir o tamanho do arquivo
        cursor.execute("VACUUM")
        conn.commit() # Commita o VACUUM também
        print("Comando VACUUM executado para reduzir o tamanho do arquivo.")


        print("Operação de limpeza concluída (mantendo as duas primeiras linhas de cada tabela e reduzindo o tamanho do DB).")

    except sqlite3.Error as e:
        print(f"Erro ao limpar o banco de dados: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    db_file = 'blockchain.db' # Nome do arquivo do banco de dados na raiz
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_file) # Caminho completo para o db

    if os.path.exists(db_path):
        tamanho_inicial = os.path.getsize(db_path) / (1024 * 1024) # Tamanho em MB
        print(f"Tamanho inicial do banco de dados: {tamanho_inicial:.2f} MB")
        limpar_tabelas_blockchain_mantendo_duas_linhas(db_path)
        tamanho_final = os.path.getsize(db_path) / (1024 * 1024) # Tamanho em MB
        print(f"Tamanho final do banco de dados após limpeza e VACUUM: {tamanho_final:.2f} MB")
        if tamanho_final < tamanho_inicial:
            print("O tamanho do banco de dados foi reduzido com sucesso!")
        else:
            print("O tamanho do banco de dados não foi reduzido (ou a redução foi insignificante).")

    else:
        print(f"Banco de dados '{db_path}' não encontrado na raiz do script.")