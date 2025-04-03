# Guia de Contribuição

## 📝 Introdução
Obrigado por considerar contribuir com o Message Broker! Este documento fornece as diretrizes e o processo para contribuir com o projeto.

## 🎯 Como Contribuir

### 1. Reportando Bugs
- Use o template de issue
- Descreva o bug em detalhes
- Inclua passos para reproduzir
- Adicione logs e screenshots
- Especifique o ambiente

### 2. Sugerindo Melhorias
- Use o template de feature request
- Explique o problema/necessidade
- Descreva a solução proposta
- Liste benefícios
- Considere alternativas

### 3. Pull Requests
- Crie uma branch para sua feature
- Siga o padrão de commits
- Atualize a documentação
- Adicione testes
- Mantenha o código limpo

## 🛠️ Ambiente de Desenvolvimento

### 1. Configuração
```bash
# Clone o repositório
git clone https://github.com/seu-usuario/message-broker.git
cd message-broker

# Crie um ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Instale as dependências
pip install -r requirements.txt
```

### 2. Desenvolvimento
```bash
# Inicie o servidor
uvicorn message_broker_v1:app --reload

# Execute os testes
pytest

# Verifique a documentação
http://localhost:8000/docs
```

## 📚 Padrões de Código

### 1. Python
- PEP 8
- Type hints
- Docstrings
- Comentários claros

### 2. Commits
- Mensagens descritivas
- Prefixos semânticos
- Referências a issues
- Commits atômicos

### 3. Documentação
- README atualizado
- Docstrings
- Comentários
- Exemplos

## 🧪 Testes

### 1. Unitários
- Cobertura > 80%
- Casos de borda
- Mocks quando necessário
- Assertions claros

### 2. Integração
- Fluxos completos
- Diferentes ambientes
- Edge cases
- Performance

### 3. Carga
- Cenários realistas
- Métricas claras
- Limites definidos
- Análise de resultados

## 📊 Métricas de Qualidade

### 1. Código
- Complexidade ciclomática
- Duplicação
- Dependências
- Manutenibilidade

### 2. Performance
- Tempo de resposta
- Uso de recursos
- Escalabilidade
- Concorrência

### 3. Segurança
- Vulnerabilidades
- Dependências
- Configurações
- Permissões

## 🔄 Processo de Review

### 1. Checklist
- Código limpo
- Testes passando
- Documentação atualizada
- Performance adequada

### 2. Feedback
- Construtivo
- Específico
- Respeitoso
- Açãoável

### 3. Aprovação
- Dois reviewers
- Todos os checks
- Sem conflitos
- Documentação OK

## 📝 Licença
Ao contribuir, você concorda que suas contribuições serão licenciadas sob a licença MIT do projeto.

## 👨‍💻 Autor
Elias Andrade - Arquiteto de Soluções
- Email: seu-email@exemplo.com
- LinkedIn: [seu-linkedin](https://linkedin.com/in/seu-usuario)

## 📅 Versão
1.0.0 - 2024-03-19 