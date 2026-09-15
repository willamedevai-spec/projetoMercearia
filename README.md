# Gerenciador de Produtos e Vendas

Sistema web para gestão de produtos, clientes, vendedores e vendas, com dashboard de indicadores e controle de estoque.

## Stack utilizada

- **Backend:** Python 3 + [Flask](https://flask.palletsprojects.com/)
- **Banco de dados:** SQLite3 (via `sqlite3` nativo do Python)
- **Frontend:** HTML5, CSS3 e JavaScript puro (sem frameworks), templates renderizados com Jinja2
- **Autenticação:** sessão de servidor (Flask session) com senha em hash (`werkzeug.security`)
- **Segurança:**
  - [Flask-WTF](https://flask-wtf.readthedocs.io/) — proteção CSRF
  - [Flask-Limiter](https://flask-limiter.readthedocs.io/) — rate limiting

## Funcionalidades

### Dashboard (tela inicial)
- Indicadores gerais: total de produtos, clientes, vendedores e vendas
- Receita total e receita/quantidade de vendas do dia
- Alerta de produtos com estoque baixo (≤ 5 unidades)
- Últimas 5 vendas registradas
- Top 5 produtos mais vendidos

### Produtos
- Cadastro (marca, nome, sabor, valor, quantidade)
- Listagem e remoção

### Clientes
- Cadastro (nome, CPF, telefone, e-mail)
- Listagem e remoção

### Vendedores
- Cadastro (nome, CPF, telefone)
- Listagem e remoção

### Vendas
- Registro de venda com múltiplos itens (produto + quantidade), cliente e vendedor
- Baixa automática de estoque ao registrar a venda
- Validação: um item é ignorado (com aviso) se a quantidade pedida for maior que o estoque disponível
- Histórico de vendas com modal de detalhes (via `/api/venda/<id>`) e página de detalhe dedicada (`/venda/<id>`)

### Autenticação
- Tela de login com usuário e senha (hash `pbkdf2` via Werkzeug)
- Logout
- **Timeout de inatividade:** a sessão expira automaticamente após **15 minutos sem nenhuma requisição**
- **Tempo de vida máximo da sessão:** 2 horas, mesmo com uso contínuo

## Segurança — o que foi identificado e corrigido

Analisando o código enviado, encontrei os seguintes pontos. Os marcados com ✅ já foram corrigidos nesta entrega; os com ⚠️ ficam registrados como recomendação (ver seção seguinte), pois exigem decisão sua (ambiente de produção, infraestrutura, etc.).

| Problema encontrado | Gravidade | Situação |
|---|---|---|
| Rota `/criar_admin` pública, sem autenticação: qualquer pessoa na internet podia acessá-la e criar um usuário admin | **Crítica** | ✅ Removida a rota; virou comando de terminal (`flask --app app.py criar-admin`), que pede senha interativamente e não deixa duplicar o admin |
| `SECRET_KEY` fixa e exposta no código-fonte (`'uma_chave_secreta_super_segura_aqui'`) | **Crítica** | ✅ Agora lida de variável de ambiente (`SECRET_KEY`); se não definida, gera uma aleatória por execução (dev) |
| Sem timeout de sessão / inatividade — sessão ficava válida indefinidamente enquanto o cookie existisse | Alta | ✅ Implementado: 15 min de inatividade + 2h de vida máxima |
| Sem rate limiting em nenhuma rota — login e formulários aceitavam requisições ilimitadas (força bruta, spam, DoS simples) | Alta | ✅ Implementado com Flask-Limiter: limite global de 20/min e 100/hora por IP; login limitado a **5 tentativas por minuto**; cadastros a 20–30/min |
| Sem proteção CSRF nos formulários (qualquer site externo podia forjar um POST autenticado, ex. excluir cliente, cadastrar produto, etc., enquanto a vítima estivesse logada) | Alta | ✅ Implementado Flask-WTF (`CSRFProtect`) + token oculto em todos os formulários |
| `debug=True` fixo no `app.run()` — se for parar em produção assim, expõe o debugger interativo do Werkzeug, que permite **execução remota de código** | Crítica (se for para produção) | ✅ Agora controlado por `FLASK_ENV`; só liga debug fora de produção |
| Cookies de sessão sem flags de segurança (`HttpOnly`, `SameSite`, `Secure`) | Média | ✅ `HttpOnly` e `SameSite=Lax` sempre ativos; `Secure` ativa automaticamente quando `FLASK_ENV=production` (exige HTTPS) |
| Venda podia derrubar o estoque para negativo (sem checar se havia quantidade suficiente) | Média (bug funcional com efeito de integridade de dados) | ✅ Corrigido: item é recusado se pedir mais do que o disponível |
| Mensagem inconsistente em `/criar_admin` (dizia "senha: 123456" mas o hash gerado era de `'spwadmin'`) | Baixa | ✅ Resolvido junto com a remoção da rota |

## O que eu recomendo melhorar (não implementado nesta entrega)

Você pediu para eu listar o que você não citou. Aqui vai, em ordem de prioridade:

1. **Rate limiting com storage persistente:** hoje uso `memory://` (em memória), que funciona bem para 1 processo, mas zera a contagem se o servidor reiniciar e não funciona corretamente com múltiplos workers/processos (ex. gunicorn com `-w 4`). Para produção, aponte o `storage_uri` do Flask-Limiter para Redis.
2. **HTTPS obrigatório em produção** — sem TLS, o cookie de sessão pode ser interceptado em rede (mesmo com `HttpOnly`). Combine com `SESSION_COOKIE_SECURE=True` (já preparado, só falta o certificado/proxy reverso).
3. **Bloqueio de conta por tentativas de login falhas** (além do rate limit por IP) — hoje um atacante pode trocar de IP para contornar o limite. Vale registrar tentativas falhas por usuário.
4. **Validação de dados de entrada:** CPF, telefone e e-mail são salvos como texto livre, sem validar formato nem duplicidade (dois clientes podem ter o mesmo CPF).
5. **Edição de registros:** hoje só existe cadastrar e excluir — não há como editar um produto, cliente ou vendedor sem apagar e recriar.
6. **Paginação** nas listagens — conforme a base crescer, `SELECT * FROM produtos` sem `LIMIT` vai carregar tudo de uma vez.
7. **Perfis de usuário/permissões** — hoje existe um único tipo de usuário (admin). Se mais pessoas forem usar o sistema (vendedores, por exemplo), vale ter papéis distintos com permissões diferentes.
8. **Log de auditoria** — não há registro de quem cadastrou/excluiu o quê e quando.
9. **Backup do banco** — SQLite é um arquivo único (`produtos.db`); vale ter uma rotina de backup automático.
10. **Testes automatizados** — não há nenhum teste no projeto; mesmo alguns testes básicos de rota (como os que rodei manualmente para validar esta entrega) evitam regressões.
11. **Cabeçalhos de segurança HTTP adicionais** (ex. `Content-Security-Policy`, `X-Content-Type-Options`) — pode ser feito facilmente com a extensão `flask-talisman`.
12. **Exportação de relatórios** (CSV/PDF) de vendas — comum em sistemas desse tipo.

## Como rodar

```bash
# 1. Crie e ative um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Configure as variáveis de ambiente
cp .env.example .env
# edite o .env e defina SECRET_KEY (gere com o comando abaixo)
python -c "import secrets; print(secrets.token_hex(32))"

# 4. Rode a aplicação (cria o banco automaticamente na primeira vez)
python app.py

# 5. Crie o usuário admin (uma única vez, via terminal — não é mais uma rota)
flask --app app.py criar-admin
```

A aplicação sobe em `http://127.0.0.1:5000`.

## Estrutura do projeto

```
.
├── app.py                  # rotas, lógica de negócio e configuração de segurança
├── requirements.txt
├── .env.example
├── static/
│   └── styles.css
├── templates/
│   ├── login.html
│   ├── dashboard.html      # nova tela inicial
│   ├── produtos.html       # antigo index.html, agora em /produtos
│   ├── clientes.html
│   ├── vendedores.html
│   ├── vendas.html
│   └── detalhe_venda.html
└── produtos.db              # criado automaticamente ao rodar (não versionar)
```

> **Importante:** a rota inicial (`/`) agora é o **dashboard**. A antiga tela de produtos foi movida para `/produtos` — os links de navegação em todas as páginas já foram atualizados.

---
© desenvolvido por: Willame Silva - 2026