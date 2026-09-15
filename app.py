import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, render_template, redirect, jsonify, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3

app = Flask(__name__)

# ── CONFIGURAÇÃO DE SEGURANÇA ──────────────────────────────────
# A SECRET_KEY nunca deve ficar fixa no código-fonte (ainda mais em repositório
# público). Ela é lida da variável de ambiente SECRET_KEY; se não existir,
# uma chave aleatória é gerada a cada start (útil em dev, mas invalida sessões
# antigas a cada reinício — em produção, defina SECRET_KEY no ambiente/.env).
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Tempo de vida absoluto da sessão (mesmo que o usuário fique ativo o tempo todo)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Tempo de INATIVIDADE máximo permitido antes de forçar logout automático
INACTIVITY_TIMEOUT = timedelta(minutes=15)

# Cookies de sessão mais seguros
app.config['SESSION_COOKIE_HTTPONLY'] = True      # JS não consegue ler o cookie (mitiga XSS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'      # mitiga CSRF em navegação cross-site
# Em produção, atrás de HTTPS, troque para True (exige HTTPS para enviar o cookie)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# Proteção CSRF em todos os formulários POST (via Flask-WTF)
csrf = CSRFProtect(app)

# Rate limiting — protege contra força bruta / abuso / scraping.
# Limite global bem reduzido; rotas sensíveis (login, cadastros) têm limites
# próprios e mais rígidos ainda.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour", "20 per minute"],
    storage_uri="memory://",  # em produção com múltiplos workers, use Redis (ver README)
)

DATABASE = 'produtos.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            marca TEXT NOT NULL,
            nome TEXT NOT NULL,
            sabor TEXT NOT NULL,
            valor REAL NOT NULL,
            quantidade INTEGER NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            cpf TEXT NOT NULL,
            telefone TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS vendedores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            cpf TEXT NOT NULL,
            telefone TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS vendas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id INTEGER NOT NULL,
            vendedor_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            total REAL NOT NULL,
            FOREIGN KEY (cliente_id) REFERENCES clientes(id),
            FOREIGN KEY (vendedor_id) REFERENCES vendedores(id)
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS itens_venda (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            venda_id INTEGER NOT NULL,
            produto_id INTEGER NOT NULL,
            quantidade INTEGER NOT NULL,
            valor_unitario REAL NOT NULL,
            FOREIGN KEY (venda_id) REFERENCES vendas(id),
            FOREIGN KEY (produto_id) REFERENCES produtos(id)
        )
    ''')

    conn.commit()
    conn.close()


# ── CRIAÇÃO DO ADMIN (comando de terminal, NÃO é mais uma rota) ──
# Antes isso era uma rota HTTP pública (/criar_admin): qualquer pessoa na
# internet podia acessá-la e criar usuários administradores à vontade, sem
# nenhuma autenticação. Isso é uma falha crítica. Agora é um comando de CLI,
# só executável por quem tem acesso ao servidor:
#   flask --app app.py criar-admin
@app.cli.command('criar-admin')
def criar_admin_cli():
    """Cria o usuário administrador inicial (uso único, via terminal)."""
    import getpass
    conn = get_db_connection()
    existe = conn.execute('SELECT id FROM usuarios WHERE username = ?', ('admin',)).fetchone()
    if existe:
        print('Usuário "admin" já existe. Nada foi feito.')
        conn.close()
        return

    senha = getpass.getpass('Defina a senha do admin: ')
    senha_confirma = getpass.getpass('Confirme a senha: ')
    if senha != senha_confirma:
        print('As senhas não conferem. Operação cancelada.')
        conn.close()
        return
    if len(senha) < 8:
        print('A senha deve ter pelo menos 8 caracteres. Operação cancelada.')
        conn.close()
        return

    senha_hash = generate_password_hash(senha)
    conn.execute('INSERT INTO usuarios (username, password) VALUES (?, ?)', ('admin', senha_hash))
    conn.commit()
    conn.close()
    print('Usuário admin criado com sucesso.')


# ── CONTROLE DE SESSÃO / INATIVIDADE ───────────────────────────
@app.before_request
def controlar_sessao():
    if 'usuario_id' in session:
        agora = datetime.utcnow()
        ultima_atividade = session.get('last_activity')

        if ultima_atividade:
            ultima_atividade = datetime.fromisoformat(ultima_atividade)
            if agora - ultima_atividade > INACTIVITY_TIMEOUT:
                session.clear()
                flash('Sua sessão expirou por inatividade. Faça login novamente.')
                return redirect(url_for('login'))

        session['last_activity'] = agora.isoformat()
        session.permanent = True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ── LOGIN ───────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # protege contra força bruta de senha
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE username = ?', (username,)).fetchone()
        conn.close()

        if usuario and check_password_hash(usuario['password'], password):
            session.clear()
            session['usuario_id'] = usuario['id']
            session['username'] = usuario['username']
            session['last_activity'] = datetime.utcnow().isoformat()
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos!')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── DASHBOARD (tela inicial) ────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()

    total_produtos = conn.execute("SELECT COUNT(*) FROM produtos").fetchone()[0]
    total_clientes = conn.execute("SELECT COUNT(*) FROM clientes").fetchone()[0]
    total_vendedores = conn.execute("SELECT COUNT(*) FROM vendedores").fetchone()[0]
    total_vendas = conn.execute("SELECT COUNT(*) FROM vendas").fetchone()[0]

    receita_total = conn.execute("SELECT COALESCE(SUM(total), 0) FROM vendas").fetchone()[0]

    hoje = datetime.now().strftime('%d/%m/%Y')
    vendas_hoje = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(total), 0) FROM vendas WHERE data LIKE ?",
        (hoje + '%',)
    ).fetchone()
    qtd_vendas_hoje, receita_hoje = vendas_hoje[0], vendas_hoje[1]

    estoque_baixo = conn.execute(
        "SELECT * FROM produtos WHERE quantidade <= 5 ORDER BY quantidade ASC"
    ).fetchall()

    ultimas_vendas = conn.execute('''
        SELECT v.id, c.nome AS cliente, vd.nome AS vendedor, v.data, v.total
        FROM vendas v
        JOIN clientes c ON v.cliente_id = c.id
        JOIN vendedores vd ON v.vendedor_id = vd.id
        ORDER BY v.id DESC
        LIMIT 5
    ''').fetchall()

    top_produtos = conn.execute('''
        SELECT p.nome, p.marca, SUM(iv.quantidade) AS total_vendido
        FROM itens_venda iv
        JOIN produtos p ON iv.produto_id = p.id
        GROUP BY iv.produto_id
        ORDER BY total_vendido DESC
        LIMIT 5
    ''').fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        total_produtos=total_produtos,
        total_clientes=total_clientes,
        total_vendedores=total_vendedores,
        total_vendas=total_vendas,
        receita_total=receita_total,
        qtd_vendas_hoje=qtd_vendas_hoje,
        receita_hoje=receita_hoje,
        estoque_baixo=estoque_baixo,
        ultimas_vendas=ultimas_vendas,
        top_produtos=top_produtos,
    )


# ── PRODUTOS ──────────

@app.route('/produtos')
@login_required
def produtos():
    conn = get_db_connection()
    produtos = conn.execute("SELECT * FROM produtos").fetchall()
    conn.close()
    return render_template('produtos.html', produtos=produtos)


@app.route('/add_product', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def add_product():
    try:
        marca = request.form['marca'].strip()
        nome = request.form['nome'].strip()
        sabor = request.form['sabor'].strip()
        valor = float(request.form['valor'])
        quantidade = int(request.form['quantidade'])
        if valor < 0 or quantidade < 0:
            raise ValueError()
    except (ValueError, KeyError):
        flash('Dados inválidos para o produto.')
        return redirect(url_for('produtos'))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO produtos (marca, nome, sabor, valor, quantidade) VALUES (?, ?, ?, ?, ?)",
        (marca, nome, sabor, valor, quantidade)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('produtos'))


@app.route('/delete_product/<int:id>', methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def delete_product(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM produtos WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('produtos'))


# ── CLIENTES ──────────
@app.route('/clientes')
@login_required
def clientes():
    con = get_db_connection()
    clientes = con.execute("SELECT * FROM clientes").fetchall()
    con.close()
    return render_template('clientes.html', clientes=clientes)


@app.route('/add_cliente', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def add_cliente():
    nome = request.form['nome'].strip()
    cpf = request.form['cpf'].strip()
    telefone = request.form['telefone'].strip()
    email = request.form['email'].strip()

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO clientes (nome, cpf, telefone, email) VALUES (?, ?, ?, ?)",
        (nome, cpf, telefone, email)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('clientes'))


@app.route('/delete_cliente/<int:id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def delete_cliente(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM clientes WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('clientes'))


# ── VENDEDORES ───────────

@app.route('/vendedores')
@login_required
def vendedores():
    conn = get_db_connection()
    vendedores = conn.execute("SELECT * FROM vendedores").fetchall()
    conn.close()
    return render_template('vendedores.html', vendedores=vendedores)


@app.route('/add_vendedor', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def add_vendedor():
    nome = request.form['nome'].strip()
    cpf = request.form['cpf'].strip()
    telefone = request.form['telefone'].strip()

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO vendedores (nome, cpf, telefone) VALUES (?, ?, ?)",
        (nome, cpf, telefone)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('vendedores'))


@app.route('/delete_vendedor/<int:id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def delete_vendedor(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM vendedores WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('vendedores'))


# ── VENDAS ───────────────

@app.route('/vendas')
@login_required
def vendas():
    conn = get_db_connection()
    vendas = conn.execute('''
        SELECT v.id, c.nome AS cliente, vd.nome AS vendedor, v.data, v.total
        FROM vendas v
        JOIN clientes c ON v.cliente_id = c.id
        JOIN vendedores vd ON v.vendedor_id = vd.id
        ORDER BY v.id DESC
    ''').fetchall()

    clientes = conn.execute("SELECT * FROM clientes").fetchall()
    vendedores = conn.execute("SELECT * FROM vendedores").fetchall()
    produtos = conn.execute("SELECT * FROM produtos").fetchall()

    conn.close()
    return render_template('vendas.html', vendas=vendas, clientes=clientes, vendedores=vendedores, produtos=produtos)


@app.route('/add_venda', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def add_venda():
    cliente_id = request.form['cliente_id']
    vendedor_id = request.form['vendedor_id']
    produtos_ids = request.form.getlist('produto_id[]')
    quantidades = request.form.getlist('quantidade[]')

    data = datetime.now().strftime('%d/%m/%Y %H:%M')

    conn = get_db_connection()

    total = 0
    itens = []
    avisos = []

    for p_id, qtd in zip(produtos_ids, quantidades):
        try:
            qtd = int(qtd)
        except ValueError:
            continue
        if p_id and qtd > 0:
            produto = conn.execute("SELECT nome, valor, quantidade FROM produtos WHERE id = ?", (p_id,)).fetchone()
            if not produto:
                continue
            if qtd > produto['quantidade']:
                avisos.append(f"Estoque insuficiente para {produto['nome']} (disponível: {produto['quantidade']}). Item ignorado.")
                continue
            valor_unitario = produto['valor']
            total += valor_unitario * qtd
            itens.append((p_id, qtd, valor_unitario))

    if not itens:
        conn.close()
        flash('Nenhum item válido para registrar a venda. ' + ' '.join(avisos))
        return redirect(url_for('vendas'))

    cursor = conn.execute(
        "INSERT INTO vendas (cliente_id, vendedor_id, data, total) VALUES (?, ?, ?, ?)",
        (cliente_id, vendedor_id, data, total)
    )
    venda_id = cursor.lastrowid

    for p_id, qtd, valor_unitario in itens:
        conn.execute(
            "INSERT INTO itens_venda (venda_id, produto_id, quantidade, valor_unitario) VALUES (?, ?, ?, ?)",
            (venda_id, p_id, qtd, valor_unitario)
        )
        conn.execute(
            "UPDATE produtos SET quantidade = quantidade - ? WHERE id = ?",
            (qtd, p_id)
        )

    conn.commit()
    conn.close()

    if avisos:
        flash(' '.join(avisos))
    return redirect(url_for('vendas'))


@app.route('/api/venda/<int:id>')
@login_required
@limiter.limit("60 per minute")
def api_detalhe_venda(id):
    conn = get_db_connection()
    venda = conn.execute('''
        SELECT v.id, c.nome AS cliente, vd.nome AS vendedor, v.data, v.total
        FROM vendas v
        JOIN clientes c ON v.cliente_id = c.id
        JOIN vendedores vd ON v.vendedor_id = vd.id
        WHERE v.id = ?
    ''', (id,)).fetchone()

    itens = conn.execute('''
        SELECT p.marca, p.nome, p.sabor, iv.quantidade, iv.valor_unitario, (iv.quantidade * iv.valor_unitario) as subtotal
        FROM itens_venda iv
        JOIN produtos p ON iv.produto_id = p.id
        WHERE iv.venda_id = ?
    ''', (id,)).fetchall()

    conn.close()

    if not venda:
        return jsonify({'error': 'Venda não encontrada'}), 404

    return jsonify({
        'venda': dict(venda),
        'itens': [dict(i) for i in itens]
    })


@app.route('/venda/<int:id>')
@login_required
def detalhe_venda(id):
    conn = get_db_connection()
    venda = conn.execute('''
        SELECT v.id, c.nome AS cliente, vd.nome AS vendedor, v.data, v.total
        FROM vendas v
        JOIN clientes c ON v.cliente_id = c.id
        JOIN vendedores vd ON v.vendedor_id = vd.id
        WHERE v.id = ?
    ''', (id,)).fetchone()

    itens = conn.execute('''
        SELECT p.nome, p.marca, iv.quantidade, iv.valor_unitario, (iv.quantidade * iv.valor_unitario) as subtotal
        FROM itens_venda iv
        JOIN produtos p ON iv.produto_id = p.id
        WHERE iv.venda_id = ?
    ''', (id,)).fetchall()

    conn.close()
    return render_template('detalhe_venda.html', venda=venda, itens=itens)


if __name__ == '__main__':
    init_db()
    # debug=True NUNCA deve ir para produção: expõe o debugger interativo do
    # Werkzeug, que permite execução remota de código. Controlado por env var.
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug_mode)