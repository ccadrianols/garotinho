import os
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave_padrão_local_insegura')

# Constantes
USUARIOS_CSV = 'usuarios.csv'
ATENDIMENTOS_CSV = os.path.join('uploads', 'atendimentos.csv')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class para flask-login
class User(UserMixin):
    def __init__(self, username, fullname, password_hash):
        self.id = username
        self.fullname = fullname
        self.password_hash = password_hash

# Dicionário para armazenar usuários na memória
usuarios = {}

def carregar_usuarios():
    global usuarios
    usuarios = {}
    if os.path.exists(USUARIOS_CSV):
        df = pd.read_csv(USUARIOS_CSV)
        for _, row in df.iterrows():
            usuarios[row['username']] = User(row['username'], row['fullname'], row['password_hash'])

def salvar_usuario(username, fullname, password_hash):
    global usuarios
    usuarios[username] = User(username, fullname, password_hash)
    df = pd.DataFrame([{
        'username': u.id,
        'fullname': u.fullname,
        'password_hash': u.password_hash
    } for u in usuarios.values()])
    df.to_csv(USUARIOS_CSV, index=False)

@login_manager.user_loader
def load_user(user_id):
    return usuarios.get(user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        fullname = request.form['fullname']
        password = request.form['password']
        if username in usuarios:
            return "Usuário já existe"
        password_hash = generate_password_hash(password)
        salvar_usuario(username, fullname, password_hash)
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = usuarios.get(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        return "Usuário ou senha inválidos"
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Exemplo simples de leitura de CSV atendimentos
    if not os.path.exists(ATENDIMENTOS_CSV):
        return "Arquivo de atendimentos não encontrado."
    df = pd.read_csv(ATENDIMENTOS_CSV)
    # Só exibindo os primeiros clientes não atendidos por exemplo
    clientes = df[df['Status'] != 'Atendido'].to_dict(orient='records')
    return render_template('index.html', clientes=clientes, user=current_user)

if __name__ == '__main__':
    # Criar pastas e arquivos iniciais se não existirem
    os.makedirs('uploads', exist_ok=True)
    if not os.path.exists(USUARIOS_CSV):
        df_users = pd.DataFrame(columns=['username', 'fullname', 'password_hash'])
        df_users.to_csv(USUARIOS_CSV, index=False)
    carregar_usuarios()

    # Usar porta do ambiente (Render) ou padrão 10000 localmente
    port = int(os.environ.get('PORT', 10000))
    app.run(host='100.20.92.101', port=port, debug=False)
