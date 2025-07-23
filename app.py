from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from io import BytesIO
import socket
import json
import bcrypt
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROMPTS_FOLDER'] = 'prompts'
app.config['USERS_FILE'] = 'users.json'
app.secret_key = 'sua_chave_secreta_aqui_mude_em_producao'  # Mude em produção!

# Criar pasta de uploads se não existir
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Criar pasta de prompts se não existir
if not os.path.exists(app.config['PROMPTS_FOLDER']):
    os.makedirs(app.config['PROMPTS_FOLDER'])
    # Criar subpasta para empresas
    os.makedirs(os.path.join(app.config['PROMPTS_FOLDER'], 'empresas'), exist_ok=True)

# Estrutura para armazenar os tipos de prompts disponíveis por categoria
PROMPTS_TIPOS = {
    'empresas': ['resumo_executivo', 'analise_swot_concorrente', 'analise_sentimento_cliente', 
                'elaboracao_email_prospeccao', 'criacao_descricao_vaga', 'roteiro_entrevista_competencias', 'plano_acao_reuniao',
                'brainstorm_conteudo_midias_sociais', 'simplificador_relatorio_financeiro', 
                'analisador_edital_ficha_resumo', 'checklist_documentos_habilitacao',
                'minuta_pedido_esclarecimento_impugnacao', 'analise_ata_julgamento_sessao',
                'analise_proposta_vencedora_inteligencia_competitiva']
}

# Funções de autenticação
def carregar_usuarios():
    """Carrega usuários do arquivo JSON"""
    if os.path.exists(app.config['USERS_FILE']):
        try:
            with open(app.config['USERS_FILE'], 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Erro ao carregar usuários: {e}")
            return {}
    return {}

def salvar_usuarios(usuarios):
    """Salva usuários no arquivo JSON"""
    try:
        with open(app.config['USERS_FILE'], 'w', encoding='utf-8') as f:
            json.dump(usuarios, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erro ao salvar usuários: {e}")
        return False

def hash_senha(senha):
    """Gera hash da senha"""
    return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verificar_senha(senha, hash_senha):
    """Verifica se a senha confere com o hash"""
    return bcrypt.checkpw(senha.encode('utf-8'), hash_senha.encode('utf-8'))

def login_required(f):
    """Decorator para proteger rotas que requerem login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def carregar_prompt(categoria, tipo):
    """Carrega o prompt de um arquivo externo"""
    caminho_arquivo = os.path.join(app.config['PROMPTS_FOLDER'], categoria, f"{tipo}.txt")
    
    # Se o arquivo existir, carrega o conteúdo
    if os.path.exists(caminho_arquivo):
        try:
            with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
                return arquivo.read().strip()
        except Exception as e:
            print(f"Erro ao ler arquivo de prompt {caminho_arquivo}: {str(e)}")
            return None
    
    # Se o arquivo não existir, retorna None
    return None

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        dados = request.get_json() if request.is_json else request.form
        email = dados.get('email', '').strip().lower()
        senha = dados.get('senha', '')
        
        if not email or not senha:
            if request.is_json:
                return jsonify({'erro': 'Email e senha são obrigatórios'}), 400
            flash('Email e senha são obrigatórios', 'error')
            return render_template('login.html')
        
        usuarios = carregar_usuarios()
        
        if email in usuarios and verificar_senha(senha, usuarios[email]['senha']):
            session['user_id'] = email
            session['user_name'] = usuarios[email]['nome']
            
            # Atualizar último login
            usuarios[email]['ultimo_login'] = datetime.now().isoformat()
            salvar_usuarios(usuarios)
            
            if request.is_json:
                return jsonify({'sucesso': True, 'redirect': url_for('index')})
            return redirect(url_for('index'))
        else:
            if request.is_json:
                return jsonify({'erro': 'Email ou senha incorretos'}), 401
            flash('Email ou senha incorretos', 'error')
    
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        dados = request.get_json() if request.is_json else request.form
        nome = dados.get('nome', '').strip()
        email = dados.get('email', '').strip().lower()
        senha = dados.get('senha', '')
        confirmar_senha = dados.get('confirmar_senha', '')
        
        # Validações
        if not all([nome, email, senha, confirmar_senha]):
            erro = 'Todos os campos são obrigatórios'
            if request.is_json:
                return jsonify({'erro': erro}), 400
            flash(erro, 'error')
            return render_template('registro.html')
        
        if senha != confirmar_senha:
            erro = 'As senhas não conferem'
            if request.is_json:
                return jsonify({'erro': erro}), 400
            flash(erro, 'error')
            return render_template('registro.html')
        
        if len(senha) < 6:
            erro = 'A senha deve ter pelo menos 6 caracteres'
            if request.is_json:
                return jsonify({'erro': erro}), 400
            flash(erro, 'error')
            return render_template('registro.html')
        
        usuarios = carregar_usuarios()
        
        if email in usuarios:
            erro = 'Este email já está cadastrado'
            if request.is_json:
                return jsonify({'erro': erro}), 400
            flash(erro, 'error')
            return render_template('registro.html')
        
        # Criar novo usuário
        usuarios[email] = {
            'nome': nome,
            'senha': hash_senha(senha),
            'data_criacao': datetime.now().isoformat(),
            'ultimo_login': None
        }
        
        if salvar_usuarios(usuarios):
            if request.is_json:
                return jsonify({'sucesso': True, 'mensagem': 'Usuário criado com sucesso'})
            flash('Usuário criado com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('login'))
        else:
            erro = 'Erro ao criar usuário. Tente novamente.'
            if request.is_json:
                return jsonify({'erro': erro}), 500
            flash(erro, 'error')
    
    return render_template('registro.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

# Rotas principais (protegidas)
@app.route('/')
@login_required
def index():
    return render_template('index.html', user_name=session.get('user_name'))

@app.route('/gerar_prompt', methods=['POST'])
@login_required
def gerar_prompt():
    dados = request.json
    categoria = 'empresas'  # Sempre usar empresas
    tipo = dados.get('tipo', 'resumo_executivo')  # Padrão para resumo executivo
    
    # Tenta carregar o prompt do arquivo externo
    prompt_base = carregar_prompt(categoria, tipo)
    
    # Se não encontrar o arquivo ou ocorrer erro na leitura, usa um prompt padrão
    if prompt_base is None:
        prompt_base = "Faça uma análise do texto a seguir."
        print(f"Aviso: Prompt não encontrado para {categoria}/{tipo}. Usando prompt padrão.")
    
    prompt_gerado = f"{prompt_base}\n\n[Insira aqui o texto a ser analisado]"
    
    return jsonify({'prompt': prompt_gerado})

@app.route('/config')
@login_required
def config():
    return render_template('config.html', user_name=session.get('user_name'))

@app.route('/api/prompts/<categoria>')
@login_required
def listar_prompts(categoria):
    """Lista todos os prompts disponíveis para uma categoria"""
    if categoria not in PROMPTS_TIPOS:
        return jsonify({'erro': 'Categoria não encontrada'}), 404
    
    prompts = []
    for tipo in PROMPTS_TIPOS[categoria]:
        caminho_arquivo = os.path.join(app.config['PROMPTS_FOLDER'], categoria, f"{tipo}.txt")
        existe = os.path.exists(caminho_arquivo)
        prompts.append({
            'tipo': tipo,
            'nome': tipo.replace('_', ' ').title(),
            'existe': existe
        })
    
    return jsonify({'prompts': prompts})

@app.route('/api/prompt/<categoria>/<tipo>')
@login_required
def obter_prompt(categoria, tipo):
    """Obtém o conteúdo de um prompt específico"""
    if categoria not in PROMPTS_TIPOS or tipo not in PROMPTS_TIPOS[categoria]:
        return jsonify({'erro': 'Prompt não encontrado'}), 404
    
    conteudo = carregar_prompt(categoria, tipo)
    if conteudo is None:
        return jsonify({'erro': 'Arquivo de prompt não encontrado'}), 404
    
    return jsonify({'conteudo': conteudo})

@app.route('/api/prompt/<categoria>/<tipo>', methods=['POST'])
@login_required
def salvar_prompt(categoria, tipo):
    """Salva o conteúdo de um prompt"""
    if categoria not in PROMPTS_TIPOS or tipo not in PROMPTS_TIPOS[categoria]:
        return jsonify({'erro': 'Prompt não encontrado'}), 404
    
    dados = request.json
    conteudo = dados.get('conteudo', '')
    
    caminho_arquivo = os.path.join(app.config['PROMPTS_FOLDER'], categoria, f"{tipo}.txt")
    
    try:
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(caminho_arquivo), exist_ok=True)
        
        with open(caminho_arquivo, 'w', encoding='utf-8') as arquivo:
            arquivo.write(conteudo)
        
        return jsonify({'sucesso': True, 'mensagem': 'Prompt salvo com sucesso'})
    except Exception as e:
        return jsonify({'erro': f'Erro ao salvar prompt: {str(e)}'}), 500

@app.route('/api/server-info')
@login_required
def server_info():
    """Retorna informações do servidor"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Tentar obter informações de rede mais detalhadas
        interfaces = []
        try:
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.') and not ip.startswith('169.254.'):
                            interfaces.append({
                                'interface': interface,
                                'ip': ip
                            })
        except ImportError:
            # netifaces não está disponível
            pass
        
        return jsonify({
            'hostname': hostname,
            'local_ip': local_ip,
            'interfaces': interfaces
        })
    except Exception as e:
        return jsonify({
            'hostname': 'unknown',
            'local_ip': 'localhost',
            'interfaces': [],
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9005)
    