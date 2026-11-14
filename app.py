# -*- coding: utf-8 -*-
"""Backend do app FINDRISC.

Publicado no Render (Flask). Banco de dados: Supabase (Postgres).
O app nunca fala direto com o banco nem com a Groq: tudo passa por aqui.
"""
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import psycopg2
import psycopg2.extras
import requests
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
VERSAO_TERMOS = "2026-11"

app = Flask(__name__)
app.json.ensure_ascii = False
CORS(app)

# ---------------------------------------------------------------- regras FINDRISC

# chave: (rótulo, modificável por hábitos/corpo?, pontuação máxima)
FATORES = {
    "idade": ("Idade", False, 4),
    "imc": ("IMC", True, 3),
    "cintura": ("Circunferência da cintura", True, 4),
    "atividade": ("Atividade física", True, 2),
    "frutas": ("Frutas e vegetais", True, 1),
    "pressao": ("Remédio para pressão", False, 2),
    "glicose": ("Glicose alta já detectada", False, 5),
    "familia": ("Histórico familiar", False, 5),
}

NIVEIS = [
    (6, "Baixo"),
    (11, "Levemente elevado"),
    (14, "Moderado"),
    (20, "Alto"),
    (26, "Muito alto"),
]

URGENCIA = {
    "Baixo": "Não há urgência. Pode comentar o resultado na próxima consulta de rotina.",
    "Levemente elevado": "Não é urgente, mas vale marcar uma consulta de rotina nos próximos meses.",
    "Moderado": "Vale agendar uma consulta médica nas próximas semanas, incluindo exame de glicemia.",
    "Alto": "Recomenda-se buscar atendimento médico o quanto antes, sem ser uma emergência.",
    "Muito alto": (
        "Pontuações nesta faixa aumentam a chance de a pessoa já ter diabetes não diagnosticada. "
        "Recomenda-se procurar atendimento médico o quanto antes para fazer exames."
    ),
}

SISTEMA = """Você explica, em português do Brasil e em linguagem simples, por que uma pessoa obteve determinado resultado no questionário FINDRISC (risco de diabetes tipo 2 em 10 anos).

Regras:
- Explique apenas os fatores que tiveram pontos maiores que 0, com 1 a 2 frases por fator, dizendo como ele se relaciona com o risco de diabetes tipo 2. Exemplo: cintura muito aumentada indica excesso de gordura abdominal (visceral), associada à resistência à insulina.
- Não recalcule, altere nem conteste a pontuação, o nível de risco ou a orientação de urgência recebidos.
- Não diagnostique a pessoa. Não cite medicamentos, doses, dietas específicas ou tratamentos.
- Fatores que a pessoa não controla (idade, histórico familiar) devem ser explicados sem culpabilizar.
- Termine sempre com uma frase respondendo diretamente à pergunta "é indicado procurar um médico agora?", usando apenas a orientação de urgência fornecida no pedido. Não invente um grau de urgência diferente do fornecido, nem o suavize ou intensifique.
- Máximo de 170 palavras. Sem markdown, sem listas com símbolos."""


def nivel_do_score(score):
    for limite, nome in NIVEIS:
        if score <= limite:
            return nome
    return NIVEIS[-1][1]


# ---------------------------------------------------------------- utilidades

def erro(mensagem, status=400):
    return jsonify(erro=mensagem), status


def ip_do_cliente():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


_tentativas = defaultdict(deque)


def limitar(chave, maximo, janela_segundos):
    """Limite simples em memória (o Render roda com 1 processo, então vale para todos)."""
    agora = time.time()
    fila = _tentativas[chave]
    while fila and agora - fila[0] > janela_segundos:
        fila.popleft()
    if len(fila) >= maximo:
        return False
    fila.append(agora)
    return True


def db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    return g.db


def cursor():
    return db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@app.teardown_appcontext
def fechar_conexao(_):
    conexao = g.pop("db", None)
    if conexao is not None:
        conexao.close()  # o que não recebeu commit é descartado


@app.errorhandler(Exception)
def erro_inesperado(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("erro inesperado")
    return erro("erro interno do servidor", 500)


# ---------------------------------------------------------------- autenticação

SENHA_FALSA = generate_password_hash("senha-falsa-para-igualar-o-tempo")


def criar_token(usuario_id):
    agora = datetime.now(timezone.utc)
    carga = {"sub": str(usuario_id), "iat": agora, "exp": agora + timedelta(days=30)}
    return jwt.encode(carga, JWT_SECRET, algorithm="HS256")


def exige_login(funcao):
    @wraps(funcao)
    def interna(*args, **kwargs):
        cabecalho = request.headers.get("Authorization", "")
        if not cabecalho.startswith("Bearer "):
            return erro("não autenticado", 401)
        try:
            dados = jwt.decode(cabecalho[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return erro("sessão inválida ou expirada", 401)
        with cursor() as cur:
            cur.execute("select 1 from usuarios where id = %s", (dados["sub"],))
            if cur.fetchone() is None:
                return erro("conta não encontrada", 401)
        g.usuario_id = dados["sub"]
        return funcao(*args, **kwargs)

    return interna


@app.get("/saude")
def saude():
    """Usada para 'acordar' o servidor e conferir o banco."""
    with cursor() as cur:
        cur.execute("select 1")
    return jsonify(ok=True)


@app.post("/registrar")
def registrar():
    if not limitar(f"registro:{ip_do_cliente()}", 10, 3600):
        return erro("muitas tentativas, tente mais tarde", 429)
    d = request.get_json(silent=True) or {}
    usuario = str(d.get("usuario", "")).strip().lower()
    senha = str(d.get("senha", ""))
    if not re.fullmatch(r"[a-z0-9_.]{3,30}", usuario):
        return erro("usuário: 3 a 30 caracteres (letras, números, ponto ou sublinhado)")
    if not 8 <= len(senha) <= 128:
        return erro("a senha deve ter de 8 a 128 caracteres")
    if d.get("consentimento") is not True:
        return erro("é necessário aceitar os termos de uso e a política de privacidade")

    try:
        with cursor() as cur:
            cur.execute(
                "insert into usuarios (usuario, senha_hash, consentimento_em, versao_termos) "
                "values (%s, %s, now(), %s) returning id",
                (usuario, generate_password_hash(senha), VERSAO_TERMOS),
            )
            novo_id = cur.fetchone()["id"]
        db().commit()
    except psycopg2.errors.UniqueViolation:
        db().rollback()
        return erro("este usuário já existe", 409)
    return jsonify(token=criar_token(novo_id), usuario=usuario), 201


@app.post("/entrar")
def entrar():
    d = request.get_json(silent=True) or {}
    usuario = str(d.get("usuario", "")).strip().lower()
    senha = str(d.get("senha", ""))
    if not limitar(f"login:{ip_do_cliente()}:{usuario}", 10, 600):
        return erro("muitas tentativas, aguarde alguns minutos", 429)
    with cursor() as cur:
        cur.execute("select id, senha_hash from usuarios where usuario = %s", (usuario,))
        linha = cur.fetchone()
    # confere a senha mesmo quando o usuário não existe, para o tempo de resposta não revelar isso
    hash_conferido = linha["senha_hash"] if linha else SENHA_FALSA
    senha_ok = check_password_hash(hash_conferido, senha)
    if not linha or not senha_ok:
        return erro("usuário ou senha incorretos", 401)
    return jsonify(token=criar_token(linha["id"]), usuario=usuario)


@app.delete("/conta")
@exige_login
def excluir_conta():
    with cursor() as cur:
        cur.execute("delete from usuarios where id = %s", (g.usuario_id,))  # apaga as avaliações junto
    db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- avaliações

def serializar(linha):
    return {
        "id": linha["id"],
        "criado_em": linha["criado_em"].isoformat(),
        "peso": float(linha["peso"]),
        "altura": float(linha["altura"]),
        "cintura": float(linha["cintura"]),
        "imc": float(linha["imc"]),
        "score": int(linha["score"]),
        "nivel": linha["nivel"],
    }


@app.post("/avaliacoes")
@exige_login
def criar_avaliacao():
    d = request.get_json(silent=True) or {}
    try:
        peso, altura, cintura = float(d["peso"]), float(d["altura"]), float(d["cintura"])
        score = int(d["score"])
    except (KeyError, TypeError, ValueError):
        return erro("dados inválidos")
    if not (20 <= peso <= 400 and 100 <= altura <= 250 and 30 <= cintura <= 250 and 0 <= score <= 26):
        return erro("valores fora do intervalo permitido")

    fatores = d.get("fatores")
    if not isinstance(fatores, list) or len(fatores) != len(FATORES):
        return erro("fatores inválidos")
    pontos = {}
    for f in fatores:
        chave = f.get("chave") if isinstance(f, dict) else None
        p = f.get("pontos") if isinstance(f, dict) else None
        valido = (
            chave in FATORES
            and chave not in pontos
            and isinstance(p, int)
            and not isinstance(p, bool)
            and 0 <= p <= FATORES[chave][2]
        )
        if not valido:
            return erro("fatores inválidos")
        pontos[chave] = p
    if sum(pontos.values()) != score:
        return erro("pontuação inconsistente com os fatores")

    imc = round(peso / ((altura / 100) ** 2), 1)
    nivel = nivel_do_score(score)  # o servidor define o nível, não o app
    with cursor() as cur:
        cur.execute(
            "insert into avaliacoes (usuario_id, peso, altura, cintura, imc, score, nivel, fatores) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s) returning id, criado_em",
            (g.usuario_id, peso, altura, cintura, imc, score, nivel, psycopg2.extras.Json(pontos)),
        )
        nova = cur.fetchone()
    db().commit()
    return jsonify(id=nova["id"], criado_em=nova["criado_em"].isoformat(), imc=imc, nivel=nivel), 201


@app.get("/avaliacoes")
@exige_login
def listar_avaliacoes():
    with cursor() as cur:
        cur.execute(
            "select id, criado_em, peso, altura, cintura, imc, score, nivel from avaliacoes "
            "where usuario_id = %s order by criado_em desc limit 100",
            (g.usuario_id,),
        )
        linhas = cur.fetchall()
    return jsonify(avaliacoes=[serializar(l) for l in reversed(linhas)])


@app.get("/avaliacoes/ultima")
@exige_login
def ultima_avaliacao():
    """Usada para pré-preencher o questionário com a avaliação anterior."""
    with cursor() as cur:
        cur.execute(
            "select id, criado_em, peso, altura, cintura, imc, score, nivel, fatores from avaliacoes "
            "where usuario_id = %s order by criado_em desc limit 1",
            (g.usuario_id,),
        )
        linha = cur.fetchone()
    if linha is None:
        return erro("nenhuma avaliação ainda", 404)
    return jsonify(**serializar(linha), fatores=linha["fatores"])


@app.delete("/avaliacoes/<int:avaliacao_id>")
@exige_login
def excluir_avaliacao(avaliacao_id):
    with cursor() as cur:
        cur.execute(
            "delete from avaliacoes where id = %s and usuario_id = %s",
            (avaliacao_id, g.usuario_id),
        )
        apagadas = cur.rowcount
    db().commit()
    if apagadas == 0:
        return erro("avaliação não encontrada", 404)
    return jsonify(ok=True)


# ---------------------------------------------------------------- estatísticas pessoais

def variacao(a, b):
    """Diferença entre duas avaliações (a menos b)."""
    return {
        "peso": round(float(a["peso"]) - float(b["peso"]), 1),
        "imc": round(float(a["imc"]) - float(b["imc"]), 1),
        "cintura": round(float(a["cintura"]) - float(b["cintura"]), 1),
        "score": int(a["score"]) - int(b["score"]),
    }


@app.get("/estatisticas")
@exige_login
def estatisticas():
    with cursor() as cur:
        cur.execute(
            "select id, criado_em, peso, altura, cintura, imc, score, nivel, fatores from avaliacoes "
            "where usuario_id = %s order by criado_em desc limit 200",
            (g.usuario_id,),
        )
        linhas = list(reversed(cur.fetchall()))  # da mais antiga para a mais recente

    total = len(linhas)
    if total == 0:
        return jsonify(total=0)

    primeira, ultima = linhas[0], linhas[-1]
    anterior = linhas[-2] if total >= 2 else None

    fatores = []
    modificaveis = nao_modificaveis = 0
    for chave, (rotulo, modificavel, maximo) in FATORES.items():
        pts = int(ultima["fatores"].get(chave, 0))
        fatores.append({
            "chave": chave,
            "rotulo": rotulo,
            "pontos": pts,
            "maximo": maximo,
            "pontos_anterior": int(anterior["fatores"].get(chave, 0)) if anterior else None,
            "modificavel": modificavel,
        })
        if modificavel:
            modificaveis += pts
        else:
            nao_modificaveis += pts
    fatores.sort(key=lambda f: (-f["pontos"], f["rotulo"]))

    return jsonify(
        total=total,
        serie=[serializar(l) for l in linhas[-60:]],
        ultima=serializar(ultima),
        anterior=serializar(anterior) if anterior else None,
        variacao_anterior=variacao(ultima, anterior) if anterior else None,
        variacao_total=variacao(ultima, primeira) if total >= 2 else None,
        fatores=fatores,
        pontos_modificaveis=modificaveis,
        pontos_nao_modificaveis=nao_modificaveis,
    )


# ---------------------------------------------------------------- explicação por IA

def texto_curto(valor, limite=80):
    return str(valor if valor is not None else "").replace("\n", " ").strip()[:limite]


@app.post("/explicar")
@exige_login
def explicar():
    if not GROQ_API_KEY:
        return erro("serviço de IA não configurado", 503)
    if not limitar(f"ia:{g.usuario_id}", 10, 60):
        return erro("muitas solicitações, aguarde um minuto", 429)

    d = request.get_json(silent=True) or {}
    try:
        score = int(d["score"])
    except (KeyError, TypeError, ValueError):
        return erro("dados inválidos")
    fatores = d.get("fatores")
    if not 0 <= score <= 26 or not isinstance(fatores, list) or not 1 <= len(fatores) <= 12:
        return erro("dados inválidos")

    nivel = nivel_do_score(score)  # nível e urgência vêm do servidor, nunca do app
    linhas = []
    for f in fatores:
        if not isinstance(f, dict):
            return erro("dados inválidos")
        try:
            pts = int(f.get("pontos", 0))
        except (TypeError, ValueError):
            return erro("dados inválidos")
        linhas.append(f"- {texto_curto(f.get('rotulo'))}: {texto_curto(f.get('resposta'))} ({pts} pontos)")

    pedido = (
        f"Pontuação total: {score} de 26. Nível de risco: {nivel}.\n"
        f"Orientação de urgência (use para responder se é indicado procurar um médico agora): "
        f"{URGENCIA[nivel]}\nFatores:\n" + "\n".join(linhas)
    )

    try:
        r = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "temperature": 0.3,
                "reasoning_effort": "low",
                "max_completion_tokens": 1000,
                "messages": [
                    {"role": "system", "content": SISTEMA},
                    {"role": "user", "content": pedido},
                ],
            },
            timeout=30,
        )
    except requests.RequestException:
        app.logger.exception("falha ao chamar a Groq")
        return erro("falha ao consultar a IA", 502)

    if not r.ok:
        app.logger.error("Groq respondeu %s: %s", r.status_code, r.text[:300])
        return erro("falha ao consultar a IA", 502)
    texto = (r.json()["choices"][0]["message"].get("content") or "").strip()
    if not texto:
        return erro("resposta vazia da IA", 502)
    return jsonify(texto=texto)


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)))
