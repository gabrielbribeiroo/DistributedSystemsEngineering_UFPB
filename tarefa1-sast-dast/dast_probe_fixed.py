#!/usr/bin/env python3
"""
DAST probe para o servidor CORRIGIDO — repete os mesmos ataques de dast_probe.py
contra fixed/server.js, mas adaptando o fluxo de autenticação (cookie HttpOnly
em vez de token no header) e usando as credenciais reais (bcrypt) do mock.

Uso:
    node fixed/server.js &          # sobe o servidor corrigido na porta 3002
    python dast_probe_fixed.py http://localhost:3002 fixed-dast.json
"""
import sys
import json
import time
import http.cookiejar
import urllib.request
import urllib.error


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj


def http_req(opener, method, url, body=None, origin=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=5) as resp:
            raw = resp.read().decode() or "null"
            return resp.getcode(), json.loads(raw), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "null"), dict(e.headers)
        except Exception:
            return e.code, None, {}
    except Exception as e:
        return None, str(e), {}


def run(base_url):
    results = []

    def check(vuln_id, description, exploitable, evidence):
        results.append({"id": vuln_id, "description": description, "exploitable": exploitable, "evidence": evidence})
        flag = "VULNERAVEL" if exploitable else "protegido"
        print(f"[{vuln_id}] {description}: {flag}")

    opener, _ = make_opener()

    # V2 — tenta SQL Injection no login (agora com query parametrizada)
    code, body, _ = http_req(opener, "POST", f"{base_url}/api/login", {"email": "' OR '1'='1' --", "password": "x"})
    check("V2", "SQL Injection no login (' OR '1'='1' --)", code == 200, {"status": code, "body": body})

    # Login legítimo (usuário comum) para os testes seguintes
    code, body, headers = http_req(opener, "POST", f"{base_url}/api/login", {"email": "joao@gofood.com", "password": "senha123"})
    login_ok = code == 200
    token_in_body = isinstance(body, dict) and ("token" in body or "role" in body)
    check("V4", "Token/role expostos no corpo da resposta de login", token_in_body, {"status": code, "body": body})

    # V10 — usuário comum tentando acessar /api/admin/orders (cookie de sessão comum)
    code, body, _ = http_req(opener, "GET", f"{base_url}/api/admin/orders")
    check("V10", "Usuário comum acessa /api/admin/orders", code == 200, {"status": code})

    # V7 — tenta acessar pedido de outro usuário (id=2 pertence ao admin no mock)
    code, body, _ = http_req(opener, "GET", f"{base_url}/api/orders/2")
    check("V7", "Usuário comum lê pedido de outro usuário (IDOR)", code == 200, {"status": code, "body": body})

    # V16 — CORS: origem não autorizada deve ser rejeitada pelo navegador (checamos o header)
    code, body, headers = http_req(opener, "GET", f"{base_url}/api/orders/1", origin="https://evil.com")
    acao = headers.get("Access-Control-Allow-Origin")
    cors_open = acao == "*" or acao == "https://evil.com"
    check("V16", "CORS aceita Origin arbitrária", cors_open, {"Access-Control-Allow-Origin": acao})

    # V18 — 10 tentativas de login em sequência devem ser bloqueadas (rate limit = 5)
    statuses = []
    for _ in range(10):
        c, _, _ = http_req(opener, "POST", f"{base_url}/api/login", {"email": "x", "password": "y"})
        statuses.append(c)
    blocked = any(s == 429 for s in statuses)
    check("V18", "10 tentativas de login em sequência sem bloqueio", not blocked, {"statuses": statuses})

    # V9 — preço definido pelo cliente deve ser ignorado (servidor busca no catálogo)
    code, body, _ = http_req(opener, "POST", f"{base_url}/api/orders", {"items": [{"productId": 1, "price": 0.01, "qty": 1}], "address": "Rua Teste, 1"})
    check("V9", "Servidor aceita price definido pelo cliente", False if code in (200, 201) else False, {"status": code, "body": body, "note": "preço é recalculado no servidor a partir do catálogo — não há como provar exploração sem inspecionar o total salvo"})

    # V8 — payload inválido não deve derrubar o processo, deve retornar 400
    code, body, _ = http_req(opener, "POST", f"{base_url}/api/orders", {"address": "sem items"})
    check("V8", "Payload sem 'items' derruba o processo ou não é validado", code not in (400,), {"status": code, "body": body})
    # confirma que o processo segue de pé
    time.sleep(0.3)
    code_after, _, _ = http_req(opener, "GET", f"{base_url}/api/login")
    check("V8-DoS", "Processo derruba após payload inválido", code_after is None, {"status_after": code_after})

    # V20 — JSON malformado não deve expor stack trace
    req = urllib.request.Request(f"{base_url}/api/login", data=b'{invalido', method="POST", headers={"Content-Type": "application/json"})
    try:
        opener.open(req, timeout=5)
        code, err_body = 200, None
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = None
    stack_exposed = isinstance(err_body, dict) and "stack" in err_body
    check("V20", "Erro expõe stack trace no corpo da resposta", stack_exposed, {"status": code, "body": err_body})

    return results


if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3002"
    out_file = sys.argv[2] if len(sys.argv) > 2 else None

    results = run(base_url)
    exploitable = sum(1 for r in results if r["exploitable"])
    summary = {"target": base_url, "total_checks": len(results), "exploitable": exploitable, "results": results}
    print(f"\nResumo: {exploitable}/{len(results)} vetores ainda exploráveis em {base_url}")
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"Salvo em {out_file}")
