# Recon AI Triage - v1.1.0
# Features: Nmap, FFUF, logs, scoring, correlation engine, optional LLM, optional CVE enrichment

import os
import re
import json
import yaml
import argparse
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


Finding = Dict[str, Any]


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not config:
        raise ValueError("config.yaml vazio ou inválido.")

    return config


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def classify(score: int, config: Dict[str, Any]) -> str:
    if score >= config["scoring"]["vuln_threshold"]:
        return "potencial_vulnerabilidade"

    if score >= config["scoring"]["interesting_threshold"]:
        return "interessante"

    return "ruido"


def calculate_score(item: Finding, config: Dict[str, Any]) -> Finding:
    score = 0
    reasons = []

    text = normalize_text(json.dumps(item, ensure_ascii=False))

    for kw in config["keywords"]["high"]:
        if kw.lower() in text:
            score += 20
            reasons.append(f"Keyword crítica encontrada: {kw}")

    for kw in config["keywords"]["medium"]:
        if kw.lower() in text:
            score += 8
            reasons.append(f"Keyword interessante encontrada: {kw}")

    status = item.get("status") or item.get("status_code")

    try:
        status = int(status)
    except Exception:
        status = None

    if status:
        if status in [200, 201, 202]:
            score += 15
            reasons.append(f"Status HTTP positivo: {status}")
        elif status in [401, 403]:
            score += 20
            reasons.append(f"Recurso protegido encontrado: {status}")
        elif status in [500, 502, 503]:
            score += 25
            reasons.append(f"Erro server-side encontrado: {status}")

    url = item.get("url") or item.get("path") or item.get("endpoint") or ""
    url_l = url.lower()

    risky_patterns = {
        "Possível exposição de arquivo .env": r"\.env($|\?)",
        "Possível exposição de Git": r"\.git",
        "Possível Swagger/OpenAPI exposto": r"(swagger|openapi|api-docs)",
        "Possível Actuator exposto": r"actuator",
        "Possível painel administrativo": r"(admin|dashboard|manager)",
        "Possível backup exposto": r"(backup|\.bak|\.old|\.zip|\.tar|\.gz|dump)",
        "Possível endpoint de upload": r"(upload|file)",
        "Possível redirect/callback": r"(redirect|callback|returnurl|next=)",
        "Possível IDOR": r"(user|account|profile|invoice|order|id=|uuid=)",
        "Possível GraphQL exposto": r"graphql",
    }

    for name, pattern in risky_patterns.items():
        if re.search(pattern, url_l):
            score += 20
            reasons.append(name)

    port = item.get("port")
    service = normalize_text(item.get("service"))
    product = normalize_text(item.get("product"))
    version = normalize_text(item.get("version"))

    risky_ports = {
        "21": "FTP exposto",
        "22": "SSH exposto",
        "23": "Telnet exposto",
        "25": "SMTP exposto",
        "3306": "MySQL exposto",
        "5432": "PostgreSQL exposto",
        "6379": "Redis exposto",
        "9200": "Elasticsearch exposto",
        "27017": "MongoDB exposto",
        "11211": "Memcached exposto",
    }

    if str(port) in risky_ports:
        score += 25
        reasons.append(risky_ports[str(port)])

    if any(s in service for s in ["ftp", "mysql", "postgres", "redis", "mongodb", "elasticsearch"]):
        score += 20
        reasons.append(f"Serviço sensível detectado: {service}")

    if port and item.get("state") == "open":
        score += 15
        reasons.append(f"Porta aberta detectada: {port}")

    if version or item.get("product"):
        score += 15
        reasons.append("Banner/versionamento exposto")

    if "apache" in product and "2.4.7" in version:
        score += 20
        reasons.append("Apache antigo detectado")

    if "openssh" in product and "6.6" in version:
        score += 20
        reasons.append("OpenSSH antigo detectado")

    return {
        "score": min(score, 100),
        "classification": classify(score, config),
        "reasons": reasons
    }


def build_cve_query(product: str, version: str) -> Optional[str]:
    product_l = normalize_text(product)
    version_l = normalize_text(version)

    if not product_l:
        return None

    if "apache" in product_l:
        return f"Apache httpd {version_l}".strip()

    if "openssh" in product_l:
        return f"OpenSSH {version_l}".strip()

    if "nginx" in product_l:
        return f"nginx {version_l}".strip()

    if "mysql" in product_l:
        return f"MySQL {version_l}".strip()

    if "postgres" in product_l:
        return f"PostgreSQL {version_l}".strip()

    if "redis" in product_l:
        return f"Redis {version_l}".strip()

    if "mongodb" in product_l:
        return f"MongoDB {version_l}".strip()

    return f"{product} {version}".strip()


def fetch_cves_nvd(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    encoded = urllib.parse.urlencode({
        "keywordSearch": query,
        "cvssV3Severity": "HIGH"
    })

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{encoded}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Recon-AI-Triage/1.1"}
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return [{
            "error": str(e),
            "query": query
        }]

    results = []

    for vuln in data.get("vulnerabilities", [])[:limit]:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})

        cvss_score = None
        severity = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        results.append({
            "id": cve.get("id"),
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "severity": severity,
            "cvss": cvss_score,
            "description": description[:500],
            "references": [
                ref.get("url") for ref in cve.get("references", {}).get("referenceData", [])
            ][:5]
        })

    return results


def apply_cve_enrichment(findings: List[Finding], config: Dict[str, Any]) -> List[Finding]:
    cache = {}

    for item in findings:
        product = item.get("product")
        version = item.get("version")

        if not product:
            continue

        query = build_cve_query(product, version or "")

        if not query:
            continue

        if query not in cache:
            cache[query] = fetch_cves_nvd(query)

        cves = cache[query]
        item["cve_query"] = query
        item["cves"] = cves

        valid_cves = [c for c in cves if c.get("id")]

        if valid_cves:
            item["score"] = min(item.get("score", 0) + 20, 100)
            item["reasons"].append(f"CVE enrichment encontrou {len(valid_cves)} CVEs HIGH relacionadas")
            item["classification"] = classify(item["score"], config)

    return sorted(findings, key=lambda x: x.get("score", 0), reverse=True)


def apply_correlation_engine(findings: List[Finding], config: Dict[str, Any]) -> List[Finding]:
    all_text = normalize_text(json.dumps(findings, ensure_ascii=False))

    has_admin = any(re.search(r"(admin|dashboard|manager)", normalize_text(f)) for f in findings)
    has_403 = any(str(f.get("status")) == "403" for f in findings)
    has_401 = any(str(f.get("status")) == "401" for f in findings)
    has_swagger = "swagger" in all_text or "openapi" in all_text or "api-docs" in all_text
    has_graphql = "graphql" in all_text
    has_upload = "upload" in all_text
    has_redirect = "redirect" in all_text or "callback" in all_text or "returnurl" in all_text
    has_idor_surface = any(re.search(r"(user|account|invoice|order|profile|id=|uuid=)", normalize_text(f)) for f in findings)
    has_server_error = any(str(f.get("status")) in ["500", "502", "503"] for f in findings)
    has_sensitive_file = any(re.search(r"(\.env|\.git|backup|dump|\.bak|\.old|\.zip|\.tar|\.gz)", normalize_text(f)) for f in findings)

    open_ports = {str(f.get("port")) for f in findings if f.get("state") == "open"}
    services = normalize_text(" ".join([str(f.get("service", "")) for f in findings]))

    correlations = []

    if has_admin and (has_403 or has_401):
        correlations.append({
            "name": "Painel administrativo protegido detectado",
            "boost": 20,
            "reason": "Admin/dashboard com 401/403 pode indicar superfície com bypass ou enumeração."
        })

    if has_swagger:
        correlations.append({
            "name": "Documentação de API exposta",
            "boost": 25,
            "reason": "Swagger/OpenAPI pode revelar endpoints, parâmetros e fluxos internos."
        })

    if has_graphql:
        correlations.append({
            "name": "GraphQL detectado",
            "boost": 25,
            "reason": "GraphQL pode permitir introspection, IDOR, BOLA e enumeração de schema."
        })

    if has_upload and has_idor_surface:
        correlations.append({
            "name": "Upload + superfície de objeto/usuário",
            "boost": 25,
            "reason": "Combinação relevante para IDOR, upload abuse, overwrite ou acesso indevido."
        })

    if has_redirect and has_403:
        correlations.append({
            "name": "Redirect/callback + recurso protegido",
            "boost": 20,
            "reason": "Pode indicar open redirect, OAuth abuse, bypass de autorização ou SSRF indireto."
        })

    if has_server_error:
        correlations.append({
            "name": "Erros server-side detectados",
            "boost": 20,
            "reason": "Erros 5xx indicam possível falha de parsing, stack trace ou vetor de fuzzing."
        })

    if has_sensitive_file:
        correlations.append({
            "name": "Possível arquivo sensível exposto",
            "boost": 30,
            "reason": "Arquivos como .env, .git, backups e dumps são altamente relevantes."
        })

    if "22" in open_ports and "80" in open_ports:
        correlations.append({
            "name": "SSH + HTTP no mesmo host",
            "boost": 10,
            "reason": "Pode indicar servidor tradicional com stack web e acesso administrativo exposto."
        })

    if any(p in open_ports for p in ["3306", "5432", "6379", "27017", "9200"]):
        correlations.append({
            "name": "Serviço de banco/cache/search exposto",
            "boost": 35,
            "reason": "Portas de dados expostas costumam ter alto impacto se mal configuradas."
        })

    if "smtp" in services or "25" in open_ports:
        correlations.append({
            "name": "SMTP detectado",
            "boost": 15,
            "reason": "Pode ser útil para testar spoofing, enumeração, relay incorreto ou exposição de banner."
        })

    for item in findings:
        item_text = normalize_text(item)
        item["correlations"] = []

        for corr in correlations:
            applies = False

            if "admin" in item_text or "dashboard" in item_text or "manager" in item_text:
                applies = True
            if "swagger" in item_text or "openapi" in item_text or "api-docs" in item_text:
                applies = True
            if "graphql" in item_text:
                applies = True
            if "upload" in item_text or "file" in item_text:
                applies = True
            if "redirect" in item_text or "callback" in item_text:
                applies = True
            if re.search(r"(\.env|\.git|backup|dump|\.bak|\.old|\.zip|\.tar|\.gz)", item_text):
                applies = True
            if str(item.get("status")) in ["401", "403", "500", "502", "503"]:
                applies = True
            if item.get("state") == "open":
                applies = True

            if applies:
                item["score"] = min(item.get("score", 0) + corr["boost"], 100)
                item["reasons"].append(f"Correlação: {corr['name']}")
                item["correlations"].append(corr)

        item["classification"] = classify(item.get("score", 0), config)

    return sorted(findings, key=lambda x: x.get("score", 0), reverse=True)


def parse_ffuf_json(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    findings = []

    for r in data.get("results", []):
        findings.append({
            "source": "ffuf",
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "content_type": r.get("content-type") or r.get("content_type"),
            "input": r.get("input")
        })

    return findings


def parse_nmap_xml(path: str) -> List[Finding]:
    tree = ET.parse(path)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.attrib.get("addr") if addr_el is not None else None

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            port_id = port.attrib.get("portid")
            protocol = port.attrib.get("protocol")

            state_el = port.find("state")
            state = state_el.attrib.get("state") if state_el is not None else None

            service_el = port.find("service")
            service = service_el.attrib.get("name") if service_el is not None else None
            product = service_el.attrib.get("product") if service_el is not None else None
            version = service_el.attrib.get("version") if service_el is not None else None
            extrainfo = service_el.attrib.get("extrainfo") if service_el is not None else None
            cpe_items = [cpe.text for cpe in service_el.findall("cpe")] if service_el is not None else []

            if state == "open":
                findings.append({
                    "source": "nmap",
                    "host": ip,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "cpe": cpe_items
                })

    return findings


def parse_generic_log(path: str) -> List[Finding]:
    findings = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            status = None
            status_match = re.search(r"\s([1-5][0-9]{2})\s", f" {line} ")

            if status_match:
                status = int(status_match.group(1))

            url_match = re.search(r"(https?://[^\s\"']+|/[A-Za-z0-9_\-./?=&%]+)", line)
            url = url_match.group(1) if url_match else None

            findings.append({
                "source": "generic_log",
                "line_no": line_no,
                "raw": line[:1000],
                "url": url,
                "status": status
            })

    return findings


def detect_file_type(path: str) -> str:
    if path.lower().endswith(".json"):
        return "ffuf_json"

    if path.lower().endswith(".xml"):
        return "nmap_xml"

    return "generic_log"


def llm_analyze(finding: Finding, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    llm_cfg = config.get("llm", {})

    if not llm_cfg.get("enabled"):
        return None

    if OpenAI is None:
        return None

    api_key = os.getenv(llm_cfg.get("api_key_env", "OPENAI_API_KEY"))

    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    prompt = f"""
Você é um analista de segurança ofensiva em Bug Bounty.

Analise este item de recon e classifique como:
- ruido
- interessante
- potencial_vulnerabilidade

Retorne JSON válido com:
classification, confidence, possible_vulnerabilities, exploitation_ideas, impact, notes.

Item:
{json.dumps(finding, ensure_ascii=False, indent=2)}
"""

    try:
        response = client.chat.completions.create(
            model=llm_cfg.get("model", "gpt-4.1-mini"),
            messages=[
                {
                    "role": "system",
                    "content": "Você classifica outputs de recon com foco em Bug Bounty. Levante hipóteses plausíveis sem inventar fatos."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2
        )

        content = response.choices[0].message.content.strip()

        try:
            return json.loads(content)
        except Exception:
            return {"raw_llm_output": content}

    except Exception as e:
        return {"llm_error": str(e)}


def enrich_findings(
    findings: List[Finding],
    config: Dict[str, Any],
    use_llm: bool,
    use_cve: bool
) -> List[Finding]:
    enriched = []

    for item in findings:
        local = calculate_score(item, config)
        item["score"] = local["score"]
        item["classification"] = local["classification"]
        item["reasons"] = local["reasons"]
        enriched.append(item)

    enriched = apply_correlation_engine(enriched, config)

    if use_cve:
        enriched = apply_cve_enrichment(enriched, config)

    if use_llm:
        for item in enriched:
            if item["classification"] != "ruido":
                item["llm_analysis"] = llm_analyze(item, config)

    return sorted(enriched, key=lambda x: x.get("score", 0), reverse=True)


def write_json(findings: List[Finding], output: str):
    with open(output, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def write_markdown(findings: List[Finding], output: str):
    with open(output, "w", encoding="utf-8") as f:
        f.write("# Recon AI Triage\n\n")

        visible = [x for x in findings if x.get("classification") != "ruido"]

        if not visible:
            f.write("Nenhum achado acima do threshold atual.\n\n")
            f.write("Dica: reduza `interesting_threshold` no config.yaml para visualizar mais sinais.\n")
            return

        for item in visible:
            f.write(f"## {item.get('classification')} — Score {item.get('score')}\n\n")

            f.write("### Resumo\n\n")
            f.write(f"- Source: `{item.get('source')}`\n")

            if item.get("host"):
                f.write(f"- Host: `{item.get('host')}`\n")

            if item.get("port"):
                f.write(f"- Port: `{item.get('port')}`\n")

            if item.get("service"):
                f.write(f"- Service: `{item.get('service')}`\n")

            if item.get("product"):
                f.write(f"- Product: `{item.get('product')}`\n")

            if item.get("version"):
                f.write(f"- Version: `{item.get('version')}`\n")

            if item.get("url"):
                f.write(f"- URL: `{item.get('url')}`\n")

            if item.get("status"):
                f.write(f"- Status: `{item.get('status')}`\n")

            f.write("\n### Motivos\n\n")

            for reason in item.get("reasons", []):
                f.write(f"- {reason}\n")

            if item.get("correlations"):
                f.write("\n### Correlações\n\n")

                for corr in item["correlations"]:
                    f.write(f"- **{corr['name']}**: {corr['reason']}\n")

            if item.get("cves"):
                f.write("\n### CVE Enrichment\n\n")
                f.write(f"- Query: `{item.get('cve_query')}`\n\n")

                for cve in item["cves"]:
                    if cve.get("id"):
                        f.write(f"- **{cve.get('id')}**")
                        if cve.get("severity") or cve.get("cvss"):
                            f.write(f" — {cve.get('severity')} / CVSS {cve.get('cvss')}")
                        f.write("\n")
                        if cve.get("description"):
                            f.write(f"  - {cve.get('description')}\n")
                    elif cve.get("error"):
                        f.write(f"- Erro ao consultar CVE: `{cve.get('error')}`\n")

            f.write("\n### JSON bruto\n\n")
            f.write("```json\n")
            f.write(json.dumps(item, ensure_ascii=False, indent=2))
            f.write("\n```\n\n")


def print_summary(findings: List[Finding], output: str, markdown: str):
    total = len(findings)
    vuln = len([x for x in findings if x["classification"] == "potencial_vulnerabilidade"])
    interesting = len([x for x in findings if x["classification"] == "interessante"])
    noise = len([x for x in findings if x["classification"] == "ruido"])

    print(f"[+] Total analisado: {total}")
    print(f"[+] Potenciais vulnerabilidades: {vuln}")
    print(f"[+] Interessantes: {interesting}")
    print(f"[+] Ruído: {noise}")
    print(f"[+] JSON salvo em: {output}")
    print(f"[+] Markdown salvo em: {markdown}")

    top = [x for x in findings if x["classification"] != "ruido"][:5]

    if top:
        print("\n[+] Top findings:")
        for item in top:
            label = item.get("url") or f"{item.get('host')}:{item.get('port')}"
            print(f"    - {item['classification']} | score={item['score']} | {label}")


def main():
    parser = argparse.ArgumentParser(description="Recon AI Triage para Nmap, FFUF e logs.")
    parser.add_argument("-i", "--input", required=True, help="Arquivo de entrada")
    parser.add_argument("-c", "--config", default="config.yaml", help="Arquivo config.yaml")
    parser.add_argument("-o", "--output", default="outputs/findings.json", help="Saída JSON")
    parser.add_argument("--markdown", default="outputs/findings.md", help="Saída Markdown")
    parser.add_argument("--no-llm", action="store_true", help="Desabilita análise por LLM")
    parser.add_argument("--cve", action="store_true", help="Ativa enriquecimento CVE via NVD")

    args = parser.parse_args()

    config = load_config(args.config)
    file_type = detect_file_type(args.input)

    if file_type == "ffuf_json":
        findings = parse_ffuf_json(args.input)
    elif file_type == "nmap_xml":
        findings = parse_nmap_xml(args.input)
    else:
        findings = parse_generic_log(args.input)

    use_llm = not args.no_llm
    use_cve = args.cve

    enriched = enrich_findings(findings, config, use_llm, use_cve)

    Path("outputs").mkdir(exist_ok=True)

    write_json(enriched, args.output)
    write_markdown(enriched, args.markdown)
    print_summary(enriched, args.output, args.markdown)


if __name__ == "__main__":
    main()
