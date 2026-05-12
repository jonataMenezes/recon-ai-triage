import os
import re
import json
import yaml
import argparse
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
        return yaml.safe_load(f)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def calculate_score(item: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons = []

    text = normalize_text(json.dumps(item, ensure_ascii=False))

    high_keywords = config["keywords"]["high"]
    medium_keywords = config["keywords"]["medium"]

    for kw in high_keywords:
        if kw.lower() in text:
            score += 20
            reasons.append(f"Keyword crítica encontrada: {kw}")

    for kw in medium_keywords:
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
        "Possível actuator exposto": r"actuator",
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

    if "version" in item and item["version"]:
        score += 10
        reasons.append("Banner/versionamento exposto")

    if score >= config["scoring"]["vuln_threshold"]:
        classification = "potencial_vulnerabilidade"
    elif score >= config["scoring"]["interesting_threshold"]:
        classification = "interessante"
    else:
        classification = "ruido"

    return {
        "score": min(score, 100),
        "classification": classification,
        "reasons": reasons
    }


def parse_ffuf_json(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    results = data.get("results", [])
    findings = []

    for r in results:
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
    p = path.lower()

    if p.endswith(".json"):
        return "ffuf_json"

    if p.endswith(".xml"):
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

Analise este item de recon e diga se é:
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
                    "content": "Você classifica outputs de recon com foco em Bug Bounty. Não invente fatos, mas levante hipóteses plausíveis."
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


def enrich_findings(findings: List[Finding], config: Dict[str, Any], use_llm: bool) -> List[Finding]:
    enriched = []

    for item in findings:
        local = calculate_score(item, config)

        item["score"] = local["score"]
        item["classification"] = local["classification"]
        item["reasons"] = local["reasons"]

        if use_llm and item["classification"] != "ruido":
            item["llm_analysis"] = llm_analyze(item, config)

        enriched.append(item)

    return sorted(enriched, key=lambda x: x.get("score", 0), reverse=True)


def write_json(findings: List[Finding], output: str):
    with open(output, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def write_markdown(findings: List[Finding], output: str):
    with open(output, "w", encoding="utf-8") as f:
        f.write("# Recon AI Triage\n\n")

        for item in findings:
            if item.get("classification") == "ruido":
                continue

            f.write(f"## {item.get('classification')} — Score {item.get('score')}\n\n")
            f.write("```json\n")
            f.write(json.dumps(item, ensure_ascii=False, indent=2))
            f.write("\n```\n\n")


def main():
    parser = argparse.ArgumentParser(description="Recon AI Triage para Nmap, FFUF e logs.")
    parser.add_argument("-i", "--input", required=True, help="Arquivo de entrada")
    parser.add_argument("-c", "--config", default="config.yaml", help="Arquivo config.yaml")
    parser.add_argument("-o", "--output", default="outputs/findings.json", help="Saída JSON")
    parser.add_argument("--markdown", default="outputs/findings.md", help="Saída Markdown")
    parser.add_argument("--no-llm", action="store_true", help="Desabilita análise por LLM")
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
    enriched = enrich_findings(findings, config, use_llm)

    Path("outputs").mkdir(exist_ok=True)

    write_json(enriched, args.output)
    write_markdown(enriched, args.markdown)

    total = len(enriched)
    vuln = len([x for x in enriched if x["classification"] == "potencial_vulnerabilidade"])
    interesting = len([x for x in enriched if x["classification"] == "interessante"])
    noise = len([x for x in enriched if x["classification"] == "ruido"])

    print(f"[+] Total analisado: {total}")
    print(f"[+] Potenciais vulnerabilidades: {vuln}")
    print(f"[+] Interessantes: {interesting}")
    print(f"[+] Ruído: {noise}")
    print(f"[+] JSON salvo em: {args.output}")
    print(f"[+] Markdown salvo em: {args.markdown}")


if __name__ == "__main__":
    main()
