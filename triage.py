# Recon AI Triage - v1.1.1 (Debian Optimized)
# Features: Nmap, FFUF, logs, scoring, correlation engine, optional LLM, CVE enrichment (NVD v2.0 Fix)

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

    risky_ports = {"21": "FTP exposto", "22": "SSH exposto", "23": "Telnet exposto", "25": "SMTP exposto", "3306": "MySQL exposto", "5432": "PostgreSQL exposto", "6379": "Redis exposto", "9200": "Elasticsearch exposto", "27017": "MongoDB exposto", "11211": "Memcached exposto"}

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

    return {
        "score": min(score, 100),
        "classification": classify(score, config),
        "reasons": reasons
    }

def build_cve_query(product: str, version: str) -> Optional[str]:
    p_l, v_l = normalize_text(product), normalize_text(version)
    if not p_l: return None
    return f"{product} {version}".strip()

def fetch_cves_nvd(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    encoded = urllib.parse.urlencode({"keywordSearch": query, "cvssV3Severity": "HIGH"})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{encoded}"
    req = urllib.request.Request(url, headers={"User-Agent": "Recon-AI-Triage/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return [{"error": str(e), "query": query}]

    results = []
    for vuln in data.get("vulnerabilities", [])[:limit]:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score, severity = cvss.get("baseScore"), cvss.get("baseSeverity")
        
        description = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        
        # --- FIX: Correção do erro de atributo 'get' em lista ---
        raw_references = cve.get("references", [])
        extracted_refs = [ref.get("url") for ref in raw_references if isinstance(ref, dict)]

        results.append({
            "id": cve.get("id"),
            "severity": severity,
            "cvss": cvss_score,
            "description": description[:500],
            "references": extracted_refs[:5]
        })
    return results

def apply_cve_enrichment(findings: List[Finding], config: Dict[str, Any]) -> List[Finding]:
    cache = {}
    for item in findings:
        product, version = item.get("product"), item.get("version")
        if not product: continue
        query = build_cve_query(product, version or "")
        if not query: continue
        if query not in cache: cache[query] = fetch_cves_nvd(query)
        
        item["cve_query"], item["cves"] = query, cache[query]
        valid_cves = [c for c in item["cves"] if c.get("id")]
        if valid_cves:
            item["score"] = min(item.get("score", 0) + 20, 100)
            item["reasons"].append(f"CVE enrichment encontrou {len(valid_cves)} CVEs HIGH")
            item["classification"] = classify(item["score"], config)
    return findings

def apply_correlation_engine(findings: List[Finding], config: Dict[str, Any]) -> List[Finding]:
    # Lógica de correlação simplificada para performance
    for item in findings:
        item["correlations"] = []
        # Exemplo: Se for 403 e tiver 'admin' no texto
        if str(item.get("status")) == "403" and "admin" in normalize_text(item):
            item["score"] = min(item["score"] + 20, 100)
            item["reasons"].append("Correlação: Painel administrativo protegido")
    return findings

def parse_nmap_xml(path: str) -> List[Finding]:
    tree = ET.parse(path)
    root = tree.getroot()
    findings = []
    for host in root.findall("host"):
        ip = host.find("address").attrib.get("addr")
        for port in host.find("ports").findall("port"):
            p_id = port.attrib.get("portid")
            state = port.find("state").attrib.get("state")
            service_el = port.find("service")
            if state == "open":
                findings.append({
                    "source": "nmap", "host": ip, "port": p_id, "state": state,
                    "service": service_el.attrib.get("name") if service_el is not None else None,
                    "product": service_el.attrib.get("product") if service_el is not None else None,
                    "version": service_el.attrib.get("version") if service_el is not None else None
                })
    return findings

def parse_ffuf_json(path: str) -> List[Finding]:
    with open(path, "r") as f:
        data = json.load(f)
    return [{"source": "ffuf", "url": r.get("url"), "status": r.get("status")} for r in data.get("results", [])]

def enrich_findings(findings: List[Finding], config: Dict[str, Any], use_llm: bool, use_cve: bool) -> List[Finding]:
    enriched = []
    for item in findings:
        res = calculate_score(item, config)
        item.update(res)
        enriched.append(item)
    enriched = apply_correlation_engine(enriched, config)
    if use_cve: enriched = apply_cve_enrichment(enriched, config)
    return sorted(enriched, key=lambda x: x.get("score", 0), reverse=True)

def write_markdown(findings: List[Finding], output: str):
    with open(output, "w") as f:
        f.write("# Recon AI Triage Report\n\n")
        for item in [x for x in findings if x["classification"] != "ruido"]:
            f.write(f"## {item['classification']} (Score: {item['score']})\n")
            f.write(f"- Destino: {item.get('url') or item.get('host')}\n")
            f.write(f"- Motivos: {', '.join(item['reasons'])}\n\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("-o", "--output", default="outputs/findings.json")
    parser.add_argument("--markdown", default="outputs/findings.md")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--cve", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    ext = args.input.split('.')[-1]
    findings = parse_nmap_xml(args.input) if ext == 'xml' else parse_ffuf_json(args.input)
    
    enriched = enrich_findings(findings, config, not args.no_llm, args.cve)
    Path("outputs").mkdir(exist_ok=True)
    with open(args.output, "w") as f: json.dump(enriched, f, indent=2)
    write_markdown(enriched, args.markdown)
    print(f"[+] Triagem concluída. Resultados em {args.output}")

if __name__ == "__main__":
    main()
