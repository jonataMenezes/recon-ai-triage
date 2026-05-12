import os
import sys
from google import genai

def clean_logs(raw_data):
    """Refinaria agressiva para evitar erro de cota (429)."""
    important_lines = []
    # Foco total no que importa para o pesquisador
    for line in raw_data.splitlines():
        # Filtramos apenas resultados REAIS de ferramentas
        if "[SUBDOMAIN]" in line or "[HTTPX]" in line:
            # Removemos cores de terminal e espaços inúteis para economizar tokens
            clean_line = line.replace("[31m", "").replace("[0m", "").replace("[35m", "").strip()
            important_lines.append(clean_line)
    
    # Pegamos apenas os primeiros 100 resultados para garantir que caiba na cota
    return "\n".join(important_lines[:500]) 

def analyze(log_path):
    api_key = os.getenv("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)
    
    if not os.path.exists(log_path):
        print(f"[!] Arquivo não encontrado: {log_path}")
        return

    with open(log_path, 'r', encoding='utf-8') as f:
        raw_data = f.read()

    # Reduzimos 276k caracteres para algo em torno de 5k a 10k
    refined_data = clean_logs(raw_data)
    
    if not refined_data:
        print("[!] Nenhum resultado de HTTPX ou Subdomínios encontrado.")
        return

    prompt = f"""
    Aja como um Pentester Sênior. Analise estes resultados de recon do alvo Syfe.
    Identifique os 3 alvos mais promissores para testes de:
    1. Broken Access Control (Status 200 em caminhos sensíveis)
    2. Cloud Misconfiguration (Firebase/S3)
    3. Bypass de WAF (Subdomínios que pareçam esquecidos)

    DADOS:
    {refined_data}
    """

    print(f"[*] Dados refinados com sucesso. Enviando para análise estratégica...")
    
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash", 
            contents=prompt
        )
        print("\n" + "==="*15)
        print("🎯 ALVOS PRIORITÁRIOS - SYFE.COM")
        print("==="*15)
        print(response.text)
    except Exception as e:
        if "429" in str(e):
            print("[!] Cota ainda esgotada. Aguarde 60 segundos e tente novamente.")
        else:
            print(f"[!] Erro: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze(sys.argv[1])