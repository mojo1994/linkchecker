import requests
import base64
import argparse
from colorama import Fore, Style, init
import socket

# Inicializa o colorama
init(autoreset=True)

# Configuração da API
API_KEY = 'febdad7d0cfb29952da3f58ffa7c44fc18fdb4e4297076206a4a12e56abffe80'
BASE_URL = 'https://www.virustotal.com/api/v3/urls'

# Exibe o título estilizado
def show_title():
    print(Fore.GREEN + Style.BRIGHT + "===================================")
    print(Fore.MAGENTA + Style.BRIGHT + "            LINK CHECKER           ")
    print(Fore.GREEN + Style.BRIGHT + "===================================\n")

# Função para exibir o menu inicial
def show_menu():
    print(Fore.CYAN + """
    Escolha uma opção:
      1. Verificar IP do site
      2. Verificar vulnerabilidade do site
      3. Verificar se o site é seguro
      -h   Mostrar ajuda
      -L   Listar histórico
    """)

# Função para codificar URLs em Base64
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

# Função para verificar o IP do site
def get_site_ip(site):
    try:
        ip = socket.gethostbyname(site)
        print(Fore.GREEN + f"O IP do site {site} é: {ip}")
    except Exception as e:
        print(Fore.RED + f"[ERRO] Não foi possível obter o IP: {e}")

# Função para verificar vulnerabilidades do site
def check_vulnerability(site):
    try:
        print(Fore.YELLOW + f"[INFO] Verificando vulnerabilidades no site {site}...")
        response = requests.get(f"https://www.vulnscan.org/api/v1/?url={site}")

        if response.status_code == 200:
            data = response.json()
            if data['vulnerabilities']:
                print(Fore.RED + "[ALERTA] Vulnerabilidades encontradas:")
                for vuln in data['vulnerabilities']:
                    print(Fore.RED + f"- {vuln}")
            else:
                print(Fore.GREEN + "[SEGURO] Nenhuma vulnerabilidade encontrada.")
        else:
            print(Fore.RED + f"[ERRO] Não foi possível verificar as vulnerabilidades: {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[ERRO] Ocorreu um erro: {e}")

# Função para verificar se o site é seguro
def check_url(url, force=False):
    try:
        encoded_url = encode_url(url)
        headers = {'x-apikey': API_KEY}
        response = requests.get(f"{BASE_URL}/{encoded_url}", headers=headers)

        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)

            print(Fore.GREEN + f"[SEGURO] {stats.get('harmless', 0)} mecanismos consideraram o link seguro.")
            print(Fore.RED + f"[MALICIOSO] {malicious} mecanismos identificaram como malicioso.")
            print(Fore.YELLOW + f"[SUSPEITO] {stats.get('suspicious', 0)} mecanismos consideraram suspeito.")
            print(Fore.CYAN + "Detalhes das detecções:")
            for scanner, report in result['data']['attributes']['last_analysis_results'].items():
                status = report['result']
                color = Fore.RED if report['category'] == 'malicious' else Fore.GREEN
                print(f"  {scanner}: {color}{status}")

            # Forçar nova análise se solicitado
            if force:
                print(Fore.MAGENTA + "[FORÇANDO] Enviando o link para análise completa...")
                submit_url(url)

        elif response.status_code == 404:
            print(Fore.YELLOW + f"[ERRO] O link {url} não foi encontrado no banco do VirusTotal. Enviando para análise.")
            submit_url(url)
        else:
            print(Fore.RED + f"[ERRO] Erro ao verificar o link: {response.status_code}")
            print(response.json())
    except Exception as e:
        print(Fore.RED + f"[ERRO] Ocorreu um erro: {e}")

# Função para enviar uma URL para análise
def submit_url(url):
    headers = {'x-apikey': API_KEY}
    response = requests.post(BASE_URL, headers=headers, data={'url': url})

    if response.status_code == 200:
        print(Fore.GREEN + f"[OK] URL enviada para análise com sucesso!")
    else:
        print(Fore.RED + f"[ERRO] Falha ao enviar URL. Código: {response.status_code}")

# Função para listar URLs verificadas (simulado)
def list_urls():
    print(Fore.CYAN + "[INFO] Histórico de URLs verificadas (salvar em arquivo futuramente):")
    print(Fore.YELLOW + "  Nenhuma URL no histórico (ainda não implementado).")

# Função principal
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', action='store_true', help='Exibir ajuda.')
    parser.add_argument('-L', action='store_true', help='Listar histórico.')
    args = parser.parse_args()

    # Exibe o título
    show_title()

    # Opções globais
    if args.h:
        print(Fore.CYAN + """
        Link Checker - Ajuda
        ----------------------
        Opções globais:
          -h   Exibe esta ajuda.
          -L   Lista o histórico de URLs verificadas.
        
        Navegue pelo menu principal para escolher uma das funções.
        """)
        return
    elif args.L:
        list_urls()
        return

    # Exibe o menu inicial
    while True:
        show_menu()
        escolha = input(Fore.GREEN + ">>> ").strip()
        
        if escolha == "1":
            site = input(Fore.CYAN + "Digite o domínio do site (ex: example.com): ").strip()
            get_site_ip(site)
        elif escolha == "2":
            site = input(Fore.CYAN + "Digite o domínio do site (ex: example.com): ").strip()
            check_vulnerability(site)
        elif escolha == "3":
            url = input(Fore.CYAN + "Digite a URL completa (ex: https://example.com): ").strip()
            force = input(Fore.YELLOW + "Forçar análise? (s/n): ").strip().lower() == 's'
            check_url(url, force)
        elif escolha.lower() in ["sair", "exit"]:
            print(Fore.MAGENTA + "Encerrando o LINK CHECKER. Até a próxima!")
            break
        else:
            print(Fore.RED + "Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
