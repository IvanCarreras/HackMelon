# CVE Wiki
from bs4 import BeautifulSoup
import re
import requests
from colores import bcolors, colors
# Regex para validar formato de CVE
patron_cve = re.compile(r"^CVE-\d{4}-\d{4,}$")

def extraer_info_cve(html):
    soup = BeautifulSoup(html, 'html.parser')
    
    def get_text_by_id(tag, attrs):
        elemento = soup.find(tag, attrs=attrs)
        return elemento.text.strip() if elemento else "No encontrada"

    return {
        "descripcion": get_text_by_id('p', {"data-testid": "vuln-description"}),
        "gravedad": get_text_by_id('a', {"data-testid": "vuln-cvss3-panel-score"}),
        "fecha": get_text_by_id('span', {"data-testid": "vuln-published-on"}),
    }

def CVEWiki():
    print("=" * 50)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    }

    try:
        cve_user = input(f"{bcolors.OKBLUE}Introduce un CVE ->{bcolors.ENDC} ").strip().upper()

        if not patron_cve.match(cve_user):
            print(f"{bcolors.FAIL}[-] Formato de CVE inválido. Usa CVE-YYYY-NNNN{bcolors.ENDC}")
            return

        url_completa = f"https://nvd.nist.gov/vuln/detail/{cve_user}"
        response = requests.get(url_completa, headers=headers, timeout=10)

        if response.status_code == 200:
            datos = extraer_info_cve(response.text)

            print("-" * 50)
            print(f"{bcolors.OKCYAN}Descripción:\n{bcolors.ENDC}", datos["descripcion"])
            print("-" * 50)
            print(f"{bcolors.OKCYAN}Gravedad (CVSS Score):\n{bcolors.ENDC}", datos["gravedad"])
            print("-" * 50)
            print(f"{bcolors.OKCYAN}Fecha de descubrimiento:\n{bcolors.ENDC}", datos["fecha"])
            print("-" * 50)
            print(f"{bcolors.OKCYAN}Más información:\n{bcolors.ENDC}", url_completa)
        else:
            print(f"{bcolors.FAIL}[-] No se pudo obtener información (HTTP {response.status_code}){bcolors.ENDC}")
        print("=" * 50)

    except requests.exceptions.RequestException as e:
        print(f"{bcolors.FAIL}[!] Error de conexión: {e}{bcolors.ENDC}")
    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")