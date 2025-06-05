# CVE Wiki
from bs4 import BeautifulSoup

import requests
from colores import bcolors, colors

def CVEWiki():
    print("=" * 50)
    # Necesito esto porque algunas apginas si no le añades un user agent no te dejan entrar.
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    }
    try:
        cve_user = input(f"{bcolors.OKBLUE}Introduce un CVE ->{bcolors.ENDC} ")
        # CVE de testing -> CVE-2025-24201
        url_completa = "https://nvd.nist.gov/vuln/detail/"+cve_user
        response = requests.get(url_completa, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extraer la descripción
            description_tag = soup.find(
                'p', attrs={"data-testid": "vuln-description"})
            description = description_tag.text.strip() if description_tag else "No encontrada"

            # Extraer gravedad
            severity_tag = soup.find(
                'a', attrs={"data-testid": "vuln-cvss3-panel-score"})
            severity = severity_tag.text.strip() if severity_tag else "No encontrada"

            # Extraer fecha de descubrimiento
            published_date_tag = soup.find(
                'span', attrs={"data-testid": "vuln-published-on"})
            published_date = published_date_tag.text.strip(
            ) if published_date_tag else "No encontrada"

            # Lo que se mostrara por pantalla
            print("-" * 50)
            print(f"{bcolors.OKCYAN}Descripción:\n{bcolors.ENDC}", description)
            print("-" * 50)
            print(f"{bcolors.OKCYAN}Gravedad (CVSS Score):\n{bcolors.ENDC}", severity)
            print("-" * 50)
            print(
                f"{bcolors.OKCYAN}Fecha de descubrimiento:\n{bcolors.ENDC}", published_date)
            print("-" * 50)
            print(
                f"{bcolors.OKCYAN}Mas información en:\n{bcolors.ENDC}", url_completa)

        else:
            print("No se ha encontrado: " + cve_user)
        print("=" * 50)
    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")

