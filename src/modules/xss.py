# ---------------------------------------------------------------#
#                              XSS SCANNER                       #
# ---------------------------------------------------------------#

import os
import re
import html
import time
import requests
from tqdm import tqdm
from colores import bcolors
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Fichero de payloads
def cargar_payloads(path):
    with open(path, encoding='utf-8', errors='ignore') as file:
        return file.read().splitlines()

# La peticion
def hacer_peticion_xss(url):
    try:
        return requests.get(url, timeout=5)
    except requests.RequestException:
        return None

# Contruye la URL para que no pete
def construir_url(base_url, payload):
    # Reemplaza el valor del parámetro con el payload
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    if not qs:
        return None
    param = list(qs.keys())[0]
    qs[param] = payload
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def XSS_script():
    print("=" * 50)
    try:
        # La url insertada por el usuario + algun ajuste por si acaso
        base_url = input("Introduce una URL con el parámetro (ej: http://target.com/page?input=): ").strip()
        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url

        if "=" not in base_url:
            print("[-] La URL debe contener un parámetro (por ejemplo '?q=')")
            return

        # Llamada al diccionario
        diccionario = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets", "xss-payload-list.txt"))
        payloads = cargar_payloads(diccionario)

        # Cronometro
        print(f"{bcolors.OKGREEN}[+] XSS Scanner iniciado con {len(payloads)} payloads...{bcolors.ENDC}")
        start_time = time.time()

        # La lista de urls
        vulnerable = False
        urls = [(construir_url(base_url, payload), payload) for payload in payloads]

        # Los hilos que ejecutaran lo que tienen dentro
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Hace una peticion y la respuesta la trata el form de fuera. Asi con todas
            for (url, payload), response in tqdm(zip(urls, executor.map(lambda u: hacer_peticion_xss(u[0]), urls)),
                                                 total=len(urls), desc="Progreso", dynamic_ncols=True):
                if not response or url is None:
                    continue

                # Decodifica la URL a texto normal
                body = html.unescape(response.text)
                raw_payload = payload.strip()
                decoded_payload = html.unescape(payload)
                encoded_payload = requests.utils.quote(payload)

                # Comprueba si esta el contenido del payload en cualquiera de estos
                if any(p in body for p in [raw_payload, decoded_payload, encoded_payload]):
                    tqdm.write(f"{bcolors.WARNING}[+] Vulnerable a XSS con payload: {payload}{bcolors.ENDC}")
                    vulnerable = True
                elif re.search(re.escape(payload), response.text, re.IGNORECASE):
                    tqdm.write(f"{bcolors.WARNING}[+] Payload reflected (regex match): {payload}{bcolors.ENDC}")
                    vulnerable = True
                
                if not vulnerable:
                    print(f"[✓] La URL '{base_url}' no parece vulnerable a XSS con esta wordlist.")

    except KeyboardInterrupt:
        print("\n[-] Script interrumpido por el usuario.")
    finally:
        print(f"{bcolors.OKGREEN}[✓] Fuzzing finalizado en {round(time.time() - start_time, 2)} segundos.{bcolors.ENDC}")
        print("=" * 50)