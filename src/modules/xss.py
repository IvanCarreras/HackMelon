# ---------------------------------------------------------------#
#                              XSS                               #
# ---------------------------------------------------------------#

import os
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import time
from colores import bcolors
def cargar_payloads(path):
    with open(path, encoding='utf-8', errors='ignore') as file:
        return file.read().splitlines()

# La peticion
def hacer_peticion_xss(url):
    try:
        return requests.get(url, timeout=5)
    except requests.RequestException:
        return None


def XSS_script():
    print("=" * 50)
    try:
        base_url = input("Introduce una URL con el parámetro (ej: http://target.com/page?input=): ").strip()
        if "=" not in base_url:
            print("[-] La URL debe contener un parámetro (por ejemplo '?q=')")
            return
        
        print(f"{bcolors.OKGREEN}[+] Fuzzing iniciado con {len(urls)} rutas posibles...{bcolors.ENDC}")
        start_time = time.time()

        diccionario = os.path.abspath(os.path.join(os.path.dirname(__file__),"..","..", "assets", "xss-payload-list.txt"))
        payloads = cargar_payloads(diccionario)

        barra = tqdm(total=len(payloads), desc="Progreso", unit="payloads", dynamic_ncols=True)
        vulnerable = False

        with ThreadPoolExecutor(max_workers=20) as executor:
            for payload in payloads:
                url_test = base_url + payload
                response = hacer_peticion_xss(url_test)

                if response and payload in response.text:
                    tqdm.write(f"[+] Vulnerable a XSS con payload: {payload}")
                    vulnerable = True

                barra.update(1)

        if not vulnerable:
            print(f"[✓] La URL '{base_url}' no parece vulnerable a XSS con esta wordlist.")

    except KeyboardInterrupt:
        print("\n[-] Script interrumpido por el usuario.")
    finally:
        barra.close()
        print(f"{bcolors.OKGREEN}[✓] Fuzzing finalizado en {round(time.time() - start_time, 2)} segundos.{bcolors.ENDC}")

        print("=" * 50)