#---------------------------------------------------------------#
#                            Fuzzing                            #
#---------------------------------------------------------------#
# Status Codes HTTP -> https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status

import os
import argparse
import requests
from tqdm import tqdm
from colores import bcolors


def cargar_wordlist(path):
    with open(path) as file:
        return file.read().splitlines()

def hacer_peticion(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response
    except requests.RequestException as e:
        return None

def fuzzing():
    print("=" * 50)
    # TODO Arreglar metodo
    # Datos para el fuzzing
    url_user = input(f"{bcolors.OKBLUE}Introduce la Url:\n{bcolors.ENDC}")
    if not url_user.endswith("/"):
        url_user+="/"
    
    diccionario = os.path.join(os.path.dirname(__file__),"..", "..", "assets", "directory-list-2.3-medium.txt")
    wordlist = cargar_wordlist(diccionario)
    sufijos = ["", ".txt", ".html"]
    
    try:
        barrita = tqdm(total=len(wordlist), desc="Progreso", unit="urls", dynamic_ncols=True)

        for linea in wordlist:
            for sufijo in sufijos:
                path = linea + sufijo
                response = hacer_peticion(path)
                if not response:
                    continue
                
                status = response.status_code
                if status == 200:
                    tqdm.write(f"/{path} {bcolors.CYAN}(Status: 200){bcolors.ENDC} [Size: {len(response.content)}] [{response.url}]")
                elif status == 301:
                    tqdm.write(f"/{path} {bcolors.CYAN}(Status: 301 - Redirigido){bcolors.ENDC} [Size: {len(response.content)}] [{response.url}]")
                elif status == 401:
                    tqdm.write(f"/{path} {bcolors.CYAN}(Status: 401 - No autorizado){bcolors.ENDC}")    
                elif status == 403:
                    tqdm.write(f"/{path} {bcolors.CYAN}(Status: 403 - Prohibido){bcolors.ENDC}")

                barrita.update(1)

    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")
    finally:
        barrita.close()
        print("=" * 50)
