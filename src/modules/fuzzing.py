import os
# Fuzzing & XSS
import argparse
import requests
from tqdm import tqdm

from colores import bcolors

def fuzzing():
    print("=" * 50)
    # Status Codes HTTP -> https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
    # TODO refactorizar las wordlists
    # Datos para el fuzzing
    url_user = input(f"{bcolors.OKBLUE}Introduce la Url:\n{bcolors.ENDC}")
    diccionario = os.path.join(os.path.dirname(
        __file__), "assets", "directory-list-2.3-medium.txt")

    with open(diccionario) as file:
        wordlist = file.read().splitlines()

    try:
        barrita = tqdm(total=len(wordlist), desc="Progreso",
                       unit="urls", dynamic_ncols=True)

        for linea in wordlist:
            url_completa = url_user + linea
            url_completa1 = url_user + linea + ".txt"
            url_completa2 = url_user + linea + ".html"

            response = requests.get(url_completa)
            response1 = requests.get(url_completa1)
            response2 = requests.get(url_completa2)

            if ((not response.is_redirect) or (not response.is_permanent_redirect)):
                if response.status_code == 200:  # OK
                    tqdm.write(
                        f"/{linea} {bcolors.OKCYAN}(Status: 200){bcolors.ENDC} [Size: {len(response.content)}] [{response.url}]")

                elif response1.status_code == 200:
                    tqdm.write(
                        f"/{linea}.txt {bcolors.OKCYAN}(Status: 200){bcolors.ENDC} [Size: {len(response.content)}]")

                elif response2.status_code == 200:
                    tqdm.write(
                        f"/{linea}.html {bcolors.OKCYAN}(Status: 200){bcolors.ENDC} [Size: {len(response.content)}]")

            elif response.status_code == 301:  # URL Moved permanently
                tqdm.write(
                    f"{linea} {bcolors.WARNING}(Status: 301){bcolors.ENDC} [Size: {len(response.content)}] [{response.url}]")

            elif response1.status_code == 301:
                tqdm.write(
                    f"{linea}.txt {bcolors.WARNING}(Status: 301){bcolors.ENDC} [Size: {len(response.content)}]")

            elif response2.status_code == 301:
                tqdm.write(
                    f"{linea}.html {bcolors.WARNING}(Status: 301){bcolors.ENDC} [Size: {len(response.content)}]")

            barrita.update(1)

    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")

    finally:
        barrita.close()
    print("=" * 50)
