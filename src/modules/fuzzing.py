# ---------------------------------------------------------------#
#                            Fuzzing                            #
# ---------------------------------------------------------------#
# Status Codes HTTP -> https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status

import os
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from colores import bcolors
import time



def cargar_wordlist(path):
    with open(path) as file:
        return file.read().splitlines()


def hacer_peticion(url):
    try:
        response = requests.get(url, timeout=5)
        return (url, response)
    except requests.RequestException:
        return (url, None)


def fuzzing():
    print("=" * 50)
    url_user = input(f"{bcolors.OKBLUE}Introduce la Url:\n{bcolors.ENDC}")
    if not url_user.startswith(("http://", "https://")):
        url_user = "http://" + url_user

    if not url_user.endswith("/"):
        url_user += "/"

    diccionario = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets", "directory-list-2.3-medium.txt"))
    wordlist = cargar_wordlist(diccionario)
    sufijos = ["", ".txt", ".html"]

    urls = [url_user + linea + sufijo for linea in wordlist for sufijo in sufijos]

    status_handlers = {
        200: f"{bcolors.OKCYAN}(Status: 200){bcolors.ENDC}",
        204: f"{bcolors.OKCYAN}(Status: 204 - Sin contenido){bcolors.ENDC}",
        301: f"{bcolors.WARNING}(Status: 301 - Redirigido){bcolors.ENDC}",
        302: f"{bcolors.WARNING}(Status: 302 - Encontrado){bcolors.ENDC}",
        307: f"{bcolors.WARNING}(Status: 307 - Redirección temporal){bcolors.ENDC}",
        401: f"{bcolors.FAIL}(Status: 401 - No autorizado){bcolors.ENDC}",
        403: f"{bcolors.FAIL}(Status: 403 - Prohibido){bcolors.ENDC}",
    }

    print(f"{bcolors.OKGREEN}[+] Fuzzing iniciado con {len(urls)} rutas posibles...{bcolors.ENDC}")
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            for url, response in tqdm(executor.map(hacer_peticion, urls), total=len(urls), desc="Progreso", dynamic_ncols=True):
                if not response:
                    continue
                msg = status_handlers.get(response.status_code)
                if msg:
                    tqdm.write(f"{url} {msg} [Size: {len(response.content)}]")

    except KeyboardInterrupt:
        print(
            f"\n{bcolors.FAIL}[-] Interrumpido por el usuario. Cancelando tareas...{bcolors.ENDC}")

    finally:
        print(f"{bcolors.OKGREEN}[✓] Fuzzing finalizado en {round(time.time() - start_time, 2)} segundos.{bcolors.ENDC}")
        print("=" * 50)
