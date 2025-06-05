import os
import requests
from tqdm import tqdm

def XSS_script():
    print("=" * 50)
    # https://xss-game.appspot.com/level1/frame?query=
    # "http://localhost/Web_pruebas/?name="

    try:
        url = input("Introduce una URL: ")
        diccionario = os.path.join(os.path.dirname(
            __file__), "assets", "xss-payload-list.txt")

        with open(diccionario) as file:
            payloads = file.read().splitlines()

        barrita = tqdm(total=len(payloads), desc="Progreso",
                       unit="urls", dynamic_ncols=True)
        isVuln = False
        for payload in payloads:
            # Crear la URL con el payload
            url_completa_test = url + payload
            response = requests.get(url_completa_test)

            # Verificar si la respuesta contiene el payload
            if payload in response.text:
                tqdm.write(f"Vulnerable a XSS con el payload: {payload}")
                isVuln = True

            barrita.update(1)

        if not isVuln:
            print(f"La url \"{url}\" no es vulnerable a XSS")

    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")

    finally:
        barrita.close()

    print("=" * 50)