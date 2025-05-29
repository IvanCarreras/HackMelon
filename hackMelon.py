import os

# Escaneo de Red
import sys
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf, get_working_ifaces, InterfaceProvider

# Escaneo de puertos
import nmap
import re
from datetime import timedelta

# Fuzzing & XSS
import argparse
import requests
from tqdm import tqdm

# CVE Wiki
from bs4 import BeautifulSoup


# Colores de la terminal
class bcolors:
    HEADER = '\033[95m'
    OKRED = '\033[91m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class colors:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'


# Expresion regular para IP
patron_ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

try:
    # La r para que se pueda poner el "\ " si que de errores.
    print(bcolors.OKGREEN + "#"*100 + bcolors.ENDC)
    print(bcolors.OKRED + r" __    __                      __              __       __            __                      ")
    print(r"|  \  |  \                    |  \            |  \     /  \          |  \                     ")
    print(r"| $$  | $$  ______    _______ | $$   __       | $$\   /  $$  ______  | $$  ______   _______   ")
    print(r"| $$__| $$ |      \  /       \| $$  /  \      | $$$\ /  $$$ /      \ | $$ /      \ |       \  ")
    print(r"| $$    $$  \$$$$$$\|  $$$$$$$| $$_/  $$      | $$$$\  $$$$|  $$$$$$\| $$|  $$$$$$\| $$$$$$$\ ")
    print(r"| $$$$$$$$ /      $$| $$      | $$   $$       | $$\$$ $$ $$| $$    $$| $$| $$  | $$| $$  | $$ ")
    print(r"| $$  | $$|  $$$$$$$| $$_____ | $$$$$$\       | $$ \$$$| $$| $$$$$$$$| $$| $$__/ $$| $$  | $$ ")
    print(r"| $$  | $$ \$$    $$ \$$     \| $$  \$$\      | $$  \$ | $$ \$$     \| $$ \$$    $$| $$  | $$ ")
    print(rf" \$$   \$$  \$$$$$$$  \$$$$$$$ \$$   \$$       \$$      \$$  \$$$$$$$ \$$  \$$$$$$  \$$   \$$ {bcolors.ENDC}v1.0")
    print()
    print(bcolors.OKGREEN + "#"*100 + bcolors.ENDC)
except:
    print("Error en el logo ")


def escaneoRed():
    try:
        print('=' * 50)
        interfaces = get_working_ifaces()
        for iface in interfaces:
            if (iface.is_valid()):
                print(f"{colors.GREEN}Nombre:{bcolors.ENDC} {iface.name}")
                print(
                    f"{colors.WHITE}Identificador de Red:{bcolors.ENDC} {iface.network_name}")
                print(
                    f"{colors.WHITE}Descripcion:{bcolors.ENDC} {iface.description}")
                print(f"{colors.WHITE}IP:{bcolors.ENDC} {iface.ip}/{iface.type}")
                print(f"{colors.WHITE}MAC:{bcolors.ENDC} {iface.mac}")
                print("-" * 40)

        interfaz = input(
            f"{bcolors.OKBLUE}Introduce el identificador de red a escanear ->{bcolors.ENDC} ")

        print(f"[*] Escaneando {interfaz} ...")
        tiempo_ini = datetime.now()
        # Hace un escaneo de la red local principal
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),
                         timeout=2,
                         iface=interfaz,  # Red predeterminada.
                         inter=0.1,
                         verbose=False)
        print("\n[*] IP - MAC")
        # Muestra el resultado
        for snd, rcv in ans:
            print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
        tiempo_fin = datetime.now()
        tiempo_total = tiempo_fin - tiempo_ini
        print("\n[*] Escaneo Completado. Duracion:", tiempo_total)

        print('=' * 50)
    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")

# Necesario para el exe
def recurso_path(rel_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, rel_path)

def escaneoPuertos():

    try:
        
        scanner = nmap.PortScanner()
        options = ""
        scanmenu = int(input(f"Tipos de escaneos: \n 1. Escaneo completo estandar\n 2. Escaneo completo UDP"
                             f"\n 3. Escaneo completo sin ping\n 4. Escaneo critico\n{bcolors.OKBLUE}Eleccion -> {bcolors.ENDC}"))
        match scanmenu:
            case 1:
                options = "-p 1-1000 -T5 -A"
            case 2:
                options = "-sS -sU -T5 -A"
            case 3:
                options = "-v -Pn -T5 -A"
            case 4:
                options = "-sS -sU -T5 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)'"
            case _:
                print(bcolors.OKRED + "Valor incorrecto"+bcolors.ENDC)

        # Define un target IP o Hostname
        # nmap "50.116.1.184"
        # alvaro queso "192.168.11.11"
        while True:
            target = input(f"{bcolors.OKBLUE}Introduce una IP:{bcolors.ENDC} ")
            if patron_ip.search(target):
                print(f"La ip: {target} es valida")
                break

        # Define las opciones del escaneo
        # Hace un escaneo basico del target (el argumets no hacen del todo falta)
        # print(
        print("[*] Escaneando...")
        scanner.scan(target, arguments=options)
        # )

        # Output del escaneo
        for host in scanner.all_hosts():
            print('=' * 50)
            # Host info
            print(f"Host: {host} ({scanner[host].hostname() or 'Sin nombre'})")
            print(f"Estado: {scanner[host].state().upper()}")

            # Uptime
            uptime_data = scanner[host].get('uptime', {})
            last_boot = uptime_data.get('lastboot', 'N/A')
            uptime_seconds = int(uptime_data.get('seconds', 0))
            uptime_str = str(timedelta(seconds=uptime_seconds)
                             ) if uptime_seconds else "N/A"
            print(f"Tiempo encendido: {uptime_str} (desde {last_boot})")

            # Sistema operativo
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                os_name = scanner[host]['osmatch'][0]['name']
                os_accuracy = scanner[host]['osmatch'][0]['accuracy']
                print(f"Sistema operativo: {os_name} ({os_accuracy}%)")
            else:
                print("Sistema operativo: Desconocido")

            # Protocolos de red
            print("\nPuertos detectados:")
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                print("Protocolo: " + proto)
                for port in sorted(ports):
                    # Extracccion de la informacion
                    port_info = scanner[host][proto][port]
                    state = port_info.get('state')
                    service = port_info.get('name', 'desconocido')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    extrainfo = port_info.get('extrainfo', '')
                    # Solo puestra los puertos abiertos o filtrados
                    if state not in ['open', 'filtered']:
                        continue

                    # Una cadena de detalles
                    detalles = " ".join(
                        filter(None, [product, version, f"({extrainfo})" if extrainfo else ""])).strip()
                    # La salida esta si o si
                    salida = f"- {port}/{proto} ({service}) - state {state}"
                    if detalles:
                        salida += f" -> {detalles}"
                    print(salida)

            print("=" * 50)
    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")


def fuzzing():
    print("=" * 50)
    # Status Codes HTTP -> https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status

    # Datos para el fuzzing
    url_user = input(f"{bcolors.OKBLUE}Introduce la Url:\n{bcolors.ENDC}")
    diccionario = os.path.join(os.path.dirname(__file__),"assets","directory-list-2.3-medium.txt")

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
            print(f"{bcolors.OKCYAN}Mas información en:\n{bcolors.ENDC}", url_completa)

        else:
            print("No se ha encontrado: " + cve_user)
        print("=" * 50)
    except KeyboardInterrupt:
        print("\nScript interrumpido por el usuario al pulsar control + C")


def bruteForce():
    print("=" * 50)
    print("Brute Forze (en desarrollo)")
    print("=" * 50)
    main()

def SQLi_script():
    print("=" * 50)
    print("SQL injection (en desarrollo)")
    print("=" * 50)


def XSS_script():
    print("=" * 50)
    # https://xss-game.appspot.com/level1/frame?query=
    # "http://localhost/Web_pruebas/?name="

    try:
        url = input("Introduce una URL: ")
        diccionario = os.path.join(os.path.dirname(__file__),"assets","xss-payload-list.txt")

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


def LFI_script():
    print("=" * 50)
    print("LFI (en desarrollo)")
    print("=" * 50)


def main():
    # Donde empieza el main
    nuser = - 1
    while (nuser != 5):
        nuser = int(input(f" {bcolors.HEADER}Que quieres hacer:{bcolors.ENDC}\n" +
                          f" {bcolors.WARNING}[1]{bcolors.ENDC} Escaneo de Red\n" +
                          f" {bcolors.WARNING}[2]{bcolors.ENDC} Escaneo de puertos\n" +
                          f" {bcolors.WARNING}[3]{bcolors.ENDC} Fuzzing\n" +
                          f" {bcolors.WARNING}[4]{bcolors.ENDC} CVE Wiki\n" +
                          f" {bcolors.WARNING}[5]{bcolors.ENDC} Fuerza Bruta (en desarrollo)\n" +
                          f" {bcolors.WARNING}[6]{bcolors.ENDC} SQL Injection (SQLi) (en desarrollo)\n" +
                          f" {bcolors.WARNING}[7]{bcolors.ENDC} Cross-Site Scripting (XSS)\n" +
                          f" {bcolors.WARNING}[8]{bcolors.ENDC} Local File Inclusion (LFI) (en desarrollo)\n" +
                          f" {bcolors.WARNING}[9]{bcolors.ENDC} Salir\n" +
                          f" {bcolors.OKBLUE}Eleccion ->{bcolors.ENDC} "))

        match nuser:
            case 1:
                escaneoRed()
            case 2:
                escaneoPuertos()
            case 3:
                fuzzing()
            case 4:
                CVEWiki()
            case 5:
                bruteForce()
            case 6:
                SQLi_script()
            case 7:
                XSS_script()
            case 8:
                LFI_script()
            case 9:
                print("Adios")
                break
            case _:
                print("Valor incorrecto")
main()