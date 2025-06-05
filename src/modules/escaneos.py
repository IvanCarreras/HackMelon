from colores import bcolors, colors
# Escaneo de Red
import sys
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf, get_working_ifaces, InterfaceProvider

# Escaneo de puertos
import nmap
import re
from datetime import timedelta

# Expresion regular para IP
patron_ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

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
