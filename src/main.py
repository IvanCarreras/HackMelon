import os
from modules.escaneos import escaneoRed, escaneoPuertos
from modules.fuzzing import fuzzing
from modules.cveWiki import CVEWiki
from modules.xss import XSS_script
from modules.SQLi import SQLi_script

from colores import bcolors, colors


def banner():
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
        print(
            rf" \$$   \$$  \$$$$$$$  \$$$$$$$ \$$   \$$       \$$      \$$  \$$$$$$$ \$$  \$$$$$$  \$$   \$$ {bcolors.ENDC}v1.1")
        print()
        print(bcolors.OKGREEN + "#"*100 + bcolors.ENDC)
    except:
        print("Error en el logo ")


def bruteForce():
    print("=" * 50)
    print("Brute Forze (en desarrollo)")
    print("=" * 50)
    main()



def LFI_script():
    print("=" * 50)
    print("LFI (en desarrollo)")
    print("=" * 50)
    main()



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


if __name__ == "__main__":
    banner()
    main()
