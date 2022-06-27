#!/usr/bin/env python

"""compliance.py: API for NACD compliance checks."""

__author__      = "Yonariel Hernandez & Luis Cofresi"

from fastapi import FastAPI, BackgroundTasks
from av_check import av_check
from fw_check import fw_check
import computer_identity
import user_identity
import datetime

# Se crea API
app = FastAPI()

# Se declaran los tiempos de vencimiento de los token
timeout_compliance = datetime.timedelta(0, 60, 0)
timeout_not_compliance = datetime.timedelta(0, 10, 0)


# Se crea funcion que sumariza todos los checks de los dispositivos y guarda su estado en el archivo.
def host_check(args_list):
    # Extrayendo valores de la lista de argumentos
    host = args_list[0]
    user = args_list[1]
    passwd = args_list[2]
    timeout_comp = args_list[3]
    timeout_not_comp = args_list[4]
    # Se ejecutan las funciones que llaman los scripts de PowerShell
    av_state = av_check(host, user, passwd)
    fw_state = fw_check(host, user, passwd)
    computer_existence = computer_identity.computer_verification(host, user, passwd)
    user_existence = user_identity.user_identity(host, user, passwd)

    # Condicional para que un equipo se considere en cumplimiento.
    # Antivirus y Firewall activados y actualizados, no se toma en cuenta la marca del producto.
    # Se agrega token al archivo de estados.
    if av_state[0] == 1 and av_state[1] and fw_state[0] == 1 and fw_state[1]:
        print("")
        f = open("tokens", "a")
        d = datetime.datetime.now()
        d_expired = d + timeout_comp
        f.write("\nCompliant" + "," + host + "," + str(d) + "," + str(d_expired))
        f.close()
        print("El equipo %s ha pasado las verificaciones, instalando token \n" % host)

    # En caso de que no cumpla con las condiciones se considera al equipo no cumplidor.
    # Se agrega token "NoCompliant" al archivo de estado
    else:
        print("")
        f = open("tokens", "a")
        d = datetime.datetime.now()
        d_expired = d + timeout_not_comp
        f.write("\nNotCompliant" + "," + host + "," + str(d) + "," + str(d_expired))
        f.close()
        print("El equipo %s ha fallado las verificaciones \n" % host)

    # Se retornan los valores de interes.
    return av_state, fw_state, d, d_expired


#API Y BUSQUEDA EN EL ARCHIVO DE TOKENS

@app.get("/compliance")
# Se crea funcion que sera ejecutada por la API
async def compliance_check(host: str, user: str, passwd: str, background_task: BackgroundTasks):
    # Se crea lista de argumentos para ser enviada a los procesos en Background
    args = (host, user, passwd, timeout_compliance, timeout_not_compliance)
    # Se abre el archivo que aloja los tokens
    f = open("tokens", "r")
    # Se lee y almacena
    lines_list = f.readlines()
    f.close()
    print("")

    # Para cada linea en el archivo empezando desde el final
    for line in range((len(lines_list) - 1), 0, -1):
        # Se separa cada valor dentro de una lista.
        line_parsed = lines_list[line].split(",")
        # Se eliminan caracteres innecesarios
        line_parsed[2] = line_parsed[2].replace("\n", "")
        line_parsed[3] = line_parsed[3].replace("\n", "")
        # Se convierte la fecha de STR a DATE
        line_date_exp = datetime.datetime.strptime(line_parsed[3], "%Y-%m-%d %H:%M:%S.%f")

        # Si se cuentra la IP del Host
        if host == line_parsed[1]:
            # Verificamos si el equipo esta en cumplimiento para este token y si el token no esta vencido
            if line_parsed[0] == "Compliant" and line_date_exp > datetime.datetime.now():
                print("Verificacion de estado: El host %s tiene un token de cumplimiento vigente hasta fecha %s" %
                      (host, str(line_date_exp)))
                print("")
                # En caso de que si se retorna 1, el controlador lo interpreta como permitir el acceso
                return 1
            # Si el equipo no esta en cumplimiento para ese token y si el token aun no esta vencido
            elif line_parsed[0] == "NotCompliant" and line_date_exp > datetime.datetime.now():
                print("Verificacion de estado: El host %s tiene un token de NO cumplimiento vigente hasta la fecha %s"
                      % (host, str(line_date_exp)))
                print("")
                # Se retorna 2, el controlador lo interpreta como denegar el acceso.
                return 2
            # El caso contrario significa que el token se ha vencido, se procede a verificar el equipo
            else:
                print("Verificacion de estado: El token mas reciente de %s ha expirado, iniciando verificaciones de"
                      " cumplimiento" % host)
                print("")
                # Se llama a la tarea de verificacion en background
                background_task.add_task(host_check, args)
                # Se retorna inmediatamente al controlador para evitar tiempos muertos en la red
                return 3
        # Si no se cuentra la IP del host en la lista, se procede a realizar la verificacion.
        else:
            print("Verificacion de estado: El host %s no tiene ningun token, iniciando verificaciones de"
                  "cumplimiento" % host)
            print("")
            # Se llama a la tarea de verificacion en background
            background_task.add_task(host_check, args)
            # Se retorna inmediatamente al controlador para evitar tiempos muertos en la red
            return 3
