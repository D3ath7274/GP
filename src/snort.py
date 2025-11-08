from flask import Flask, request, jsonify, redirect, url_for
import sys
sys.path.insert(0, './classes')
sys.path.insert(0,'./interpreter')
sys.path.insert(0,'./parallel')
from system import *
from iptables import *
from interpreterMain import *
from ruleCleaner import *
from functools import wraps
import sqlite3
import os
import time

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False


#@app.route('/')
#def hello_world():
#    return redirect(url_for('apiStandartHandler'))

# -------------- Authentication function decorators ------------ #

def requestAuth(func):
    @wraps(func)
    def funcWrapper():
        data = request.get_json(force=True)
        apiAddr = request.remote_addr
        apiKey = data["API Register Key"]

        conn = sqlite3.connect("database/apiConfiguration.db")
        cursor = conn.cursor()
        cursor.execute('select registerkey from RegisterInfo ;'.format(apiAddr))
        result = cursor.fetchall()
        if result[0][0] != apiKey:
            return jsonify({"Reponse":"ERROR - Authentication with the SystemAPI failed","Status":"400"}),400
        elif result[0][0] == apiKey:
            return func()
    return funcWrapper

def requestFormat(requestSituation):
    def decorator(func):
        @wraps(func)
        def funcWrapper(*args,**kwargs):
            data = request.get_json(force=True)
            dataKeys = data.keys()

            allNecessary = []
            trustNecessaryFields = ["API Description", "API Port", "API Register Key"]
            untrustNecessaryFields = ["API Description", "Controller Key","API Register Key"]
            generalNecessaryFields = ["API Register Key"]
            iptablesNecessaryFields = ["API Register Key","Table","Action","Chain","Rule"]
            snortNecessaryFields = ["API Register Key","Action","Rule"]
            allNecessary.extend((generalNecessaryFields,untrustNecessaryFields,trustNecessaryFields,iptablesNecessaryFields, snortNecessaryFields))

            knownRequestSituation = ["general","untrust","trust","iptables","snort"]
            for known in knownRequestSituation:
                if known == requestSituation:
                    knownIndex = knownRequestSituation.index(known)
                    necessaryFields = allNecessary[knownIndex]

                    if len(dataKeys) != len(necessaryFields):
                        return jsonify({"Response":"ERROR - Not all the necessary fields for the specific situation transaction were passed.","Status":"400"}),400
                    else:
                        for key in dataKeys:
                            if not key in necessaryFields:
                                return jsonify({"Response":"ERROR - Incorrect request format for the specific situation","Status":"400"}),400
                            else:
                                continue
                    break
            return func()
        return funcWrapper
    return decorator

#-------------------- Rotas para API sobre métricas de sistema --------------------#

# Caminho da API onde o Controller coletainformações acerca da utiliadade de disco na unidade que deseja
#
# disk_name = Nome do disco que deseja ser análisado, exemplo: /dev/sda1 seria +dev+sda1. Caso queira listar
# de todos os discos/partições presentes no sistema us disk_name = all. OBS: Para que a API funcione corretamente
# o disco deve estar montado no sistema de arquivos.
#
# Tal caminho retorna um JSON contendo como Response um array de dicts, cada array carrega informações sobre um
# disco específico no sistema
@app.route('/api/system/disk/<disk_name>/<byte_unity>')
#@requestFormat("general")
#@requestAuth
def apiDisk(disk_name,byte_unity):
    disk_name = disk_name.replace("+","/")
    instanceDisk = System("DISK")
    if disk_name == "all":
        responseDisk = instanceDisk.disk(disk_name,byte_unity)
        return jsonify({"Response":responseDisk,"Status":"Success"})

    elif disk_name is not "all":
        diskExists = os.popen(r"df -h | grep -P '{0} ' 1> /dev/null 2> /dev/null 2> /dev/null; echo $?".format(disk_name)).read()
        diskExists = diskExists.strip("\n")
        if diskExists == "0":
            responseDisk = instanceDisk.disk(disk_name,byte_unity)

            return jsonify({"Response":responseDisk,"Status":"Success"})
        else:
            return jsonify({"Response": "Disco não existe ou não está montado no sistema.","Status":"Error"})


# -------------------------------------------------------------------------------------------------------------------------
# Caminho da API onde o Controller coleta as informações sobre o percentual utilizado de todos os cores existentes na CPU.
#
# Tal caminho retorna um JSON cotendo como Response um dicionário ondes as chaves representam os núcleos da CPU
@app.route('/api/system/cpu')
#@requestFormat("general")
#@requestAuth
def apiCPU():
    instance = System("CPU")
    responseCPU = instance.cpu()
    return jsonify({"Response": responseCPU,"Status":"Success"})

# -------------------------------------------------------------------------------------------------------------------
# Caminho da API onde o Controller coleta as informações sobre a utilização de memória com as mais diversas métricas
#
# Tal caminho retorna um JSON contendo como Response um dicionário onde as chaves contém métricas acerca da utilização
# de memória no sistema
@app.route('/api/system/mem')
#@requestFormat("general")
#@requestAuth
def apiMem():
    instance = System("MEM")
    responseMem = instance.mem()
    return jsonify({"Response": responseMem,"Status":"Success"})


# ----------------------------------------------------------------------------------------------------------------------
# Caminho da API onde o Controller coleta informações sobre as portas abertas no sistema e a quais serviços tais portas
# estão associadas.
#
# protocol = Protocolo que as portas abertas estarão utilizando. - Valores: tcp , udp e all. Se quiser listar tanto as
# portas TCP quando as UDP utilize protocol = all.
#
# Tal caminho retorna um JSON contendo como Response um dicionário cujas chaves representam o protocolo, os valores dessa
# chave são um array de dicionários contendo informações sobre os programas e suas portas.
@app.route('/api/system/port/<protocol>')
#@requestFormat("general")
#@requestAuth
def apiPort(protocol):
    if not protocol in ["all","tcp","udp"]:
        return jsonify({"Response":"Protocolo inválido."})
    else:
        instance = System("PORT")
        responsePort = instance.ports(protocol)
        return jsonify({"Response": responsePort,"Status":"Success"})


#-------------------- Rotas para API sobre configuração da iptables --------------------#


@app.route('/api/iptables',methods=['POST'])
#@requestFormat("iptables")
#@requestAuth
def apiIptablesCreate():
    data = request.get_json(force=True)
    address = request.remote_addr
    firewallInstace = iptables(data["Table"],data["Action"],data["Chain"],data["Rule"],address)
    response = firewallInstace.execute()

    return jsonify(response)

# Executa um arquivo a partir do seu caminho absoluto
def execfile(filepath, globals=None, locals=None):
    if globals is None:
        globals = {}
    globals.update({
        "__file__": filepath,
        "__name__": "__main__",
    })
    with open(filepath, 'rb') as file:
        exec(compile(file.read(), filepath, 'exec'), globals, locals)

# execute the file
#execfile("/path/to/somefile.py")



if __name__ == "__main__":
    try:
        if sys.argv[1] == "run":
            forkPid = os.fork()
            if forkPid == 0:
                time.sleep(1)
                # Initializes the rule cleaner daemon
                execfile("parallel/ruleCleaner.py")
                os._exit(0)
            else:
                try:
                    print("INFO - Initializing SystemAPI ... ")
                    conn = sqlite3.connect('database/apiConfiguration.db')
                    cursor = conn.cursor()

                    cursor.execute('select * from APIConfig where id=1;')
                    result = cursor.fetchall()

                    host = str(result[0][1])
                    port = int(result[0][2])

                    conn.close()
                except sqlite3.OperationalError as err:
                    print("ERROR - An error has occurred when accessing the database: {0}".format(err))

                try:
                    app.run(debug=True, host=host, port=port, use_reloader=True)
                    os._exit(0)
                except OSError as err:
                    print("ERROR - An error has occured when initializing the SystemAPI: {0}".format(err))
                except KeyboardInterrupt as err:
                    print("INFO - Finishing...")

        elif sys.argv[1] == "config":
            interpreterMainLoop()

        #else:
        #    print("ERROR - Invalid command line option passed: {0}".format(sys.argv[1]))

    except IndexError as err:
        print("ERROR - No command line option given: {0}".format(err))