#!/usr/bin/python3

import os
import random
import math
import getopt
import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

CHUNKSIZE = 256
n_bloques = 0
blocks = {}
inputfile = ''
outputfile = ''
keyfile = ''
password = None
selected = None

def parse(argv):
    global inputfile
    global outputfile
    global keyfile
    global password
    global selected

    try:
        opts, args = getopt.getopt(argv,"hi:o:k:p:b:",["ifile=","ofile=","key=","pass=","bloque="])
    except getopt.GetoptError:
        print('{} -i <inputfile> -o <outputfile> [-k <RSAprivKey>] [-p <Password>] [-b <nBloque>]'.format(__file__))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('{} -i <inputfile> -o <outputfile> [-k <RSAprivKey>] [-p <Password>] [-b <nBloque>]'.format(__file__))
            sys.exit()
        elif opt == '-i':
            inputfile = arg
        elif opt == '-o':
            outputfile = arg
        elif opt == '-k':
            keyfile = arg
        elif opt == '-p':
            password = arg
        elif opt == '-b':
            selected = int(arg)

    if inputfile == "" or outputfile == "" or keyfile == "":
        print('{} -i <inputfile> -o <outputfile> -k <RSAprivKey> [-p <Password>] [-b <nBloque>]'.format(__file__))
        sys.exit()

### MAIN

if __name__ == "__main__":

    parse(sys.argv[1:])

    print("[+] Importando clave privada RSA")
    try:
        key = RSA.importKey(open(keyfile, "rb").read(),passphrase=password)
    except FileNotFoundError:
        print("[-] El fichero {} no existe".format(keyfile))
        sys.exit(-1)
    except:
        print("[-] Clave RSA invalida")
        sys.exit(-1)

    print("[+] Clave publica RSA obtenida con exito")

    try:
        cripto_file = open(inputfile, "rb")
        file_size = os.path.getsize(inputfile)
    except FileNotFoundError:
        print("[-] El fichero {} no existe".format(inputfile))
        sys.exit(-1)
    except:
        print("[-] El fichero {} no se ha podido abrir".format(inputfile))
        sys.exit(-1)

    try:
        plainfile = open(outputfile, "wb")
    except FileNotFoundError:
        print("[-] El fichero {} no existe".format(outputfile))
        sys.exit(-1)
    except:
        print("[-] El fichero {} no se ha podido abrir".format(outputfile))
        sys.exit(-1)

    print("[+] El archivo tiene {} bytes -> {} bloques que descifrar".format(file_size,file_size/CHUNKSIZE))

    try:
        n_bloques = 0
        bytes_read = cripto_file.read(CHUNKSIZE)
        while bytes_read: 
            blocks[n_bloques] = bytes_read     
            n_bloques += 1
            bytes_read = cripto_file.read(CHUNKSIZE)          
    finally:
        cripto_file.close()

    print("[+] Extrayendo datos del challenge")
    hash_sha_sha = blocks[n_bloques-1][-20:]
    size = int.from_bytes(blocks[n_bloques-1][-23:-21], byteorder='little')
    blocks[n_bloques-1] = blocks[n_bloques-1][0:-23]
    print("[+] Este fichero contiene {} bytes en el ultimo bloque".format(size))
    print("[+] Desafio a resolver: {}".format(hash_sha_sha))

    if selected == None:
        selected = -1
        for n in range(0,n_bloques-1):
            try:
                clave = SHA256.new(key.decrypt(bytes(blocks[n]))).digest()
                encryptor = AES.new(clave)
                firma = SHA.new(clave).digest()
                if (firma == hash_sha_sha):
                    print("[+] El bloque de la simetrica es la {}".format(n))
                    selected = n
                    break
            except:
                pass    
    else:
        if selected < n_bloques and selected >= 0:
            clave = SHA256.new(key.decrypt(bytes(blocks[selected]))).digest()
            encryptor = AES.new(clave)
            firma = SHA.new(clave).digest()
            if (firma == hash_sha_sha):
                print("[+] Simetrica encontrada con exito en el bloque {}".format(selected))
            else:
                print("[-] El bloque {} indicado no tiene una simetrica valida".format(selected))
                sys.exit(-1)
        else:
            print("[-] El bloque indicado no es valido")
            sys.exit(-1)

    if selected != -1:
        print("[+] Descifrando fichero.. con el bloque seleccionado")
        for i in range(0,len(blocks)-1):
            if i == selected:
                if i == len(blocks)-2:
                    blocks[i] = key.decrypt(bytes(blocks[selected]))
                    plainfile.write(blocks[i][:CHUNKSIZE-size])
                    print("[+] Se ha quitado el padding de {} bytes del ultimo bloque {}".format(CHUNKSIZE-size,i))
                else:
                    blocks[i] = key.decrypt(bytes(blocks[selected]))
                    plainfile.write(blocks[i])
            else:
                if i == len(blocks)-2:
                    blocks[i] = encryptor.decrypt(blocks[i])
                    plainfile.write(blocks[i][:CHUNKSIZE-size])
                    print("[+] Se ha quitado el padding de {} bytes del ultimo bloque {}".format(CHUNKSIZE-size,i))
                else:
                    blocks[i] = encryptor.decrypt(blocks[i])
                    plainfile.write(blocks[i])
            #print(blocks[i])
    else:
        print("[-] No se ha encontrado ninguna clave simetrica en el fichero")
        sys.exit(-1)

    print("[+] Fichero descifrado con exito")