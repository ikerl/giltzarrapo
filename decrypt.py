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

def parse(argv):
    global inputfile
    global outputfile
    global keyfile
    try:
        opts, args = getopt.getopt(argv,"hi:o:k:",["ifile=","ofile=","key="])
    except getopt.GetoptError:
        print('{} -i <inputfile> -o <outputfile> [-k <RSAprivKey>]'.format(__file__))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('{} -i <inputfile> -o <outputfile> [-k <RSAprivKey>]'.format(__file__))
            sys.exit()
        elif opt == '-i':
            inputfile = arg
        elif opt == '-o':
            outputfile = arg
        elif opt == '-k':
            keyfile = arg

    if inputfile == "" or outputfile == "" or keyfile == "":
        print('{} -i <inputfile> -o <outputfile> -k <RSAprivKey>'.format(__file__))
        sys.exit()

### MAIN

if __name__ == "__main__":

    parse(sys.argv[1:])

    print("[+] Importando clave privada RSA")
    try:
        key = RSA.importKey(open(keyfile, "rb").read())
    except:
        print("[-] Clave RSA no encontrada o invalida")
        sys.exit(-1)

    print("[+] Clave publica RSA obtenida con exito")

    try:
        cripto_file = open(inputfile, "rb")
        file_size = os.path.getsize(inputfile)
    except:
        print("[-] El fichero {} no se ha podido abrir".format(inputfile))
        sys.exit(-1)

    try:
        plainfile = open(outputfile, "wb")
    except:
        print("[-] El fichero {} no se ha podido abrir".format(outputfile))
        sys.exit(-1)

    print("[+] El archivo tiene {} bytes -> {} bloques que descifrar".format(file_size,file_size/CHUNKSIZE))

    try:
        bytes_read = cripto_file.read(CHUNKSIZE)
        blocks[n_bloques] = bytes_read
        n_bloques += 1
        while bytes_read:      
            bytes_read = cripto_file.read(CHUNKSIZE)
            blocks[n_bloques] = bytes_read
            n_bloques += 1
    finally:
        cripto_file.close()

    print("[+] Extrayendo datos del challenge")
    hash_sha_sha = blocks[n_bloques-2][-20:]
    size = int.from_bytes(blocks[n_bloques-2][-23:-21], byteorder='little')
    blocks[n_bloques-2] = blocks[n_bloques-2][0:-23]
    print("[+] Este fichero contiene {} bytes en el ultimo bloque".format(size))
    print("[+] Desafio a resolver: {}".format(hash_sha_sha))

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

    if selected != -1:
        print("[+] Descifrando fichero.. con el bloque seleccionado")
        for i in range(0,n_bloques-1):
            if i == selected:
                blocks[i] = key.decrypt(bytes(blocks[selected]))
                plainfile.write(blocks[i])
            else:
                if i == n_bloques-3:
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