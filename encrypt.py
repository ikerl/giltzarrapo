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
inputfile = ''
outputfile = ''
keyfile = ''
password = None
selected_block = None

def parse(argv):
    global inputfile
    global outputfile
    global keyfile
    global password
    global selected_block

    try:
        opts, args = getopt.getopt(argv,"hi:o:k:p:b:",["ifile=","ofile=","key=","pass=","bloque="])
    except getopt.GetoptError:
        print('{} -i <inputfile> -o <outputfile> [-k <RSApubKey>] [-p <Password>] [-b <nBloque>]'.format(__file__))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('{} -i <inputfile> -o <outputfile> [-k <RSApubKey>] [-p <Password>] [-b <nBloque>]'.format(__file__))
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
            selected_block = int(arg)

    if inputfile == "" or outputfile == "":
        print('{} -i <inputfile> -o <outputfile> [-k <RSApubKey>] [-p <Password>] [-b <nBloque>]'.format(__file__))
        sys.exit()
            


def entropy(string):
        "Calculates the Shannon entropy of a string"

        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy




### MAIN

if __name__ == "__main__":

    parse(sys.argv[1:])

    if keyfile == "":
        print("[+] Generando clave RSA")
        key = RSA.generate(2048, Random.new().read)
        privatekey = key.exportKey(pkcs=8,passphrase=password)
        publickey = key.publickey().exportKey()
        PUBkey = key.publickey()

        rsa_file_pub = open("pub_crypto.key", "wb")
        rsa_file_priv = open("priv_crypto.key", "wb")
        rsa_file_pub.write(key.publickey().exportKey("PEM"))
        rsa_file_priv.write(key.exportKey("PEM",passphrase=password))
        rsa_file_pub.close()
        rsa_file_priv.close()
    else:
        print("[+] Importando clave RSA")
        try:
            PUBkey = RSA.importKey(open(keyfile, "rb").read())
        except:
            print("[-] Clave RSA no encontrada o invalida")
            sys.exit(-1)

    print("[+] Clave publica RSA obtenida con exito")

    try:
        file = open(inputfile, "rb")
        file_size = os.path.getsize(inputfile)
    except:
        print("[-] El fichero {} no se ha podido abrir".format(inputfile))
        sys.exit(-1)

    try:
        cripto_file = open(outputfile, "wb")
    except:
        print("[-] El fichero {} no se ha podido abrir".format(outputfile))
        sys.exit(-1)
    
    blocks = {}


    print("[+] El archivo tiene {} bytes -> {} bloques que cifrar".format(file_size,file_size/CHUNKSIZE))
    try:
        bytes_read = file.read(CHUNKSIZE)
        blocks[n_bloques] = bytes_read
        while bytes_read:
            n_bloques += 1
            bytes_read = file.read(CHUNKSIZE)
            blocks[n_bloques] = bytes_read
    finally:
        file.close()

    print("[+] Se han detectado {} bloques".format(n_bloques))

    if selected_block == None:
        selected_block = random.randint(0, n_bloques-2)
        entropia = entropy(blocks[selected_block].hex())
        while entropia < 2:
            print("[-] Se ha seleccionado el bloque {} pero tiene una entropia muy baja de {}".format(selected_block,entropia))
            selected_block = random.randint(0, n_bloques-2)
            entropia = entropy(blocks[selected_block].hex())
    else:
        if selected_block < n_bloques and selected_block >= 0:
            entropia = entropy(blocks[selected_block].hex())
        else:
            print("[-] El bloque indicado no es valido")
            sys.exit(-2)

    print("[+] Se ha seleccionado el bloque {} como clave simetrica con entropia de {}".format(selected_block,entropia))

    print("[+] Cifrando fichero.. con el bloque seleccionado")
    hash_sha = SHA256.new(blocks[selected_block]).digest()
    hash_sha_sha = SHA.new(hash_sha).digest()
    encryptor = AES.new(hash_sha, AES.MODE_ECB, "")

    for n in range(0,n_bloques):
        if n == selected_block:
            blocks[n] = PUBkey.encrypt(bytes(blocks[n]),32)[0]
            cripto_file.write(blocks[n])
            print("[+] El bloque {} se ha cifrado con la publica".format(n))
        else:
            block_size = len(blocks[n])
            blocks[n] = encryptor.encrypt(bytes(blocks[n]) + (CHUNKSIZE - block_size)*b"\x00")
            cripto_file.write(blocks[n])

    cripto_file.write(int(CHUNKSIZE - block_size).to_bytes(2, 'little'))
    cripto_file.write(hash_sha_sha)
    cripto_file.close()

    print("[+] Desafio a resolver: {}".format(hash_sha_sha))
    print("[+] Fichero cifrado con exito.\n")
   