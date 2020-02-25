#!/usr/bin/python3
import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, epilog = '\n'.join(3*['{}']).format(
    'example : decrypt.py file.txt.enc file.txt.dec ~/.ssh/giltza_rsa',
    'example : decrypt.py -v -p -b 700 -m /path/to/modules file.txt.enc file.txt.dec ~/.ssh/giltza_rsa',
    'example : decrypt.py -v -p -m /path/to/modules -a file.auth file.txt.enc file.txt.dec ~/.ssh/giltza_rsa'
))
parser.add_argument('infile', help = 'input file to encrypt')
parser.add_argument('outfile', help = 'encrypted output file')
parser.add_argument('privkey', help = 'private key to use in decryption')
parser.add_argument('-p', '--passphrase', help = 'ask for privkey passphrase', action = 'store_true', default = False)
parser.add_argument('-b', '--block', help = 'symetric block used in the encryption\nproviding the block allows fast decryption in encrypted files without fast mode', metavar = 'selectedBlock', type = int, default = None)
parser.add_argument('-m', '--modules', help = 'absolute path to the modules folder\nuse this option if the script can not import the modules', metavar = 'modulesPath', default = None)
parser.add_argument('-a', '--auth', help = 'exported auth file during the encryption\nallows fast decrypt when the encryption was made with fast mode off', metavar = 'authfile', default = None)
parser.add_argument('-v', '--verbose', help = 'show decryption info and progress', action = 'store_true', default = False)
args = parser.parse_args()

import os
import sys
from getpass import getpass
if args.modules is not None : sys.path.insert(0, args.modules)
try:
    from giltzarrapo import Giltzarrapo
    from printer import ecprint
except : sys.exit('Can not import required modules. Try using -m option')

passwd = getpass('Password: ')
passphrase = getpass('Passphrase: ') if args.passphrase else ""


if not args.verbose:
    #Decrypt the file as one-liner
    Giltzarrapo().readEncrypted(args.infile, authfile = args.auth).decrypt(passwd, args.privkey, passphrase, selected_block = args.block).save(args.outfile)
else:
    #Encrypt the file step by step
    ecprint('Starting decrypting module...', color = 'blue')

    #Read the file
    g = Giltzarrapo()
    ecprint([args.infile, os.path.getsize(args.infile)], color = 'yellow', template = 'Reading file : {} ({} Bytes)')
    if args.auth is not None : ecprint(args.auth, color = 'yellow', template = 'Using auth file : {}')
    g.readEncrypted(args.infile, authfile = args.auth)
    ecprint(len(g.blocks), color = 'yellow', template = 'Blocks to decrypt: {}')

    #Find the symetric block (this step is automatically done in the decryption if the block is not provided)
    if args.block is None:
        ecprint('Finding the symetric block...', color = 'blue')
        args.block = g.findBlock(passwd, args.privkey, passphrase)
        ecprint(args.block, color = 'yellow', template = 'Symetric block found: {}')
    else : ecprint(args.block, color = 'yellow', template = 'Preselected symetric block: {}')

    #Decrypt the file
    ecprint('Decrypting file...', color = 'blue')
    ecprint([args.block, args.privkey, ''.join(['*' for _ in passwd])], color = 'yellow', template = 'Using : \n\tSymetric block: {}\n\tPrivate key: {}\n\tPassword: {}')
    g.decrypt(passwd, args.privkey, passphrase, selected_block = args.block)

    #Save the file
    ecprint('Saving file...', color = 'blue')
    g.save(args.outfile)
    ecprint(args.outfile, color = 'blue', template = 'File saved at {}')
