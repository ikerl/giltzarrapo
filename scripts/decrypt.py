#!/usr/bin/python3
import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, epilog = '\n'.join(6*['{}']).format(
    'example : decrypt.py -k ~/.ssh/giltza_rsa file.txt.enc file.txt.dec',
    'example : decrypt.py -v -k ~/.ssh/giltza_rsa file.txt.enc file.txt.dec',
    'example : decrypt.py -v -k ~/.ssh/giltza_rsa -p file.txt.enc file.txt.dec',
    'example : decrypt.py -v -k ~/.ssh/giltza_rsa -b 400 file.txt.enc file.txt.dec',
    'example : decrypt.py -v -k ~/.ssh/giltza_rsa -m /path/to/modules file.txt.enc file.txt.dec',
    'example : decrypt.py -v -k ~/.ssh/giltza_rsa -p -b 400 -m /path/to/modules file.txt.enc file.txt.dec'
))
parser.add_argument('infile', help = 'input file to encrypt')
parser.add_argument('outfile', help = 'encrypted output file')
parser.add_argument('-k', '--key', help = 'private key to use in decryption', required = True, metavar = 'privkey')
parser.add_argument('-p', '--passphrase', help = 'ask for privkey passphrase', action = 'store_true', default = False)
parser.add_argument('-b', '--block', help = 'symetric block used in the encryption', metavar = 'sb', type = int, default = None)
parser.add_argument('-m', '--modules', help = 'absolute path to the modules folder\nUse this option if the script can not import the modules', metavar = 'path', default = None)
parser.add_argument('-v', '--verbose', help = 'show decryption info and progress', action = 'store_true', default = False)
args = parser.parse_args()

import os
import sys
from getpass import getpass
if args.modules is not None : sys.path.insert(0, args.modules)
try:
    from giltzarrapo import Giltzarrapo
    from easycolor import ecprint
except : sys.exit('Can not import required modules. Try using -m option')

passwd = getpass('Password: ')
passphrase = getpass('Passphrase: ') if args.passphrase else ""


if not args.verbose:
    #Decrypt the file as one-liner
    Giltzarrapo().readEncrypted(args.infile).decrypt(passwd, args.key, passphrase, selected_block = args.block).save(args.outfile)
else:
    #Encrypt the file step by step
    ecprint('Starting decrypting module...', c = 'blue')

    #Read the file
    g = Giltzarrapo()
    ecprint([args.infile, os.path.getsize(args.infile)], c = 'yellow', template = 'Reading file : {} ({} Bytes)')
    g.readEncrypted(args.infile)
    ecprint(len(g.blocks), c = 'yellow', template = 'Blocks to decrypt: {}')

    #Find the symetric block (this step is automatically done in the decryption if the block is not provided)
    if args.block is None:
        ecprint('Finding the symetric block...', c = 'blue')
        args.block = g.findBlock(passwd, args.key, passphrase)
        ecprint(args.block, c = 'yellow', template = 'Symetric block found: {}')
    else : ecprint(args.block, c = 'yellow', template = 'Preselected symetric block: {}')

    #Decrypt the file
    ecprint('Decrypting file...', c = 'blue')
    ecprint([args.block, args.key, ''.join(['*' for _ in passwd])], c = 'yellow', template = 'Using : \n\tSymetric block: {}\n\tPrivate key: {}\n\tPassword: {}')
    g.decrypt(passwd, args.key, passphrase, selected_block = args.block)

    #Save the file
    ecprint('Saving file...', c = 'blue')
    g.save(args.outfile)
    ecprint(args.outfile, c = 'blue', template = 'File saved at {}')
