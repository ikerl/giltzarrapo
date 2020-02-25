#!/usr/bin/python3
import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, epilog = '\n'.join(2*['{}']).format(
    'example : encrypt.py file.txt file.txt.enc',
    'example : encrypt.py -v -m /path/to/modules -k ~/.ssh/giltza_rsa.pub -b 400 -f off -a file.auth file.txt file.txt.enc'
))
parser.add_argument('infile', help = 'input file to encrypt')
parser.add_argument('outfile', help = 'encrypted output file')
parser.add_argument('-k', '--key', help = 'public key used in encryption\nif the key is not specified a new pair will be generated', metavar = 'pubkey', default = None)
parser.add_argument('-f', '--fast', help = 'enable/disable fast mode\ndefault on', metavar = 'on/off', choices = ['on', 'off'], default = 'on')
parser.add_argument('-b', '--block', help = 'symetric block to use in the encryption', metavar = 'selectedBlock', type = int, default = None)
parser.add_argument('-m', '--modules', help = 'absolute path to the modules folder\nuse this option if the script can not import the modules', metavar = 'modulesPath', default = None)
parser.add_argument('-a', '--auth', help = 'export auth file\nused to encrypt with fast mode off but export the info to enable fast decrypt', metavar='authfile', default = None)
parser.add_argument('-v', '--verbose', help = 'show encryption info and progress', action = 'store_true', default = False)
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
rpasswd = getpass('Repeat password: ')
if passwd != rpasswd:
    ecprint('Passwords do not match', color = 'red')
    sys.exit()

if args.key is None:
    #Generate new a new pair of keys
    default_path = '{}/giltza_rsa'.format(os.getcwd())
    keypath = input('Enter file in which to save the key ({}): '.format(default_path))
    if keypath == "" : keypath = default_path
    passphrase = getpass('Enter passphrase (empty for no passphrase): ')
    rpassphrase = getpass('Enter same passphrase again: ')

    if passphrase != rpassphrase:
        ecprint('Passphrases do not match', color = 'red')
        sys.exit()

    keyargs = {'dir' : '/'.join(keypath.split('/')[:-1]), 'name' : keypath.split('/')[-1]}
    #Generate new a new pair of keys
    privKey, pubKey = Giltzarrapo.generateRSApair(passphrase = passphrase, **{k : v for k,v in keyargs.items() if v is not ""})
    args.key = pubKey

    if args.verbose :
        ecprint(privKey, color = 'yellow', template = 'Your identification has been saved in {}')
        ecprint(pubKey, color = 'yellow', template = 'Your public key has been save in {}')

args.fast = True if (args.fast is 'on') else False

if not args.verbose:
    #Encrypt the file as one-liner
    Giltzarrapo().readPlain(args.infile).encrypt(passwd, args.key, selected_block = args.block, fast = args.fast).save(args.outfile, authfile = args.auth)
else:
    #Encrypt the file step by step
    ecprint('Starting encrypting module...', color = 'blue')

    #Read the file
    g = Giltzarrapo()
    ecprint([args.infile, os.path.getsize(args.infile)], color = 'yellow', template = 'Reading file : {} ({} Bytes)')
    g.readPlain(args.infile)
    ecprint(len(g.blocks), color = 'yellow', template = 'Blocks to encrypt: {}')

    #Select the symetric block (this step is automatically done in the encryption if the block is not provided)
    if args.block is None:
        ecprint('Selecting a high entropy block...', color = 'blue')
        args.block = g.selectBlock(tryLimit = 10)
        while not g.verifySymetricBlock(args.block, args.key): args.block = g.selectBlock(tryLimit = 10)
    else : ecprint('Preselected block for encryption', color = 'blue')
    ecprint([args.block, '{:.4f}'.format(Giltzarrapo.entropy(g.blocks[args.block]))], color = 'yellow', template = 'Selected block: {} (entropy of {})')

    #Encrypt the file
    ecprint('Encrypting file...', color = 'blue')
    ecprint([args.block, args.key, ''.join(['*' for _ in passwd])], color = 'yellow', template = 'Using : \n\tSymetric block: {}\n\tPublic key: {}\n\tPassword: {}')
    g.encrypt(passwd, args.key, selected_block = args.block, fast = args.fast)

    #Save the file
    ecprint('Saving file...', color = 'blue')
    g.save(args.outfile, authfile = args.auth)
    ecprint(args.outfile, color = 'blue', template = 'File saved at {}')
    if (args.auth is not None): ecprint(args.auth, color = 'blue', template = 'Authfile saved at {}')
