# INF360 - Programming in Python
# Mason Templeton
# Final Project

# A custom-made RSA encryption program made in Python using the third-party PyCryptodome package.

#! python3

import sys
import math
import random
import logging

# pip install --user pycryptodome
from Crypto.Util import number

logging.basicConfig(filename='MasonTempletonFinalProjectLog.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.debug('Start of program')
#logging.disable(logging.CRITICAL)

class RSA:
    def generateKey(self):
        logging.debug('generateKey begin')
        k = 1024 # modulus bit length
        
        # choose public exponent e, 1 < e < phi, such that gcd(e,phi) = 1
        e = 65537
        
        p = number.getPrime(math.isqrt(k)) # get odd prime number of bit length sqrt(k)
        q = number.getPrime(math.isqrt(k)) # get odd prime number of bit length sqrt(k)
        
        # compute modulus n = p*q
        n = p * q
        
        # compute euler totient phi(n) = (p - 1)*(q - 1)
        phi = (p-1)*(q-1)
        
        # compute secret exponent d, 1 < d < phi, such that ed ≡ 1 mod phi
        # to compute d, use modular inversion
        d = number.inverse(e, phi)
        
        self.publicKey = (n,e)
        self.privateKey = (n,d)
        
        logging.debug('k: %s' % (k))
        logging.debug('e: %s' % (e))
        logging.debug('p: %s' % (p))
        logging.debug('q: %s' % (q))
        logging.debug('n: %s' % (n))
        logging.debug('phi: %s' % (phi))
        logging.debug('d: %s' % (d))
        logging.debug('generateKey end')
    
    def __init__(self):
        self.generateKey()
    

class Sender:
    def encrypt(self, recipientPublicKey, m):
        logging.debug('encrypt begin')
        r_n, r_e = recipientPublicKey
        
        # represent the plaintext (message digest m) as a positive integer m with 1 < m < n
        self.m = m
        
        if (m < 1 or m > r_n):
            logging.warning('m must be between 1 and n')
        
        # compute the ciphertext c = (m^e) mod n
        c = pow(m,r_e,r_n)
        
        logging.debug('r_n: %s' % (r_n))
        logging.debug('r_e: %s' % (r_e))
        logging.debug('m: %s' % (m))
        logging.debug('c: %s' % (c))
        logging.debug('encrypt end')
        
        # send the ciphertext c to recipient
        return c
    
    def digitalSign(self):
        logging.debug('digitalSign begin')
        n, d = self.privateKey
        
        # message digest m
        m = self.m
        
        # compute the signature s = (m^d) mod n
        s = pow(m,d,n)
        
        logging.debug('n: %s' % (n))
        logging.debug('d: %s' % (d))
        logging.debug('m: %s' % (m))
        logging.debug('s: %s' % (s))
        logging.debug('digitalSign end')
        
        # send signature s to the recipient
        return s
    
    def __init__(self, publicKey, privateKey):
        self.publicKey = publicKey
        self.privateKey = privateKey
        logging.debug('Sender initialized w/ publicKey=(n=%s,e=%s) privateKey=(n=%s,d=%s)' % (publicKey[0], publicKey[1], privateKey[0], privateKey[1]))
    

class Recipient:
    def decrypt(self, c):
        logging.debug('decrypt start')
        n, d = self.privateKey
        
        # compute m = (c^d) mod n
        m = pow(c,d,n)
        self.m = m
        
        logging.debug('n: %s' % (n))
        logging.debug('d: %s' % (d))
        logging.debug('c: %s' % (c))
        logging.debug('m: %s' % (m))
        logging.debug('decrypt end')
        
        return m
    
    def signatureVerify(self, senderPublicKey, s):
        logging.debug('signatureVerify start')
        s_n, s_e = senderPublicKey
        m = self.m
        
        # compute integer v = (s^e) mod n
        v = pow(s,s_e,s_n)
        
        # independently compute the message digest H' of the information that has been signed
        # if both message digests are identical, i.e H = H', the signature is valid
        if (v == m):
            print('Signature is valid')
        else:
            print('Signature is invalid')
        
        logging.debug('s: %s' % (s))
        logging.debug('s_n: %s' % (s_n))
        logging.debug('s_e: %s' % (s_e))
        logging.debug('m: %s' % (m))
        logging.debug('v: %s' % (v))
        logging.debug('signatureVerify end')
    
    def __init__(self, publicKey, privateKey):
        self.publicKey = publicKey
        self.privateKey = privateKey
        logging.debug('Recipient initialized w/ publicKey=(n=%s,e=%s) privateKey=(n=%s,d=%s)' % (publicKey[0], publicKey[1], privateKey[0], privateKey[1]))
    

if (len(sys.argv) < 2):
    print('Enter one or more integers, seperated by spaces, to encrypt')
    args = input().split()
    
    for i, dec in enumerate(args):
        if (not(dec.isdecimal())):
            logging.critical('Input must be a list of integers. Aborting program.')
            sys.exit()
        
    

else:
    args = sys.argv[1:]
    
    for i, dec in enumerate(args):
        if (not(dec.isdecimal())):
            logging.critical('Input must be a list of integers. Aborting program.')
            sys.exit()
        
    

for i, dec in enumerate(args):
    rsa = RSA()
    senderPublicKey = rsa.publicKey
    senderPrivateKey = rsa.privateKey
    
    sender = Sender(senderPublicKey, senderPrivateKey)
    
    rsa = RSA()
    recipientPublicKey = rsa.publicKey
    recipientPrivateKey = rsa.privateKey
    
    recipient = Recipient(recipientPublicKey, recipientPrivateKey)
    
    plaintext = int(dec)
    print('plaintext = ',plaintext)
    
    ciphertext = sender.encrypt(recipientPublicKey, plaintext)
    print('ciphertext = ',ciphertext)
    
    signature = sender.digitalSign()
    print('signature = ',signature)
    
    decipheredtext = recipient.decrypt(ciphertext)
    print('decipheredtext = ',decipheredtext)
    
    recipient.signatureVerify(senderPublicKey, signature)

logging.debug('End of program')
