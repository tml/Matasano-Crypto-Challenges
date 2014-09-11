
# Class for the cryptopals challenge 13 - ECB cut and paste

import crypto
import string

class Profile:

    def encode(self):
        '''
        Return the k=v encoding of the profile object.
        Deliminator is the & character
        '''
        return 'email=' + self.email + '&uid=' + str(self.uid) + '&role=' + self.role

    def __repr__(self):
        '''
        Print a dictionary of the attributes
        '''
        return str(vars(self))

def parse(string):
    '''
    Parse a string of k=v pairs (e.g. foo=bar&baz=qux&zap=zazzle)
    and produce the profile object
    {
        foo: 'bar',
        baz: 'qux',
        zap: 'zazzle'
    }
    '''
    items = string.split('&')
    p = Profile()
    for pair in items:
        if '=' in pair:
            k, v = pair.split('=')
            setattr(p, k, v)
    return p

def profile_for(email):
    '''
    Return a profile for a given email address.
    Eat/quote out the metacharacters (& and =) in the email field.
    '''
    p = Profile()
    p.email = email.translate(str.maketrans({'&':None,'=':None}))
    p.uid = 10
    p.role = 'user'
    return p

PROFILE_SECRET_KEY = None
def encrypt(encoded):
    '''
    Encrypt a k=v encoded string using AES ECB mode.
    Returns the ciphertext.
    '''
    global PROFILE_SECRET_KEY
    if not PROFILE_SECRET_KEY:
        PROFILE_SECRET_KEY = crypto.random_AES_key()

    plain = crypto.str_to_bytes(encoded)
    plain = crypto.plaintext_pad_PKCS7(plain)
    return crypto.encrypt_AES_ECB(plain, PROFILE_SECRET_KEY)

def decrypt(cipher):
    '''
    Decrypt a ciphertext and parse it to produce a profile..
    '''
    global PROFILE_SECRET_KEY
    if not PROFILE_SECRET_KEY:
        PROFILE_SECRET_KEY = crypto.random_AES_key()

    plain = crypto.decrypt_AES_ECB(cipher, PROFILE_SECRET_KEY)
    # Crudely remove any padding
    plain=plain.decode()
    plain = ''.join(filter(string.printable.__contains__, str(plain)))

    print('About to parse {0}'.format(plain))

    return parse(plain)
