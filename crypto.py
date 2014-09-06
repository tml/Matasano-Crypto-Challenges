
# Cryptographic functions for the challenges

import base64
import binascii
from itertools import cycle, starmap, product
import textutils
import string
import random
import math

from Crypto.Cipher import AES

# Basic conversion functions

# Convert a hex string to bytes
def hex_to_bytes(hexstr):
    return bytes.fromhex(hexstr)

# Convert bytes to ascii string of base64 characters
def bytes_to_base64(b):
    return base64.b64encode(b).decode()

# Convert base64 string to bytes
def base64_to_bytes(b):
    return base64.b64decode(b)

# Convert hex string to base64 ascii string
def hex_to_base64(hexstr):
    return bytes_to_base64(hex_to_bytes(hexstr))

# Convert bytes to a hex string
def bytes_to_hex(b):
    return binascii.b2a_hex(b).decode()

# Convert ascii string to bytes
def str_to_bytes(string):
    return bytes(string, encoding='utf-8')

# Cyphers

# XOR key with plaintext
def fixed_xor(plain, key):
    return bytes([x ^ y for x,y in zip(plain, cycle(key))])


def brute_xor(ciphertext, keys):
    '''
    Brute force a plaintext which has been encrypted with an XOR cipher
    by trying all the keys in the list. The plaintext which looks most
    like a piece of english text will be the winner.

    Returns the best key and the plaintext
    '''
    best = (0.0, None, None)
    for key in keys:
        try:
            plain = fixed_xor(ciphertext, key).decode()
            score = textutils.probability_english(plain)
            if score > best[0] and all(c in string.printable for c in plain):
                best = (score, key, plain)
        except UnicodeDecodeError:
            pass
    return best[1:]


def brute_xor_keysize(cipher):
    '''
    Take different key sizes and find the average normalised (by key length) hamming distance
    between all pairs of the first 4 blocks of ciphertext. The lowest wins.
    '''
    sizes = range(2, 40)
    keysizes = {}
    for size in sizes:
        # Take 4 blocks of length key
        blocks = [cipher[i*size:size*(i+1)] for i in range(0, 4)]
        assert all(len(block) == size for block in blocks)
        # Compute hamming distances
        distances = list(starmap(textutils.hamming_distance, product(blocks, blocks[1:])))
        # Compute normalised average
        #average = float(sum(distances))/float(len(distances))/float(size)
        average = sum(float(d)/float(size) for d in distances) / float(len(distances))
        keysizes[size] = average
    
    # Return the smallest
    print(keysizes)
    return min(keysizes, key=keysizes.get)

def brute_xor_key(cipher, keysize):
    '''
    Given a keysize, split the cipher into blocks of length keysize, then transpose
    and concatenate the blocks. Do single letter XOR on each block to find the key.
    '''
    blocks = [cipher[i::keysize] for i in range(keysize)]
    assert len(cipher) == sum(len(b) for b in blocks)
    key = []
    for block in blocks:
        keys = [[b] for b in range(0, 255)]
        k, _ = brute_xor(block, keys)
        key.append(k[0])
    return ''.join(map(chr,key))


def decrypt_AES_ECB(cipher, key):
    obj = AES.new(key, AES.MODE_ECB)
    return obj.decrypt(cipher)

def encrypt_AES_ECB(cipher, key):
    obj = AES.new(key, AES.MODE_ECB)
    return obj.encrypt(cipher)

def repeated_block(text):
    '''
    Detect ECB mode. If the text has a repeated block, it means
    that the plaintext was likely encoded using ECB mode.
    '''
    block_length = 16
    blocks = [text[i*block_length:block_length*(i+1)] for i in range(int(len(text)/block_length))]
    if len(set(blocks)) != len(blocks):
        return True
    return False


def pad_PKCS7(block, block_length=20):
    '''
    Pad the block to the block_length, with each element in the padding
    equal to the number of padded bytes. I.e. 4 padding bytes would be \x04
    '''
    if len(block) > block_length:
        raise ValueError('PKCS7: block length is greater than wanted block size')

    padding = block_length - len(block)
    for i in range(padding):
        block += padding.to_bytes(1, byteorder='big')
    return block


def decrypt_AES_CBC(cipher, key, IV=bytes(16)):
    '''
    Decrypt a ciphertext using AES CBC using the AES ECB mode.
    Assume an IV of zero if one is not given.
    The previous ciphertext block is XOR'd with the result of the
    block cipher to give the plaintext.
    '''
    if int(len(cipher) / 16) != len(cipher)/16:
        raise ValueError('Cipher must be a multiple of blocks of length 16')
    plain = []
    blocks = [cipher[i*16:(i+1)*16] for i in range(int(len(cipher)/16))]
    for i in range(int(len(cipher) / 16)):
        decrypt = decrypt_AES_ECB(blocks[i], key)
        xor = fixed_xor(decrypt, blocks[i-1]) if i > 0 else fixed_xor(decrypt, IV)
        plain.append(xor)
    return b''.join(plain)

def encrypt_AES_CBC(plain, key, IV=bytes(16)):
    '''
    Encrypt a plaintext using AES CBC mode.
    '''
    if int(len(plain) / 16) != len(plain)/16:
        raise ValueError('Plaintext must be a multiple of blocks of length 16')
    cipher = []
    blocks = [plain[i*16:(i+1)*16] for i in range(int(len(plain)/16))]
    for i in range(int(len(plain)/16)):
        xor = fixed_xor(blocks[i], cipher[i-1]) if i > 0 else fixed_xor(blocks[i], IV)
        encrypt = encrypt_AES_ECB(xor, key)
        cipher.append(encrypt)
    return b''.join(cipher)


def random_AES_key():
    '''
    Generate 16 random bytes
    '''
    key = [random.randint(0,255).to_bytes(1, byteorder='big') for i in range(16)]
    return b''.join(key)

def encrypt_ECB_or_CBC(plain):
    '''
    Encrypt the plaintext using EBC or CBC under a random key and random IV.
    Flip a coin to determine which was used.
    Append and prepend 5 to 10 bytes (count chosen randomly) to the plaintext.
    '''
    # Make the random choices
    random_key = random_AES_key()
    random_IV = random_AES_key()
    choice = bool(random.randrange(2))
    # Append 5 - 10 bytes
    n = random.randint(5,10)
    plain = b''.join([random.randint(0,255).to_bytes(1,byteorder='big') for i in range(n)]) + plain
    # Prepend 5 - 10 bytes
    n = random.randint(5,10)
    plain = plain + b''.join([random.randint(0,255).to_bytes(1,byteorder='big') for i in range(n)])
    # Split into blocks and pad the last block
    plain = [plain[i*16:(i+1)*16] for i in range(int(len(plain)/16))]
    plain[-1] = pad_PKCS7(plain[-1], block_length=16)
    # Reform the blocks
    plain = b''.join(plain)
    if choice:
        # Encrypt CBC
        print('(Secretly chose CBC)')
        cipher = encrypt_AES_CBC(plain, random_key, random_IV)
    else:
         #Encrypt ECB
         print('(Secretly chose ECB)')
         cipher = encrypt_AES_ECB(plain, random_key)
    return cipher

def detect_ECB(cipher):
    '''
    Given a cipher, determine if using ECB mode or CBC mode.
    Return True if ECB, False otherwise.
    Do this by encrypting a plaintext which will result in a repeading block.
    If there are two blocks, then the cipher used ECB mode.
    '''
    plaintext = str_to_bytes('A' * 50)
    ciphertext = cipher(plaintext)
    return repeated_block(ciphertext)


encrypt_append_secret_ECB_key = None
def encrypt_append_secret_ECB(plain):
    '''
    Append a string to your plaintext and encrypt under a fixed key
    using AES ECB mode.
    '''
    # Make the random key if we haven't already made it
    global encrypt_append_secret_ECB_key
    if not encrypt_append_secret_ECB_key:
        encrypt_append_secret_ECB_key = random_AES_key()
    # Append the secret
    secret = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    plain += base64_to_bytes(secret)
    # Pad if needs be
    num_blocks = math.ceil(len(plain) / 16)
    plain = pad_PKCS7(plain, 16 * num_blocks)
    # Encrypt
    return encrypt_AES_ECB(plain, encrypt_append_secret_ECB_key)

def detect_cipher_block_size(cipher):
    '''
    Send increasing length strings to cipher. When the cipher length changes,
    the difference between them is the block length.
    '''
    length = len(cipher(str_to_bytes('A')))
    for i in range(50):
        new_length = len(cipher(str_to_bytes('A' * i)))
        if new_length != length:
            return new_length - length
    raise RuntimeError('Could not determine block size')

