
# Cryptographic functions for the challenges

import base64
import binascii
from itertools import cycle, starmap, product
import textutils
import string

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

