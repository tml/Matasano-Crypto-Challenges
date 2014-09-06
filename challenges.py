#!/usr/bin/env python3
# Wrapper for running the challenges

import sys
import crypto
import textutils

# Define a decorator to register the function as a challenge
challenges = {}
def challenge(n):
    def decorator(f):
        def wrapper(*args, **kwargs):
            print()
            print('@@@@@@@@@@@@@@@@@@@@')
            print('Challenge {0}'.format(n))
            print('@@@@@@@@@@@@@@@@@@@@')
            print()
            f(*args, **kwargs)
        challenges[n] = wrapper
        return wrapper
    return decorator

# Check if the results are correct
def expect(actual, expected):
    if actual != expected:
        print('Failed.')
        print('Expected: {0}'.format(expected))
        print('Actual: {0}'.format(actual))
        return False
    return True

# The challenges

# Set 1

@challenge(1)
def c1():
    EXAMPLE_INPUT = ('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    EXAMPLE_OUTPUT = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    result = crypto.hex_to_base64(EXAMPLE_INPUT)
    print(result)
    expect(result, EXAMPLE_OUTPUT)

@challenge(2)
def c2():
    EXAMPLE_INPUT = ( \
        '1c0111001f010100061a024b53535009181c',
        '686974207468652062756c6c277320657965'
        )
    EXAMPLE_OUTPUT = '746865206b696420646f6e277420706c6179'

    plain, key = map(crypto.hex_to_bytes, EXAMPLE_INPUT)
    result = crypto.fixed_xor(plain, key)
    result = crypto.bytes_to_hex(result)

    print(result)
    expect(result, EXAMPLE_OUTPUT)

@challenge(3)
def c3():
    EXAMPLE_INPUT = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    ciphertext = crypto.hex_to_bytes(EXAMPLE_INPUT)
    potential_keys = [[b] for b in range(0, 255)]

    key, plain = crypto.brute_xor(ciphertext, potential_keys)
    print('Key: {0}'.format(key))
    print('Plaintext: {0}'.format(plain))

@challenge(4)
def c4():
    texts = []
    keys = [[b] for b in range(0, 255)]
    for line in open('inputs/4.txt').readlines():
        line = line.strip()
        _, text = crypto.brute_xor(crypto.hex_to_bytes(line), keys)
        if text:
            texts.append(text)
    best = max(texts, key=textutils.probability_english)

    print(best)

@challenge(5)
def c5():
    PLAINTEXT = "Burning 'em, if you ain't quick and nimble\n" + \
        "I go crazy when I hear a cymbal"

    KEY = 'ICE'

    EXAMPLE_OUTPUT = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' + \
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'


    plain, key = map(crypto.str_to_bytes, (PLAINTEXT, KEY))
    cipher = crypto.fixed_xor(plain, key)
    result = crypto.bytes_to_hex(cipher)

    print(result)
    expect(result, EXAMPLE_OUTPUT)

@challenge(6)
def c6():
    HAMMING_INPUTS = ('this is a test','wokka wokka!!!')
    distance = textutils.hamming_distance(*map(crypto.str_to_bytes, HAMMING_INPUTS))
    expect(distance, 37)

    with open('inputs/6.txt') as f:
        cipher = f.read()
        cipher = crypto.base64_to_bytes(cipher)
        
        keysize = crypto.brute_xor_keysize(cipher)
        print('Guessing the key size is {0}'.format(keysize))

        key = crypto.brute_xor_key(cipher, keysize)
        print('Key: {0}'.format(key))

        plain = crypto.fixed_xor(cipher, crypto.str_to_bytes(key))
        print ('Plain: {0}'.format(plain.decode('utf-8')))

@challenge(7)
def c7():
    KEY = 'YELLOW SUBMARINE'
    with open('inputs/7.txt') as f:
        cipher = f.read()
        cipher = crypto.base64_to_bytes(cipher)
        key = crypto.str_to_bytes(KEY)
        plain = crypto.decrypt_AES_ECB(cipher, key)
        print('Plain: {0}'.format(plain.decode('utf-8')))

@challenge(8)
def c8():
    for line in open('inputs/8.txt').readlines():
        if crypto.repeated_block(line.strip()):
            print('Repeated block in {0}'.format(line))


# Set 2

@challenge(9)
def c9():
    INPUT_BLOCK = 'YELLOW SUBMARINE'
    OUTPUT_BLOCK = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    result = crypto.pad_PKCS7(crypto.str_to_bytes(INPUT_BLOCK), block_length=20)
    print(result)
    expect(result, OUTPUT_BLOCK)

@challenge(10)
def c10():
    INPUT_KEY = 'YELLOW SUBMARINE'
    with open('inputs/10.txt') as f:
        cipher = f.read()
        cipher = crypto.base64_to_bytes(cipher)
        key = crypto.str_to_bytes(INPUT_KEY)
        plain = crypto.decrypt_AES_CBC(cipher, key)
        print(plain)


# Run the crypto challenges
if __name__ == '__main__':
    run = sorted(challenges.keys())

    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            print('Usage: ./challenges.py [n] (for n integer)')
            sys.exit(1)
        if n not in challenges:
            print('No challenge {0}'.format(n))
            sys.exit(1)
        run = [n]

    for r in run:
        challenges[r]()
