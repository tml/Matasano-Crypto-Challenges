
import math

# From http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
ENGLISH_FREQUENCIES = {
    'E' : .1202,
    'T' : .0910,
    'A' : .0812,
    'O' : .0768,
    'I' : .0731,
    'N' : .0695,
    'S' : .0628,
    'R' : .0602,
    'H' : .0592,
    'D' : .0432,
    'L' : .0398,
    'U' : .0288,
    'C' : .0271,
    'M' : .0261,
    'F' : .0230,
    'Y' : .0211,
    'W' : .0209,
    'G' : .0203,
    'P' : .0182,
    'B' : .0149,
    'V' : .0111,
    'K' : .0069,
    'X' : .0017,
    'Q' : .0011,
    'J' : .0010,
    'Z' : .0007
}

def probability_english(text):
    '''
    Use the Bhattacharyya coefficient to determine if the text is likely to be English.
    Higher is better.

    Whitespace is ignored.
    '''

    text = text.upper()
    frequencies = {}
    for letter in text:
        if letter in frequencies:
            frequencies[letter] += 1.
        else:
            frequencies[letter] = 1.

    total = sum(frequencies.values())
    for letter in frequencies.keys():
        frequencies[letter] /= total

    score = 0.0
    for l in ENGLISH_FREQUENCIES.keys():
        if l not in frequencies:
            frequencies[l] = 0.0
        score += math.sqrt(frequencies[l] * ENGLISH_FREQUENCIES[l])

    return score

def hamming_distance(s1, s2):
    '''
    Compute the edit/hamming distance of two _byte_ strings.
    This is done by XOR'ing each byte, and then converting the number
    to a binary string in the form '0b00..'. The leading 0b is stripped
    and the 1's counted.
    '''
    if len(s1) != len(s2):
        raise ValueError('Hamming Distance: strings must be of equal length')
    return sum(bin(c1 ^ c2)[2:].count('1') for c1,c2 in zip(s1, s2))
