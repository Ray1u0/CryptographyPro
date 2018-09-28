# -*- coding: utf-8 -*-

#Grade alternative results
def get_english_score(input_bytes):
    
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])
"""
利用字母频率表给备选结果打分，取分数最高者为答案
"""


def single_char_xor(input_bytes, char_value): 
    
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


hexstring = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
ciphertext = bytes.fromhex(hexstring)
potential_messages = []

for key_value in range(256):
    
    message = single_char_xor(ciphertext, key_value)
    score = get_english_score(message)
    data = {
        'message': message,
        'score': score,
        'key': key_value
        }
    potential_messages.append(data)
    
result = sorted(potential_messages, key=lambda x: x['score'], reverse=True)
best_score = result[0]
result3 = best_score
del result3['score']
for item in result3:
    print("{}: {}".format(item.title(), best_score[item]))

