import numpy as np


def gener_key(bits):
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]
    firstPerm = []
    K1 = []
    K2 = []

    for pos in p10:
        firstPerm.append(int(bits[pos - 1]))
    firstRoll = [*np.roll(firstPerm[:5], -1), *np.roll(firstPerm[5:], -1)]

    for pos in p8:
        K1.append(int(firstRoll[pos - 1]))
    secondRoll = [*np.roll(firstRoll[:5], -2), *np.roll(firstRoll[5:], -2)]

    for pos in p8:
        K2.append(int(secondRoll[pos - 1]))

    return K1, K2


def p4(block):
    return [block[1], block[3], block[2], block[0]]


def ip(b_block):
    return [b_block[1], b_block[5], b_block[2], b_block[0],
            b_block[3], b_block[7], b_block[4], b_block[6]]


def end_ip(block):
    return [block[3], block[0], block[2], block[4],
            block[6], block[1], block[7], block[5]]


def ep(block):
    return [block[3], block[0], block[1], block[2],
            block[1], block[2], block[3], block[0]]


def xor(first_list, second_list):
    answer = []
    for i in range(len(first_list)):
        answer.append(int(first_list[i]) ^ int(second_list[i]))

    return answer


def work_with_s_blocks(block):
    S_blocks = [[[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]], [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]]
    left_block, right_block = block[:4], block[-4:]

    str1, cell1 = int(str(left_block[0]) + str(left_block[-1]), 2), int(str(left_block[1]) + str(left_block[2]), 2)
    str2, cell2 = int(str(right_block[0]) + str(right_block[-1]), 2), int(str(right_block[1]) + str(right_block[2]), 2)

    res1 = bin(S_blocks[0][str1][cell1])
    res2 = bin(S_blocks[1][str2][cell2])

    return str(res1).replace('b', '') + str(res2).replace('b', '')


def round_crypt(b_block, key):
    left_block, right_block = b_block[:4], b_block[-4:]
    right_block_8b = ep(right_block)
    answer = xor(right_block_8b, key)
    p6 = xor(p4(work_with_s_blocks(answer)), left_block)

    return p6 + right_block


def encrypt(msg, K1, K2):
    result = ''
    count_iter = len(msg)//8

    for it in range(0, count_iter):
        block = ip(msg[it*8:(it+1)*8])
        block = round_crypt(block, K1)
        block = block[-4:] + block[:4]
        block_result = end_ip(round_crypt(block, K2))
        result += ''.join(map(str, block_result))

    return result

def decrypt(msg, K1, K2):
    result = ''
    count_iter = len(msg) // 8

    for it in range(0, count_iter):
        block = ip(msg[it * 8:(it + 1) * 8])
        block = round_crypt(block, K2)
        block = block[-4:] + block[:4]
        block_result = end_ip(round_crypt(block, K1))
        result += ''.join(map(str, block_result))

    return result


if __name__ == '__main__':
    bits = '1001010011'
    (K1, K2) = gener_key(bits)
    msg = input("Please, input your message: ")
    b_msg = bin(int.from_bytes(msg.encode(), 'big')).replace('b', '')

    encrypted_message = encrypt(b_msg, K1, K2)
    print("Encrypt message: ", encrypted_message)

    print("Decrypt message: ", bytes.fromhex(hex(int(decrypt(encrypted_message, K1, K2), 2))[2:]).decode(encoding="ascii"))