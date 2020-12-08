class SimplifiedAES(object):
    """Simplified AES is a simplified version of AES algorithm"""

    # S-Box
    sBox = [
        0x9,
        0x4,
        0xA,
        0xB,
        0xD,
        0x1,
        0x8,
        0x5,
        0x6,
        0x2,
        0x0,
        0x3,
        0xC,
        0xE,
        0xF,
        0x7,
    ]

    # Inverse S-Box
    sBoxI = [
        0xA,
        0x5,
        0x9,
        0xB,
        0x1,
        0x7,
        0x8,
        0xF,
        0x6,
        0x0,
        0x2,
        0x3,
        0xC,
        0x4,
        0xD,
        0xE,
    ]

    def __init__(self, key):
        # Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
        self.pre_round_key, self.round1_key, self.round2_key = self.key_expansion(key)

    def sub_word(self, word):
        """ Substitute word

        :param word: word
        """
        # Take each nibble in the word and substitute another nibble for it using
        # the Sbox table
        return (self.sBox[(word >> 4)] << 4) + self.sBox[word & 0x0F]

    def rot_word(self, word):
        """ Rotate word

        :param word: word
        """
        # Swapping the two nibbles in the word since eqv to rotate here
        return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)

    def key_expansion(self, key):
        """Key expansion

        Creates three 16-bit round keys from one single 16-bit cipher key

        Cipher Key : | n0 | n1 | n2 | n3 |
        w[0]       : | n0 | n1 |
        w[1]       : | n2 | n3 |

        for i % 2 == 0:
            w[i] : w[i - 2] XOR (SubWord(RotWord(W[i-1])) XOR RC[Nr])
        else:
            w[i] = w[i - 1] XOR w[i - 2]

        :param key: key to be used for encryption and/or decryption
        :returns: Tuple containing pre-round, round 1 and round 2 key in order
        """

        # Round constants
        Rcon1 = 0x80
        Rcon2 = 0x30

        # Calculating value of each word
        w = [None] * 6
        w[0] = (key & 0xFF00) >> 8
        w[1] = key & 0x00FF
        w[2] = w[0] ^ (self.sub_word(self.rot_word(w[1])) ^ Rcon1)
        w[3] = w[2] ^ w[1]
        w[4] = w[2] ^ (self.sub_word(self.rot_word(w[3])) ^ Rcon2)
        w[5] = w[4] ^ w[3]

        return (
            self.int_to_state((w[0] << 8) + w[1]),  # Pre-Round key
            self.int_to_state((w[2] << 8) + w[3]),  # Round 1 key
            self.int_to_state((w[4] << 8) + w[5]),  # Round 2 key
        )

    def gf_mult(self, a, b):
        """Galois field multiplication of a and b in GF(2^4) / x^4 + x + 1
        :param a: First number
        :param b: Second number
        :returns: Multiplication of both under GF(2^4)
        """
        # Initialise
        product = 0

        # Mask the unwanted bits
        a = a & 0x0F
        b = b & 0x0F

        # While both multiplicands are non-zero
        while a and b:

            # If LSB of b is 1
            if b & 1:

                # Add current a to product
                product = product ^ a

            # Update a to a * 2
            a = a << 1

            # If a overflows beyond 4th bit
            if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
                a = a ^ 0b10011

            # Update b to b // 2
            b = b >> 1

        return product

    def int_to_state(self, n):
        """Convert a 2-byte integer into a 4-element vector (state matrix)
        :param m: integer
        :returns: state corresponding to the integer
        """
        return [n >> 12 & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF, n & 0xF]

    def state_to_int(self, m):
        """Convert a 4-element vector (state matrix) into 2-byte integer
        :param m: state
        :returns: integer corresponding to the state
        """
        return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

    def add_round_key(self, s1, s2):
        """Add round keys in GF(2^4)

        :param s1: First number
        :param s2: Second number
        :returns: Addition of both under GF(2^4)
        """
        return [i ^ j for i, j in zip(s1, s2)]

    def sub_nibbles(self, sbox, state):
        """Nibble substitution

        :param sbox: Substitution box to use for transformatin
        :param state: State to perform sub nibbles transformation on
        :returns: Resultant state
        """
        return [sbox[nibble] for nibble in state]

    def shift_rows(self, state):
        """Shift rows and inverse shift rows of state matrix (same)

        :param state: State to perform shift rows transformation on
        :returns: Resultant state
        """
        return [state[0], state[1], state[3], state[2]]

    def mix_columns(self, state):
        """Mix columns transformation on state matrix

        :param state: State to perform mix columns transformation on
        :returns: Resultant state
        """
        return [
            state[0] ^ self.gf_mult(4, state[2]),
            state[1] ^ self.gf_mult(4, state[3]),
            state[2] ^ self.gf_mult(4, state[0]),
            state[3] ^ self.gf_mult(4, state[1]),
        ]

    def inverse_mix_columns(self, state):
        """Inverse mix columns transformation on state matrix

        :param state: State to perform inverse mix columns transformation on
        :returns: Resultant state
        """
        return [
            self.gf_mult(9, state[0]) ^ self.gf_mult(2, state[2]),
            self.gf_mult(9, state[1]) ^ self.gf_mult(2, state[3]),
            self.gf_mult(9, state[2]) ^ self.gf_mult(2, state[0]),
            self.gf_mult(9, state[3]) ^ self.gf_mult(2, state[1]),
        ]

    def encrypt(self, plaintext):
        """Encrypt plaintext with given key

        Example::

            ciphertext = SimplifiedAES(key=0b0100101011110101).encrypt(0b1101011100101000)

        :param plaintext: 16 bit plaintext
        :returns: 16 bit ciphertext
        """
        state = self.add_round_key(self.pre_round_key, self.int_to_state(plaintext))

        state = self.mix_columns(self.shift_rows(self.sub_nibbles(self.sBox, state)))

        state = self.add_round_key(self.round1_key, state)

        state = self.shift_rows(self.sub_nibbles(self.sBox, state))

        state = self.add_round_key(self.round2_key, state)

        return self.state_to_int(state)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext with given key

        Example::

            plaintext = SimplifiedAES(key=0b0100101011110101).decrypt(0b0010010011101100)

        :param ciphertext: 16 bit ciphertext
        :returns: 16 bit plaintext
        """
        state = self.add_round_key(self.round2_key, self.int_to_state(ciphertext))

        state = self.sub_nibbles(self.sBoxI, self.shift_rows(state))

        state = self.inverse_mix_columns(self.add_round_key(self.round1_key, state))

        state = self.sub_nibbles(self.sBoxI, self.shift_rows(state))

        state = self.add_round_key(self.pre_round_key, state)

        return self.state_to_int(state)