import string
import math


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def mod_inverse(a, m):
    a = int(a) % m

    for x in range(1, m):
        if (a * x) % m == 1:
            return x

    return None


def clean_text(text):
    """
    Keep alphabetic characters only and convert to uppercase.
    """
    return ''.join(
        char.upper()
        for char in str(text)
        if char.isalpha()
    )


def clean_key(key):
    """
    Keep alphabetic characters only and convert to uppercase.
    """
    return ''.join(
        char.upper()
        for char in str(key)
        if char.isalpha()
    )


# =========================================================
# 1. ADDITIVE CIPHER
# =========================================================

def additive_encrypt(plaintext, key):
    key = int(key)

    result = []

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(
                chr((ord(char) - base + key) % 26 + base)
            )
        else:
            result.append(char)

    return ''.join(result)


def additive_decrypt(ciphertext, key):
    key = int(key)

    result = []

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(
                chr((ord(char) - base - key) % 26 + base)
            )
        else:
            result.append(char)

    return ''.join(result)


# =========================================================
# 2. MULTIPLICATIVE CIPHER
# =========================================================

def multiplicative_encrypt(plaintext, key):
    key = int(key)

    if mod_inverse(key, 26) is None:
        raise ValueError(
            "Multiplicative key must be relatively prime to 26."
        )

    result = []

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')

            result.append(
                chr(
                    ((ord(char) - base) * key) % 26
                    + base
                )
            )
        else:
            result.append(char)

    return ''.join(result)


def multiplicative_decrypt(ciphertext, key):
    key = int(key)

    inv_key = mod_inverse(key, 26)

    if inv_key is None:
        raise ValueError(
            "Multiplicative key must be relatively prime to 26."
        )

    result = []

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')

            result.append(
                chr(
                    ((ord(char) - base) * inv_key) % 26
                    + base
                )
            )
        else:
            result.append(char)

    return ''.join(result)


# =========================================================
# 3. AFFINE CIPHER
# =========================================================

def affine_encrypt(plaintext, a, b):
    a = int(a)
    b = int(b)

    if mod_inverse(a, 26) is None:
        raise ValueError(
            "Affine key 'a' must be relatively prime to 26."
        )

    result = []

    for char in plaintext:

        if char.isalpha():

            base = ord('A') if char.isupper() else ord('a')

            result.append(
                chr(
                    (
                        a * (ord(char) - base) + b
                    ) % 26 + base
                )
            )

        else:
            result.append(char)

    return ''.join(result)


def affine_decrypt(ciphertext, a, b):
    a = int(a)
    b = int(b)

    inv_a = mod_inverse(a, 26)

    if inv_a is None:
        raise ValueError(
            "Affine key 'a' must be relatively prime to 26."
        )

    result = []

    for char in ciphertext:

        if char.isalpha():

            base = ord('A') if char.isupper() else ord('a')

            result.append(
                chr(
                    (
                        inv_a * (
                            (ord(char) - base) - b
                        )
                    ) % 26 + base
                )
            )

        else:
            result.append(char)

    return ''.join(result)


# =========================================================
# 4. MONOALPHABETIC SUBSTITUTION
# =========================================================

def validate_substitution_key(key):

    key = clean_key(key)

    if len(key) != 26:
        raise ValueError(
            "Substitution key must contain exactly 26 letters."
        )

    if len(set(key)) != 26:
        raise ValueError(
            "Substitution key must contain 26 unique letters."
        )

    return key


def monoalphabetic_encrypt(plaintext, key):

    key = validate_substitution_key(key)

    alphabet = string.ascii_uppercase

    upper_table = str.maketrans(
        alphabet,
        key
    )

    lower_table = str.maketrans(
        alphabet.lower(),
        key.lower()
    )

    return plaintext.translate(
        upper_table
    ).translate(
        lower_table
    )


def monoalphabetic_decrypt(ciphertext, key):

    key = validate_substitution_key(key)

    alphabet = string.ascii_uppercase

    upper_table = str.maketrans(
        key,
        alphabet
    )

    lower_table = str.maketrans(
        key.lower(),
        alphabet.lower()
    )

    return ciphertext.translate(
        upper_table
    ).translate(
        lower_table
    )


# =========================================================
# 5. AUTOKEY CIPHER
# =========================================================

def autokey_encrypt(plaintext, key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Autokey key cannot be empty."
        )

    text = clean_text(plaintext)

    extended_key = key + text

    encrypted = []

    for i, char in enumerate(text):

        shift = ord(
            extended_key[i]
        ) - ord('A')

        encrypted.append(
            chr(
                (
                    ord(char) - ord('A') + shift
                ) % 26 + ord('A')
            )
        )

    return ''.join(encrypted)


def autokey_decrypt(ciphertext, key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Autokey key cannot be empty."
        )

    ciphertext = clean_text(ciphertext)

    decrypted = []

    current_key = key

    for i, char in enumerate(ciphertext):

        shift = ord(
            current_key[i]
        ) - ord('A')

        plain_char = chr(
            (
                ord(char) - ord('A') - shift
            ) % 26 + ord('A')
        )

        decrypted.append(
            plain_char
        )

        current_key += plain_char

    return ''.join(decrypted)


# =========================================================
# 6. VIGENÈRE CIPHER
# =========================================================

def vigenere_encrypt(plaintext, key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Vigenère key cannot be empty."
        )

    result = []

    key_index = 0

    for char in plaintext:

        if char.isalpha():

            shift = (
                ord(key[key_index % len(key)])
                - ord('A')
            )

            base = (
                ord('A')
                if char.isupper()
                else ord('a')
            )

            result.append(
                chr(
                    (
                        ord(char) - base + shift
                    ) % 26 + base
                )
            )

            key_index += 1

        else:

            result.append(char)

    return ''.join(result)


def vigenere_decrypt(ciphertext, key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Vigenère key cannot be empty."
        )

    result = []

    key_index = 0

    for char in ciphertext:

        if char.isalpha():

            shift = (
                ord(key[key_index % len(key)])
                - ord('A')
            )

            base = (
                ord('A')
                if char.isupper()
                else ord('a')
            )

            result.append(
                chr(
                    (
                        ord(char) - base - shift
                    ) % 26 + base
                )
            )

            key_index += 1

        else:

            result.append(char)

    return ''.join(result)


# =========================================================
# 7. PLAYFAIR CIPHER
# =========================================================

def _playfair_table(key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Playfair key cannot be empty."
        )

    table = []
    seen = set()

    for char in key:

        if char == 'J':
            char = 'I'

        if char not in seen:
            seen.add(char)
            table.append(char)

    for char in string.ascii_uppercase:

        if char == 'J':
            continue

        if char not in seen:
            seen.add(char)
            table.append(char)

    return table


def _playfair_prepare_plaintext(plaintext):

    text = clean_text(plaintext).replace('J', 'I')

    pairs = []

    i = 0

    while i < len(text):

        first = text[i]

        if i + 1 >= len(text):

            pairs.append(
                first + 'X'
            )

            i += 1

        else:

            second = text[i + 1]

            if first == second:

                pairs.append(
                    first + 'X'
                )

                i += 1

            else:

                pairs.append(
                    first + second
                )

                i += 2

    return pairs


def playfair_encrypt(plaintext, key):

    table = _playfair_table(key)

    bigrams = _playfair_prepare_plaintext(
        plaintext
    )

    encrypted = []

    for a, b in bigrams:

        pos_a = table.index(a)
        pos_b = table.index(b)

        row_a, col_a = divmod(pos_a, 5)
        row_b, col_b = divmod(pos_b, 5)

        if row_a == row_b:

            encrypted.append(
                table[
                    row_a * 5 +
                    (col_a + 1) % 5
                ]
            )

            encrypted.append(
                table[
                    row_b * 5 +
                    (col_b + 1) % 5
                ]
            )

        elif col_a == col_b:

            encrypted.append(
                table[
                    ((row_a + 1) % 5) * 5
                    + col_a
                ]
            )

            encrypted.append(
                table[
                    ((row_b + 1) % 5) * 5
                    + col_b
                ]
            )

        else:

            encrypted.append(
                table[
                    row_a * 5 + col_b
                ]
            )

            encrypted.append(
                table[
                    row_b * 5 + col_a
                ]
            )

    return ''.join(encrypted)


def playfair_decrypt(ciphertext, key):

    table = _playfair_table(key)

    text = clean_text(ciphertext)

    if len(text) % 2 != 0:
        raise ValueError(
            "Playfair ciphertext must contain an even number of letters."
        )

    decrypted = []

    for i in range(0, len(text), 2):

        a = text[i]
        b = text[i + 1]

        pos_a = table.index(a)
        pos_b = table.index(b)

        row_a, col_a = divmod(pos_a, 5)
        row_b, col_b = divmod(pos_b, 5)

        if row_a == row_b:

            decrypted.append(
                table[
                    row_a * 5 +
                    (col_a - 1) % 5
                ]
            )

            decrypted.append(
                table[
                    row_b * 5 +
                    (col_b - 1) % 5
                ]
            )

        elif col_a == col_b:

            decrypted.append(
                table[
                    ((row_a - 1) % 5) * 5
                    + col_a
                ]
            )

            decrypted.append(
                table[
                    ((row_b - 1) % 5) * 5
                    + col_b
                ]
            )

        else:

            decrypted.append(
                table[
                    row_a * 5 + col_b
                ]
            )

            decrypted.append(
                table[
                    row_b * 5 + col_a
                ]
            )

    result = ''.join(decrypted)

    return _remove_playfair_fillers(result)


def _remove_playfair_fillers(text):

    if not text:
        return text

    result = []

    for i, char in enumerate(text):

        if (
            char == 'X'
            and i > 0
            and i < len(text) - 1
            and text[i - 1] == text[i + 1]
        ):
            continue

        result.append(char)

    result = ''.join(result)

    # Remove final padding X
    if result.endswith('X'):
        result = result[:-1]

    return result


# =========================================================
# 8. KEYLESS TRANSPOSITION
# =========================================================

def keyless_transposition_encrypt(plaintext):

    text = clean_text(plaintext)

    if not text:
        return ""

    cols = math.ceil(
        math.sqrt(len(text))
    )

    grid = [''] * cols

    for i, char in enumerate(text):

        grid[i % cols] += char

    return ''.join(grid)


def keyless_transposition_decrypt(ciphertext):

    text = clean_text(ciphertext)

    if not text:
        return ""

    n = len(text)

    cols = math.ceil(
        math.sqrt(n)
    )

    rows = math.ceil(
        n / cols
    )

    # Encryption creates columns by distributing
    # characters cyclically.
    #
    # Their lengths can differ when n is not divisible
    # by cols.

    column_lengths = []

    for col in range(cols):

        length = 0

        for i in range(n):

            if i % cols == col:
                length += 1

        column_lengths.append(length)

    columns = []

    index = 0

    for length in column_lengths:

        columns.append(
            text[
                index:index + length
            ]
        )

        index += length

    plaintext = []

    for row in range(rows):

        for col in range(cols):

            if row < len(columns[col]):

                plaintext.append(
                    columns[col][row]
                )

    return ''.join(plaintext)


# =========================================================
# 9. KEYED TRANSPOSITION
# =========================================================

def _key_order(key):

    key = clean_key(key)

    if not key:
        raise ValueError(
            "Transposition key cannot be empty."
        )

    # Stable sorting preserves the original order
    # of duplicate letters.
    return sorted(
        range(len(key)),
        key=lambda i: (key[i], i)
    )


def keyed_transposition_encrypt(plaintext, key):

    text = clean_text(plaintext)
    key = clean_key(key)

    if not key:
        raise ValueError(
            "Transposition key cannot be empty."
        )

    cols = len(key)

    rows = math.ceil(
        len(text) / cols
    )

    padded_length = rows * cols

    padded_text = (
        text +
        'X' * (
            padded_length - len(text)
        )
    )

    # Fill row by row
    grid = []

    index = 0

    for row in range(rows):

        grid.append(
            list(
                padded_text[
                    index:index + cols
                ]
            )
        )

        index += cols

    order = _key_order(key)

    ciphertext = []

    # Read columns according to sorted key
    for col in order:

        for row in range(rows):

            ciphertext.append(
                grid[row][col]
            )

    return ''.join(ciphertext)


def keyed_transposition_decrypt(ciphertext, key):

    text = clean_text(ciphertext)
    key = clean_key(key)

    if not key:
        raise ValueError(
            "Transposition key cannot be empty."
        )

    cols = len(key)

    if len(text) % cols != 0:
        raise ValueError(
            "Invalid ciphertext length for this transposition key."
        )

    rows = len(text) // cols

    grid = [
        [''] * cols
        for _ in range(rows)
    ]

    order = _key_order(key)

    index = 0

    # Put ciphertext back into columns
    for col in order:

        for row in range(rows):

            grid[row][col] = text[index]

            index += 1

    plaintext = ''.join(
        ''.join(row)
        for row in grid
    )

    # Remove padding added during encryption
    return plaintext.rstrip('X')


# =========================================================
# 10. DOUBLE TRANSPOSITION
# =========================================================

def double_transposition_encrypt(
    plaintext,
    key1,
    key2
):

    first = keyed_transposition_encrypt(
        plaintext,
        key1
    )

    second = keyed_transposition_encrypt(
        first,
        key2
    )

    return second


def double_transposition_decrypt(
    ciphertext,
    key1,
    key2
):

    # IMPORTANT:
    #
    # Encryption:
    #
    # plaintext
    #    ↓ key1
    # first
    #    ↓ key2
    # ciphertext
    #
    # Therefore decryption:
    #
    # ciphertext
    #    ↓ key2
    # first
    #    ↓ key1
    # plaintext

    first = keyed_transposition_decrypt(
        ciphertext,
        key2
    )

    second = keyed_transposition_decrypt(
        first,
        key1
    )

    return second