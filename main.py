import random
import string

# Helper functions
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def clean_text(text):
    return ''.join([char.upper() for char in text if char.isalpha()])

# Ciphers Implementation

# 1. Additive Cipher
def additive_encrypt(plaintext, key):
    return ''.join([chr((ord(char) - 65 + key) % 26 + 65) if char.isupper() else char for char in plaintext])

def additive_decrypt(ciphertext, key):
    return ''.join([chr((ord(char) - 65 - key) % 26 + 65) if char.isupper() else char for char in ciphertext])

# 2. Multiplicative Cipher
def multiplicative_encrypt(plaintext, key):
    return ''.join([chr(((ord(char) - 65) * key) % 26 + 65) if char.isupper() else char for char in plaintext])

def multiplicative_decrypt(ciphertext, key):
    inv_key = mod_inverse(key, 26)
    if inv_key is None:
        return "Invalid key"
    return ''.join([chr(((ord(char) - 65) * inv_key) % 26 + 65) if char.isupper() else char for char in ciphertext])

# 3. Affine Cipher
def affine_encrypt(plaintext, a, b):
    return ''.join([chr((a * (ord(char) - 65) + b) % 26 + 65) if char.isupper() else char for char in plaintext])

def affine_decrypt(ciphertext, a, b):
    inv_a = mod_inverse(a, 26)
    if inv_a is None:
        return "Invalid key"
    return ''.join([chr((inv_a * ((ord(char) - 65) - b)) % 26 + 65) if char.isupper() else char for char in ciphertext])

# 4. Monoalphabetic Substitution Cipher
def monoalphabetic_encrypt(plaintext, key):
    alphabet = string.ascii_uppercase
    substitution = str.maketrans(alphabet, key)
    return plaintext.translate(substitution)

def monoalphabetic_decrypt(ciphertext, key):
    alphabet = string.ascii_uppercase
    substitution = str.maketrans(key, alphabet)
    return ciphertext.translate(substitution)

# 5. Autokey Cipher
def autokey_encrypt(plaintext, key):
    key = clean_text(key)
    extended_key = key + plaintext
    return ''.join([chr((ord(plaintext[i]) - 65 + ord(extended_key[i]) - 65) % 26 + 65) for i in range(len(plaintext))])

def autokey_decrypt(ciphertext, key):
    key = clean_text(key)
    decrypted = ''
    for i in range(len(ciphertext)):
        char = chr((ord(ciphertext[i]) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65)
        decrypted += char
        key += char  # Extend the key
    return decrypted

# 6. Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    key = clean_text(key)
    encrypted = []
    for i, char in enumerate(plaintext):
        if char.isupper():
            shift = ord(key[i % len(key)]) - 65
            encrypted.append(chr((ord(char) - 65 + shift) % 26 + 65))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    key = clean_text(key)
    decrypted = []
    for i, char in enumerate(ciphertext):
        if char.isupper():
            shift = ord(key[i % len(key)]) - 65
            decrypted.append(chr((ord(char) - 65 - shift) % 26 + 65))
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# 7. Playfair Cipher
def playfair_encrypt(plaintext, key):
    key = clean_text(key)
    # Prepare the Playfair table
    table = []
    seen = set()
    for char in key:
        if char not in seen and char in string.ascii_uppercase:
            seen.add(char)
            table.append(char)
    for char in string.ascii_uppercase:
        if char not in seen and char != 'J':
            seen.add(char)
            table.append(char)
    
    # Create bigrams
    plaintext = clean_text(plaintext).replace('J', 'I')
    bigrams = []
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            bigrams.append(plaintext[i] + 'X')
            i += 1
        else:
            bigrams.append(plaintext[i:i + 2])
            i += 2 if i + 1 < len(plaintext) else 1
    
    encrypted = ''
    for bigram in bigrams:
        a, b = bigram[0], bigram[1]
        row_a, col_a = divmod(table.index(a), 5)
        row_b, col_b = divmod(table.index(b), 5)
        if row_a == row_b:  # Same row
            encrypted += table[row_a * 5 + (col_a + 1) % 5]
            encrypted += table[row_b * 5 + (col_b + 1) % 5]
        elif col_a == col_b:  # Same column
            encrypted += table[((row_a + 1) % 5) * 5 + col_a]
            encrypted += table[((row_b + 1) % 5) * 5 + col_b]
        else:  # Rectangle
            encrypted += table[row_a * 5 + col_b]
            encrypted += table[row_b * 5 + col_a]
    return encrypted

def playfair_decrypt(ciphertext, key):
    key = clean_text(key)
    # Prepare the Playfair table
    table = []
    seen = set()
    for char in key:
        if char not in seen and char in string.ascii_uppercase:
            seen.add(char)
            table.append(char)
    for char in string.ascii_uppercase:
        if char not in seen and char != 'J':
            seen.add(char)
            table.append(char)
    
    # Create bigrams
    bigrams = [ciphertext[i:i + 2] for i in range(0, len(ciphertext), 2)]
    decrypted = ''
    for bigram in bigrams:
        a, b = bigram[0], bigram[1]
        row_a, col_a = divmod(table.index(a), 5)
        row_b, col_b = divmod(table.index(b), 5)
        if row_a == row_b:  # Same row
            decrypted += table[row_a * 5 + (col_a - 1) % 5]
            decrypted += table[row_b * 5 + (col_b - 1) % 5]
        elif col_a == col_b:  # Same column
            decrypted += table[((row_a - 1) % 5) * 5 + col_a]
            decrypted += table[((row_b - 1) % 5) * 5 + col_b]
        else:  # Rectangle
            decrypted += table[row_a * 5 + col_b]
            decrypted += table[row_b * 5 + col_a]
    return decrypted

# 8. Keyless Transposition Cipher
def keyless_transposition_encrypt(plaintext):
    plaintext = clean_text(plaintext)
    n = len(plaintext)
    cols = int(n * 0.5) + (n % int(n * 0.5) > 0)
    grid = [''] * cols
    for i in range(n):
        grid[i % cols] += plaintext[i]
    return ''.join(grid)

def keyless_transposition_decrypt(ciphertext):
    n = len(ciphertext)
    cols = int(n ** 0.5)
    rows = n // cols + (n % cols > 0)
    grid = [''] * rows
    for i in range(n):
        grid[i // rows] += ciphertext[i]
    return ''.join(grid)

# 9. Keyed Transposition Cipher
def keyed_transposition_encrypt(plaintext, key):
    key = sorted(set(key), key=lambda k: key.index(k))  # Remove duplicates
    key_length = len(key)
    plaintext = clean_text(plaintext)
    
    cols = len(key)
    rows = len(plaintext) // cols + (len(plaintext) % cols > 0)
    grid = [''] * cols
    
    # Fill the grid column-wise
    for i in range(len(plaintext)):
        grid[i % cols] += plaintext[i]
    
    # Create the ciphertext by reading columns in key order
    ciphertext = ''
    for char in key:
        idx = key.index(char)
        ciphertext += grid[idx]
    return ciphertext

def keyed_transposition_decrypt(ciphertext, key):
    key = sorted(set(key), key=lambda k: key.index(k))  # Remove duplicates
    key_length = len(key)
    
    cols = len(key)
    rows = len(ciphertext) // cols + (len(ciphertext) % cols > 0)
    grid = [''] * cols
    
    # Distribute ciphertext in the grid
    for i in range(len(ciphertext)):
        grid[i % cols] += ciphertext[i]
    
    # Create the plaintext by reading rows in original order
    plaintext = ''
    for char in key:
        idx = key.index(char)
        plaintext += grid[idx]
    return plaintext

import math

# Utility function to clean text (remove spaces and convert to uppercase)
def clean_text(text):
    return text.replace(' ', '').upper()

# Keyless Transposition Cipher
def keyless_transposition_encrypt(plaintext):
    plaintext = clean_text(plaintext)
    cols = math.ceil(math.sqrt(len(plaintext)))  # Calculate number of columns
    grid = [''] * cols
    for i in range(len(plaintext)):
        grid[i % cols] += plaintext[i]
    return ''.join(grid)

def keyless_transposition_decrypt(ciphertext):
    ciphertext = clean_text(ciphertext)
    cols = math.ceil(math.sqrt(len(ciphertext)))
    rows = math.ceil(len(ciphertext) / cols)
    grid = [''] * rows
    k = 0
    for i in range(cols):
        for j in range(rows):
            if k < len(ciphertext):
                grid[j] += ciphertext[k]
                k += 1
    return ''.join(grid)
import math

# Utility function to clean text (remove spaces and convert to uppercase)
def clean_text(text):
    return text.replace(' ', '').upper()

# Keyless Transposition Cipher (already working fine)
def keyless_transposition_encrypt(plaintext):
    plaintext = clean_text(plaintext)
    cols = math.ceil(math.sqrt(len(plaintext)))  # Calculate number of columns
    grid = [''] * cols
    for i in range(len(plaintext)):
        grid[i % cols] += plaintext[i]
    return ''.join(grid)

def keyless_transposition_decrypt(ciphertext):
    ciphertext = clean_text(ciphertext)
    cols = math.ceil(math.sqrt(len(ciphertext)))
    rows = math.ceil(len(ciphertext) / cols)
    grid = [''] * rows
    k = 0
    for i in range(cols):
        for j in range(rows):
            if k < len(ciphertext):
                grid[j] += ciphertext[k]
                k += 1
    return ''.join(grid)

import math

# Utility function to clean text (remove spaces and convert to uppercase)
def clean_text(text):
    return text.replace(' ', '').upper()

# Keyless Transposition Cipher (already working fine)
def keyless_transposition_encrypt(plaintext):
    plaintext = clean_text(plaintext)
    cols = math.ceil(math.sqrt(len(plaintext)))  # Calculate number of columns
    grid = [''] * cols
    for i in range(len(plaintext)):
        grid[i % cols] += plaintext[i]
    return ''.join(grid)

def keyless_transposition_decrypt(ciphertext):
    ciphertext = clean_text(ciphertext)
    cols = math.ceil(math.sqrt(len(ciphertext)))
    rows = math.ceil(len(ciphertext) / cols)
    grid = [''] * rows
    k = 0
    for i in range(cols):
        for j in range(rows):
            if k < len(ciphertext):
                grid[j] += ciphertext[k]
                k += 1
    return ''.join(grid)

# Keyed Transposition Cipher (fixed implementation)
def keyed_transposition_encrypt(plaintext, key):
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    cols = len(key)
    rows = math.ceil(len(plaintext) / cols)
    
    # Padding plaintext with 'X' if necessary
    padded_plaintext = plaintext + 'X' * (rows * cols - len(plaintext))
    
    # Fill the grid row by row
    grid = [''] * rows
    k = 0
    for i in range(rows):
        for j in range(cols):
            grid[i] += padded_plaintext[k]
            k += 1

    # Sort the key to get the order of the columns
    key_order = sorted(range(len(key)), key=lambda x: key[x])

    # Read the grid column by column based on key order
    ciphertext = ''
    for col in key_order:
        for row in grid:
            ciphertext += row[col]

    return ciphertext

def keyed_transposition_decrypt(ciphertext, key):
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    cols = len(key)
    rows = math.ceil(len(ciphertext) / cols)

    # Sort the key to get the column order
    key_order = sorted(range(len(key)), key=lambda x: key[x])

    # Prepare grid with empty strings
    grid = [''] * rows
    for i in range(rows):
        grid[i] = [''] * cols

    # Fill the grid column by column based on key order
    index = 0
    for col in key_order:
        for row in range(rows):
            if index < len(ciphertext):
                grid[row][col] = ciphertext[index]
                index += 1

    # Read row by row to decrypt
    plaintext = ''.join(''.join(row) for row in grid).rstrip('X')  # Remove padding 'X'
    return plaintext

# Double Transposition Cipher (fixed implementation)
def double_transposition_encrypt(plaintext, key1, key2):
    # First transposition with key1
    first_transposition = keyed_transposition_encrypt(plaintext, key1)
    # Second transposition with key2
    second_transposition = keyed_transposition_encrypt(first_transposition, key2)
    return second_transposition

def double_transposition_decrypt(ciphertext, key1, key2):
    # First decryption with key2
    first_decryption = keyed_transposition_decrypt(ciphertext, key2)
    # Second decryption with key1
    second_decryption = keyed_transposition_decrypt(first_decryption, key1)
    return second_decryption


# CLI Interface
def cipher_menu():
    print("\nChoose a cipher:")
    print("1. Additive Cipher")
    print("2. Multiplicative Cipher")
    print("3. Affine Cipher")
    print("4. Monoalphabetic Substitution Cipher")
    print("5. Autokey Cipher")
    print("6. Vigenère Cipher")
    print("7. Playfair Cipher")
    print("8. Keyless Transposition Cipher")
    print("9. Keyed Transposition Cipher")
    print("10. Double Transposition Cipher")
    print("11. Exit")
    return input("Enter your choice (1-11): ")

def operation_menu():
    print("\n1. Encrypt")
    print("2. Decrypt")
    print("3. Back to main menu")
    return input("Choose an operation (1-3): ")

def cli():
    while True:
        cipher_choice = cipher_menu()

        if cipher_choice == "1":  # Additive Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = int(input("Enter the key (integer): "))
                    print(f"Encrypted text: {additive_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = int(input("Enter the key (integer): "))
                    print(f"Decrypted text: {additive_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "2":  # Multiplicative Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = int(input("Enter the key (integer, relatively prime to 26): "))
                    print(f"Encrypted text: {multiplicative_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = int(input("Enter the key (integer, relatively prime to 26): "))
                    print(f"Decrypted text: {multiplicative_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "3":  # Affine Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    a = int(input("Enter the 'a' key (integer, relatively prime to 26): "))
                    b = int(input("Enter the 'b' key (integer): "))
                    print(f"Encrypted text: {affine_encrypt(plaintext, a, b)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    a = int(input("Enter the 'a' key (integer, relatively prime to 26): "))
                    b = int(input("Enter the 'b' key (integer): "))
                    print(f"Decrypted text: {affine_decrypt(ciphertext, a, b)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "4":  # Monoalphabetic Substitution Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = input("Enter the substitution key (26 unique letters): ").upper()
                    print(f"Encrypted text: {monoalphabetic_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = input("Enter the substitution key (26 unique letters): ").upper()
                    print(f"Decrypted text: {monoalphabetic_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "5":  # Autokey Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Encrypted text: {autokey_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Decrypted text: {autokey_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "6":  # Vigenère Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Encrypted text: {vigenere_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Decrypted text: {vigenere_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "7":  # Playfair Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Encrypted text: {playfair_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Uppercase letters only): ").upper()
                    print(f"Decrypted text: {playfair_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "8":  # Keyless Transposition Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    print(f"Encrypted text: {keyless_transposition_encrypt(plaintext)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    print(f"Decrypted text: {keyless_transposition_decrypt(ciphertext)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "9":  # Keyed Transposition Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Unique letters): ").upper()
                    print(f"Encrypted text: {keyed_transposition_encrypt(plaintext, key)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key = input("Enter the key (Unique letters): ").upper()
                    print(f"Decrypted text: {keyed_transposition_decrypt(ciphertext, key)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "10":  # Double Transposition Cipher
            while True:
                operation = operation_menu()
                if operation == "1":  # Encrypt
                    plaintext = input("Enter the text to encrypt (Uppercase only): ").upper()
                    key1 = input("Enter the first key (Unique letters): ").upper()
                    key2 = input("Enter the second key (Unique letters): ").upper()
                    print(f"Encrypted text: {double_transposition_encrypt(plaintext, key1, key2)}")
                elif operation == "2":  # Decrypt
                    ciphertext = input("Enter the text to decrypt (Uppercase only): ").upper()
                    key1 = input("Enter the first key (Unique letters): ").upper()
                    key2 = input("Enter the second key (Unique letters): ").upper()
                    print(f"Decrypted text: {double_transposition_decrypt(ciphertext, key1, key2)}")
                elif operation == "3":  # Back to main menu
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif cipher_choice == "11":  # Exit
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    cli()
