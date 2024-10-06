import tkinter as tk
from tkinter import messagebox
from NtruEncrypt import *
from Polynomial import Zx
from num_to_polynomial import *

# Define NTRU parameters
p = 3
q = 128
d = 5
stored_private_key = None  # Initialize stored_private_key
stored_N = None  # Initialize stored_N

# Function to encode the message
def encode_message(message, a, b):
    try:
        character_polynomials, N = koblitz_encoder(message, a, b)
        return character_polynomials, N
    except Exception as e:
        messagebox.showerror("Error", f"Encoding error: {e}")
        return None, None

# Function to generate public and private keys
def generate_keys(p, q, d, N):
    try:
        public_key, private_key = generate_keypair(p, q, d, N)
        return public_key, private_key
    except Exception as e:
        messagebox.showerror("Error", f"Key generation error: {e}")
        return None, None

# Function to encrypt the message
def encrypt_message(character_polynomials, public_key, d, N, q):
    cipher_polys = []
    for element in character_polynomials:
        cipher_text = encrypt(element, public_key, d, N, q)
        cipher_polys.append(cipher_text)
    return cipher_polys

# Function to decrypt the message
def decrypt_message(cipher_polys, private_key, p, q, N):
    dec_w = []
    for element in cipher_polys:
        decrypted_message = decrypt(element, private_key, p, q, N)
        dec_w.append(decrypted_message.coeffs)
    return dec_w

# Function to display decrypted message
def print_decrypted_message(dec_w):
    try:
        decrypted_plain_text = koblitz_decoder(points_decoder(dec_w))
        messagebox.showinfo("Decrypted Message", decrypted_plain_text)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption error: {e}")

# Function to format the ciphered text
def format_ciphered_text(cipher_polys):
    formatted_polynomials = []
    for cipher_text in cipher_polys:
        formatted_polynomials.append(' '.join(map(str, cipher_text.coeffs)))
    return '; '.join(formatted_polynomials)

# Function to parse polynomial string and extract coefficients
def parse_polynomial(polynomial_str):
    polynomial_str = polynomial_str.replace('-', '+-')
    terms = polynomial_str.split('+')
    coefficients = []
    for term in terms:
        if 'x' in term:
            coeff = term.split('x')[0]
            coefficients.append(int(coeff) if coeff != '' and coeff != '-' else -1)
        elif term:
            coefficients.append(int(term))
    return coefficients

# Function to handle encrypting
def encrypt_action(message, a, b):
    character_polynomials, N = encode_message(message, a, b)
    if character_polynomials is None:
        return

    public_key, private_key = generate_keys(p, q, d, N)
    if public_key is None or private_key is None:
        return

    public_key_str = public_key.print_polynomial()
    cipher_polys = encrypt_message(character_polynomials, public_key, d, N, q)
    encrypted_text = format_ciphered_text(cipher_polys)

    return public_key_str, encrypted_text, private_key, N  # Return N as well

# Function to handle decrypting
def decrypt_action(public_key_input, ciphered_text_input, N):  # Accept N as a parameter
    public_key = Zx(parse_polynomial(public_key_input))
    cipher_polys = [Zx([int(coeff) for coeff in poly.split()]) for poly in ciphered_text_input.split(';')]

    dec_w = decrypt_message(cipher_polys, stored_private_key, p, q, N)  # Pass N here
    print_decrypted_message(dec_w)

# Function to go back to the main menu
def back_to_menu(window):
    window.destroy()
    main_menu()

# Function to create the first menu
def main_menu():
    menu = tk.Tk()
    menu.title("NTRU Cryptography")
    menu.geometry("400x300")
    menu.configure(bg="#f0f0f0")

    welcome_label = tk.Label(menu, text="Welcome to Advanced Quantum Cryptography", bg="#f0f0f0", font=("Arial", 16))
    welcome_label.pack(pady=10)

    options_label = tk.Label(menu, text="What do you want to do?", bg="#f0f0f0", font=("Arial", 14))
    options_label.pack(pady=10)

    encrypt_button = tk.Button(menu, text="Encrypt", command=lambda: open_encrypt_window(menu), bg="#4CAF50", fg="white")
    encrypt_button.pack(pady=5)

    decrypt_button = tk.Button(menu, text="Decrypt", command=lambda: open_decrypt_window(menu), bg="#F44336", fg="white")
    decrypt_button.pack(pady=5)

    exit_button = tk.Button(menu, text="Exit", command=menu.quit, bg="#2196F3", fg="white")
    exit_button.pack(pady=5)

    menu.mainloop()

# Function to open encrypt window
def open_encrypt_window(menu):
    menu.destroy()
    encrypt_window = tk.Tk()
    encrypt_window.title("Encrypt Message")
    encrypt_window.geometry("400x400")
    encrypt_window.configure(bg="#f0f0f0")

    message_label = tk.Label(encrypt_window, text="Message:", bg="#f0f0f0")
    message_label.pack(pady=5)

    message_entry = tk.Entry(encrypt_window, width=50)
    message_entry.pack(pady=5)

    a_label = tk.Label(encrypt_window, text="Elliptic A:", bg="#f0f0f0")
    a_label.pack(pady=5)

    a_entry = tk.Entry(encrypt_window, width=50)
    a_entry.pack(pady=5)

    b_label = tk.Label(encrypt_window, text="Elliptic B:", bg="#f0f0f0")
    b_label.pack(pady=5)

    b_entry = tk.Entry(encrypt_window, width=50)
    b_entry.pack(pady=5)

    # Create text widgets for displaying results
    public_key_text = tk.Text(encrypt_window, height=5, width=50, bg="#ffffff")
    public_key_text.pack(pady=5)

    encrypted_text_text = tk.Text(encrypt_window, height=5, width=50, bg="#ffffff")
    encrypted_text_text.pack(pady=5)

    def encrypt_and_display():
        global stored_N  # Declare stored_N as global
        message = message_entry.get()
        elliptic_a = int(a_entry.get())
        elliptic_b = int(b_entry.get())

        result = encrypt_action(message, elliptic_a, elliptic_b)
        if result:
            public_key_str, encrypted_text, private_key, N = result  # Get N here
            public_key_text.delete(1.0, tk.END)  # Clear previous text
            public_key_text.insert(tk.END, public_key_str)  # Insert new public key

            encrypted_text_text.delete(1.0, tk.END)  # Clear previous text
            encrypted_text_text.insert(tk.END, encrypted_text)  # Insert new cipher text

            global stored_private_key
            stored_private_key = private_key

            stored_N = N  # Store N for decryption
            return N  # Return N for decryption

    encrypt_button = tk.Button(encrypt_window, text="Encrypt", command=encrypt_and_display, bg="#4CAF50", fg="white")
    encrypt_button.pack(pady=10)

    back_button = tk.Button(encrypt_window, text="Back to Menu", command=lambda: back_to_menu(encrypt_window), bg="#2196F3", fg="white")
    back_button.pack(pady=10)

    encrypt_window.mainloop()

# Function to open decrypt window
def open_decrypt_window(menu):
    menu.destroy()
    decrypt_window = tk.Tk()
    decrypt_window.title("Decrypt Message")
    decrypt_window.geometry("400x400")
    decrypt_window.configure(bg="#f0f0f0")

    public_key_label = tk.Label(decrypt_window, text="Public Key:", bg="#f0f0f0")
    public_key_label.pack(pady=5)

    public_key_entry = tk.Entry(decrypt_window, width=50)
    public_key_entry.pack(pady=5)

    ciphered_text_label = tk.Label(decrypt_window, text="Ciphered Text:", bg="#f0f0f0")
    ciphered_text_label.pack(pady=5)

    ciphered_text_entry = tk.Entry(decrypt_window, width=50)
    ciphered_text_entry.pack(pady=5)

    def decrypt_and_display():
        public_key_input = public_key_entry.get()
        ciphered_text_input = ciphered_text_entry.get()
        decrypt_action(public_key_input, ciphered_text_input, stored_N)  # Pass stored_N here

    decrypt_button = tk.Button(decrypt_window, text="Decrypt", command=decrypt_and_display, bg="#F44336", fg="white")
    decrypt_button.pack(pady=10)

    back_button = tk.Button(decrypt_window, text="Back to Menu", command=lambda: back_to_menu(decrypt_window), bg="#2196F3", fg="white")
    back_button.pack(pady=10)

    decrypt_window.mainloop()

if __name__ == "__main__":
    main_menu()
