import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

text_entry = None
def open_algorithm_window():
    selected_algorithm = algorithm_var.get()
    if selected_algorithm == "AES":
        open_aes_window()
    elif selected_algorithm == "DES":
        open_des_window()
    elif selected_algorithm == "RSA":
        open_rsa_window()
    else:
        result_label.config(text="Invalid algorithm selected.")   


def open_aes_window():
    global key_entry
    aes_window = tk.Toplevel(window)
    aes_window.title("AES Encryption")

    # Labels and Entry widgets for AES
    key_label = tk.Label(aes_window, text="Enter AES Key:")
    key_label.grid(row=0, column=0, padx=10, pady=5)
    key_entry = tk.Entry(aes_window, show="*")  # Show asterisks for password entry
    key_entry.grid(row=0, column=1, padx=10, pady=5)

    file_label = tk.Label(aes_window, text="Select File for Encryption/Decryption:")
    file_label.grid(row=1, column=0, padx=10, pady=5)
    choose_file_button = tk.Button(aes_window, text="Choose File", command=lambda: choose_file_for_operation("both"))
    choose_file_button.grid(row=1, column=1, padx=10, pady=5)

    encrypt_button = tk.Button(aes_window, text="Encrypt", command=lambda: perform_aes_operation("encrypt", key_entry))
    encrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

    decrypt_button = tk.Button(aes_window, text="Decrypt", command=lambda: perform_aes_operation("decrypt", key_entry))
    decrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

    brute_force_aes_button = tk.Button(aes_window, text="Brute Force AES", command=brute_force_aes)
    brute_force_aes_button.grid(row=4, column=0, columnspan=2, pady=10)

# Global variables
key_entry = None
selected_file_path = None

def choose_file_for_operation(operation):
    global selected_file_path
    selected_file_path = filedialog.askopenfilename()
    if operation == "both":
        encrypt_file_label.config(text=f"Selected File for Encryption/Decryption: {selected_file_path}")

def perform_aes_operation(operation, key_entry):
    key = key_entry.get()

    if operation == "encrypt":
        if selected_file_path:
            encrypt_file(selected_file_path, key)
            
        else:
            result_label.config(text="No file selected for encryption.")
    elif operation == "decrypt":
        if selected_file_path:
            decrypt_file(selected_file_path, key)
        else:
            result_label.config(text="No file selected for decryption.")

def encrypt_file(file_path, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    with open(file_path, 'rb') as file:
        file_data = file.read()
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
    with open(file_path + "_encrypted", 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    result_label.config(text="File encrypted successfully.")

def decrypt_file(file_path, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(file_path + "_decrypted", 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    result_label.config(text="File decrypted successfully.")




def open_des_window():
    global key_entry, selected_file_path, text_entry  # Ajouter text_entry ici
    des_window = tk.Toplevel(window)
    des_window.title("DES Encryption")

    # Labels and Entry widgets for DES
    key_label = tk.Label(des_window, text="Enter DES Key:")
    key_label.grid(row=0, column=0, padx=10, pady=5)
    key_entry = tk.Entry(des_window, show="*")
    key_entry.grid(row=0, column=1, padx=10, pady=5)

    text_label = tk.Label(des_window, text="Enter Text to Encrypt/Decrypt:")
    text_label.grid(row=1, column=0, padx=10, pady=5)
    text_entry = tk.Entry(des_window)  # Retirer la redéfinition de text_entry
    text_entry.grid(row=1, column=1, padx=10, pady=5)

    encrypt_button = tk.Button(des_window, text="Encrypt", command=lambda: perform_des_operation("encrypt", key_entry, text_entry, DES))
    encrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

    decrypt_button = tk.Button(des_window, text="Decrypt", command=lambda: perform_des_operation("decrypt", key_entry, text_entry, DES))
    decrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

    brute_force_des_button = tk.Button(des_window, text="Brute Force DES", command=brute_force_des)
    brute_force_des_button.grid(row=4, column=0, columnspan=2, pady=10)


    

def perform_des_operation(operation, key_entry, text_entry, cipher_algorithm):
    key = key_entry.get()
    text = text_entry.get()

    if operation == "encrypt":
        cipher = cipher_algorithm.new(key.encode(), cipher_algorithm.MODE_ECB)
        padded_data = pad(text.encode(), cipher_algorithm.block_size)
        encrypted_data = b64encode(cipher.encrypt(padded_data)).decode()
        result_label.config(text=f"Encrypted Text: {encrypted_data}")
    elif operation == "decrypt":
        try:
            cipher = cipher_algorithm.new(key.encode(), cipher_algorithm.MODE_ECB)
            decrypted_data = cipher.decrypt(b64decode(text))
            unpadded_data = unpad(decrypted_data, cipher_algorithm.block_size)
            decrypted_text = unpadded_data.decode()
            result_label.config(text=f"Decrypted Text: {decrypted_text}")
        except ValueError as e:
            result_label.config(text=f"Decryption error: {str(e)}")





def open_rsa_window():
    global public_key_entry, private_key_entry, text_entry

    rsa_window = tk.Toplevel(window)
    rsa_window.title("RSA Encryption")

    # Labels and Entry widgets for RSA
    public_key_label = tk.Label(rsa_window, text="Public Key:")
    public_key_label.grid(row=0, column=0, padx=10, pady=5)
    public_key_entry = tk.Entry(rsa_window, width=40)
    public_key_entry.grid(row=0, column=1, padx=10, pady=5)

    private_key_label = tk.Label(rsa_window, text="Private Key:")
    private_key_label.grid(row=1, column=0, padx=10, pady=5)
    private_key_entry = tk.Entry(rsa_window, width=40)
    private_key_entry.grid(row=1, column=1, padx=10, pady=5)

    text_label = tk.Label(rsa_window, text="Enter Text to Encrypt/Decrypt:")
    text_label.grid(row=2, column=0, padx=10, pady=5)
    text_entry = tk.Entry(rsa_window, width=40)
    text_entry.grid(row=2, column=1, padx=10, pady=5)

    encrypt_button = tk.Button(rsa_window, text="Encrypt", command=lambda: perform_rsa_operation("encrypt"))
    encrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

    decrypt_button = tk.Button(rsa_window, text="Decrypt", command=lambda: perform_rsa_operation("decrypt"))
    decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

def perform_rsa_operation(operation):
    public_key_pem = public_key_entry.get()
    private_key_pem = private_key_entry.get()
    text = text_entry.get()

    try:
        if operation == "encrypt":
            ciphertext = encrypt_text_with_rsa(text, public_key_pem)
            result_label.config(text=f"Encrypted Text: {ciphertext.hex()}")
        elif operation == "decrypt":
            if private_key_pem:  # Ensure private key is provided
                decrypted_text = decrypt_text_with_rsa(bytes.fromhex(text), private_key_pem)
                result_label.config(text=f"Decrypted Text: {decrypted_text}")
            else:
                result_label.config(text="Private key not provided.")
    except Exception as e:
        result_label.config(text=f"Operation error: {str(e)}")

def encrypt_text_with_rsa(plaintext, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_text_with_rsa(ciphertext, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode()
import itertools
import string

def brute_force_aes_attack(encrypted_data):
    # Supposons que la clé AES soit de 16 caractères (128 bits)
    key_length = 16

    # Générer toutes les combinaisons possibles de clés
    all_possible_keys = [''.join(p) for p in itertools.product(string.ascii_letters + string.digits, repeat=key_length)]

    # Tester chaque clé
    for key in all_possible_keys:
        try:
            decrypt_file(encrypted_data, key)
            print(f"Key found: {key}")
            return key
        except Exception as e:
            # La clé n'est pas la bonne, continuer avec la suivante
            pass

    print("Force brute échouée. La clé n'a pas été trouvée.")
    return None

def brute_force_aes():
    try:
        encrypted_data = b64encode(open(selected_file_path, 'rb').read()).decode()
        key = brute_force_aes_attack(encrypted_data)
        if key:
            result_label.config(text=f"Brute Force AES Successful. Key found: {key}")
        else:
            result_label.config(text="Brute Force AES Failed. Key not found.")
    except Exception as e:
        result_label.config(text=f"Error during Brute Force AES: {str(e)}")
def decrypt_text_with_des(encrypted_text, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(b64decode(encrypted_text)), DES.block_size)
    decrypted_text = decrypted_data.decode()
    return decrypted_text


def brute_force_des_attack(encrypted_text):
    # Supposons que la clé DES soit de 8 caractères (64 bits)
    key_length = 8

    # Générer toutes les combinaisons possibles de clés
    all_possible_keys = [''.join(p) for p in itertools.product(string.ascii_letters + string.digits, repeat=key_length)]

    # Tester chaque clé
    for key in all_possible_keys:
        try:
            decrypted_text = decrypt_text_with_des(encrypted_text, key)
            print(f"Key found: {key}")
            return key
        except Exception as e:
            # La clé n'est pas la bonne, continuer avec la suivante
            pass

    print("Force brute échouée. La clé n'a pas été trouvée.")
    return None
 
def brute_force_des():
    global text_entry
    try:
        if text_entry is not None:
            encrypted_text = b64encode(text_entry.get().encode()).decode()
            key = brute_force_des_attack(encrypted_text)
            if key:
                result_label.config(text=f"Brute Force DES Successful. Key found: {key}")
            else:
                result_label.config(text="Brute Force DES Failed. Key not found.")
        else:
            result_label.config(text="Error: text_entry is not defined.")
    except Exception as e:
        result_label.config(text=f"Error during Brute Force DES: {str(e)}")



# Create the main window
window = tk.Tk()
window.title("Encryption Algorithm Chooser")
window.geometry("500x300")  # Set the size of the window

# Dropdown menu for algorithm selection (AES, DES, or RSA)
algorithm_var = tk.StringVar()
algorithm_var.set("AES")  # Default selection
algorithm_label = tk.Label(window, text="Select Encryption Algorithm:")
algorithm_label.pack(pady=10)
algorithm_menu = tk.OptionMenu(window, algorithm_var, "AES", "DES", "RSA")  # Include "RSA" in the options
algorithm_menu.pack(pady=10)




# Button to open the selected algorithm window
open_algorithm_window_button = tk.Button(window, text="Open Algorithm Window", command=open_algorithm_window)
open_algorithm_window_button.pack(pady=10)

# Label to display the result
result_label = tk.Label(window, text="", font=("Arial", 12, "bold"), fg="green")
result_label.pack(pady=10)

# Labels to display selected files for encryption and decryption
encrypt_file_label = tk.Label(window, text="Selected File for Encryption/Decryption: None")
encrypt_file_label.pack(pady=5)

# Start the main loop
window.mainloop()
