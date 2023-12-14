import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Rest of the code (excluding imports) remains the same


# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a file with RSA public key
def encrypt_file(file_path, public_key):
    try:
        # Read the file content
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the file content
        encrypted_data = public_key.encrypt(
            file_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create a new file with ".enc" extension
        encrypted_file_path = file_path + '.rsa'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        return encrypted_file_path
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred: {str(e)}")
        return None

# Decrypt a file with RSA private key
def decrypt_file(encrypted_file_path, private_key):
    try:
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Decrypt the file content
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Remove the '.enc' extension from the original file name
        decrypted_file_path = encrypted_file_path[:-4]

        # Write the decrypted data to a new file
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return decrypted_file_path
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred: {str(e)}")
        return None




# Create the main application window
root = tk.Tk()
root.title("File Encryption and Decryption GUI")

# Function to perform encryption and display the public key
def encrypt_and_display_key():
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()
    
    # Specify the path to the file you want to encrypt
    input_file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not input_file_path:
        return

    # Encrypt the file
    encrypted_file_path = encrypt_file(input_file_path, public_key)

    if encrypted_file_path:
        messagebox.showinfo("Encryption Successful", f"File encrypted and saved as '{encrypted_file_path}'")

        # Save the public key to a file
        private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Optionally, you can add encryption
    )

    key_file_path = filedialog.asksaveasfilename(title="Save Private Key", defaultextension=".pem")
    
    if key_file_path:
        with open(key_file_path, 'wb') as key_file:
            key_file.write(private_key_pem)

# Function to decrypt a file using a provided private key
def decrypt_using_key():
    # Specify the path to the encrypted file
    encrypted_file_path = filedialog.askopenfilename(title="Select an encrypted file to decrypt")
    if not encrypted_file_path:
        return

    # Prompt the user to enter the private key
    private_key_file = filedialog.askopenfilename(title="Select the private key file")
    if not private_key_file:
        messagebox.showwarning("Private Key", "Please select the private key file.")
        return

    try:
        # Load the private key from the selected file
        with open(private_key_file, 'rb') as key_file:
            private_key_pem = key_file.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        # Decrypt the file
        decrypted_file_path = decrypt_file(encrypted_file_path, private_key)

        if decrypted_file_path:
            messagebox.showinfo("Decryption Successful", f"File decrypted and saved as '{decrypted_file_path}'")

    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred: {str(e)}")

# Create buttons for file encryption, decryption, and key display
encrypt_button = tk.Button(root, text="Encrypt File and Display Public Key", command=encrypt_and_display_key)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File with Private Key", command=decrypt_using_key)
decrypt_button.pack(pady=5)

# Run the main event loop
root.mainloop()
