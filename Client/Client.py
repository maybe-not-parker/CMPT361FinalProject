# client.py - client for the secure mail transfer program.
# For CMPT 361 Final Project
# Instructor: Mahdi D. Firoozjaei
# Authors: Gabriel Young, Ethan Stevenson, Parker Mack, Nicklas Luzia

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import socket
import sys

# Encryption / decryption helpers

def pad_16bytes(data):
    """
    What it does: Adds padding to the plaintext data to ensure its length is a multiple of 16 bytes for AES encryption.
    Parameters:
        data: the raw data to be padded
    Returns: the padded data as a string
    """
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def unpad_16bytes(data):
    """
    What it does: Removes the padding from the decrypted data after AES decryption.
    Parameters:
        data: the decrypted data with padding
    Returns: the original raw data with padding removed
    """
    padding_length = data[-1]
    return data[:-padding_length]


def aes_encrypt(data, sym_key):
    """
    What it does: perform AES encryption on the inputed data using the provided symmetric key.
    Parameters:
        data: the plaintext data to be encrypted
        sym_key: the symmetric key used for encryption
    Returns: the encrypted data as bytes with padding applied
    """
    cipher = AES.new(sym_key, AES.MODE_ECB)
    padded_data = pad_16bytes(data.encode("ascii"))
    return cipher.encrypt(padded_data)


def aes_decrypt(data, sym_key):
    """"
    What it does: Performs AES decryption on the input data using the provided symmetric key.
    Parameters:
        data: the encrypted data to be decrypted
        sym_key: the symmetric key used for decryption
    Returns: the decrypted data as a string with padding removed
    """
    cipher = AES.new(sym_key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    return unpad_16bytes(decrypted_data).decode("ascii")


# Send / receive helpers

def send(sock: socket.socket, message: bytes):
    """Sends raw data to the server with a length header."""

    sizeStr = "{:010d}".format(len(message)).encode("ascii")

    sock.sendall(sizeStr + message)


def send_str(sock: socket.socket, message: str):
    """Sends a string and its size to the server."""

    encodedMsg = message.encode("ascii")
    sizeStr = "{:010d}".format(len(encodedMsg)).encode("ascii") # Prepend the size of the message to the message

    sock.sendall(sizeStr + encodedMsg)


def recv_exact(sock: socket.socket, size: int):
    """Receives size bytes of data from the server."""

    data = b""

    while len(data) < size: # Loop to make sure the whole message is received
        packet = sock.recv(size - len(data))

        if not packet:  # Connection closed
            return None
            
        data += packet

    return data


def recv(sock: socket.socket):
    """
    Receives a message from the server, checking its size to
    ensure the whole message is received.
    """
    sizeHeader = recv_exact(sock, 10) # Message length header, in bytes

    if not sizeHeader:  # Connection closed
        return None
        
    size = int(sizeHeader.decode("ascii"))

    message = recv_exact(sock, size)
    return message


def recv_str(sock: socket.socket):
    """Receives a string from the server."""

    sizeHeader = recv_exact(sock, 10)

    if not sizeHeader:  # Connection closed
        return None
    
    size = int(sizeHeader.decode("ascii"))

    message = recv_exact(sock, size)
    return message.decode("ascii")


def send_encrypted(sock: socket.socket, message: str, sym_key: str):
    """
    What it does:
        Encrypts a message using the symmetric key and sends it.

        Note:
        - Uses placeholder encryption for now
        - Will be replaced with AES encryption

    Parameters:
        conn (socket) connection to client
        message (str) message to send
        sym_key (str) symmetric encryption key

    Returns:
        None
    """
    encrypted_message = aes_encrypt(message, sym_key)

    send(sock, encrypted_message)


def recv_decrypted(sock, sym_key):
    """
    What it does:
        Receives a message from the client and decrypts it.

        Note:
        - Uses placeholder decryption for now
        - Only receives one chunk (not safe for large messages)

    Parameters:
        conn (socket) connection to client
        sym_key (str) symmetric encryption key

    Returns:
        str decrypted message
    """
    data = recv(sock)
    return aes_decrypt(data, sym_key)


# Main logic helpers

def login(sock: socket.socket, server_pub):
    """
    Prompts the user for their login details and sends them to the server.

    Parameters:
        sock: The socket for the connection to the server
        server_pub: The server's public key

    Returns:
        A tuple containing the username and symmetric key on success and None if authentication failed.
    """
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    credentials = f"{username}:{password}"

    # Load this user's private key
    try:
        with open(f"{username}_private.pem", "rb") as f:
            client_priv = RSA.import_key(f.read())
    except:
        pass    # The server still expects a message from the user and will report a failure

    # Encrypt credentials and send
    cipher_rsa_enc = PKCS1_OAEP.new(server_pub)
    encrypted_creds = cipher_rsa_enc.encrypt(credentials.encode("ascii"))

    send(sock, encrypted_creds)

    # Receive symmetric key OR error message
    response = recv(sock)

    if response == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        sock.close()
        return None, None
    
    # Decrypt and return symmetric key
    cipher_rsa_dec = PKCS1_OAEP.new(client_priv)
    sym_key = cipher_rsa_dec.decrypt(response)

    send_encrypted(sock, "OK", sym_key)

    return username, sym_key


def send_email(sock: socket.socket, username: str, sym_key: bytes):
    """Sends an email either from a text file or user input."""

    message = recv_decrypted(sock, sym_key)
    print(message)
    
    recipients = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")[:100]

    body = ""

    from_file = input("Would you like to load contents from a file?(Y/N) ")

    if from_file.lower() == "y":
        filename = input("Enter filename: ")

        with open(filename, "r") as f:
            body = f.read()

    else:
        body = input("Enter message contents: ")

    body = body[:1000000]

    # Construct the email formatted with message details.
    email = f"From: {username}\nTo: {recipients}\nTitle: {title}\n" + \
        f"Content Length: {len(body)}\nContent:\n{body}"
    
    send_encrypted(sock, email, sym_key)

    print("The message is sent to the server.\n")


def view_inbox(sock: socket.socket, sym_key: bytes):
    """Displays the user's inbox."""

    inbox = recv_decrypted(sock, sym_key)

    print(inbox)

    send_encrypted(sock, "OK", sym_key)


def view_email(sock: socket.socket, sym_key: bytes):
    """Displays an email from the user's inbox."""

    message = recv_decrypted(sock, sym_key)
    print(message + ": ", end="")

    index = input()
    send_encrypted(sock, index, sym_key)

    email = recv_decrypted(sock, sym_key)   # Might also be an error message if index is invalid
    print(email + "\n")


def main(port):
    """
    Creates a socket and tries to connect to the server program.
    On success, enters a loop which lets the user interact with the server.
    """
    addr = input("Enter the server IP or name: ")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((addr, port))

    except socket.error as e:
        print(f"Error on socket setup: ", e)
        sys.exit(1)

    # Load the public server and private user keys
    with open("server_public.pem", "rb") as f:
        server_pub_key = RSA.import_key(f.read())

    # Main loop
    with sock:
        username, sym_key = login(sock, server_pub_key)

        running = True if sym_key else False

        with open("client1_private.pem", "rb") as f:
            client_priv_key = RSA.import_key(f.read())

        while running:
            menu = recv_decrypted(sock, sym_key)
            print(menu, end="")
            choice = input()

            send_encrypted(sock, choice, sym_key)

            match(choice):
                case "1":
                    send_email(sock, username, sym_key)

                case "2":
                    view_inbox(sock, sym_key)

                case "3":
                    view_email(sock, sym_key)

                case _:
                    print("The connection is terminated with the server.")
                    running = False


if __name__ == "__main__":
    main(13000)