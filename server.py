import socket
import json
import os
import sys
from datetime import datetime
import key_generator.py
PORT = 13000
BUFFER_SIZE = 4096



# Placeholder Crypto Helpers
def load_private_key(filename):
    """
    What it does: obtains the server's private key
    
    Parameters:
        filename: the name of the file that contains the server's private key
        
    Returns:
        Private key ()
    
    
    """
    with open(filename, "rb") as file:
        return RSA.import_key(file.read())
    
def load_public_key(filename):
"""
    What it does: obtains the server's public key
    
    Parameters:
        filename: the name of the file that contains the server's public key
        
    Returns:
        Public key ()
    
    
    """
    with open(filename, "rb") as file:
        return RSA.import_key(file.read())
        
def rsa_decrypt(key, data):
    """
    What it does: Performs RSA decryption using the provided key and data.
    Parameters:
        key: the RSA key to use for decryption
        data: the encrypted data to be decrypted
    returns: the decrypted data as a string 
    """
    data_decoded = PKCS1_OAEP.new(key)
    return data_decoded.decrypt(data).decode()


def rsa_encrypt(key, data):
    """
    What it does: performs RSA encrpytion using the provided key and data.
    Parameters:
        key: the rsa key used for Encryption
        data: the plaintext data to be encrypted
    returns: the encrypted data
""""
    data_encoded = PKCS1_OAEP.new(key)
    return data_encoded.encrypt(data)

def 16byte_pad(data):
    """
    What it does: Adds padding to the plaintext data to ensure its length is a multiple of 16 bytes for AES encryption.
    Parameters:
        data: the plaintext data to be padded
    Returns: the padded data as a string
    """
    padding_length = 16 - (len(data) % 16)
    padding = chr(padding_length) * padding_length
    return data + padding

def 16byte_unpad(data):
    """
    What it does: Removes the padding from the decrypted data after AES decryption.
    Parameters:
        data: the decrypted data with padding
    Returns: the original plaintext data with padding removed
    """
    padding_length = ord(data[-1])
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
    padding = 16byte_pad(data)
    return cipher.encrpyt(padding.encode())


def aes_decrypt(data, sym_key):
    """"
    What it does: Performs AES decryption on the input data using the provided symmetric key.
    Parameters:
        data: the encrypted data to be decrypted
        sym_key: the symmetric key used for decryption
    Returns: the decrypted data as a string with padding removed

"""
    cipher = AES.new(sym_key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data).decode()
    return 16byte_unpad(decrypted_data)


def generate_sym_key():
    """
    Placeholder symmetric key.
    Replace later with real 256-bit AES key generation.
    """
    key = os.urandom(32) #aes 256
    return key

# File / User Setup Helpers

def load_users():
    """
    What it does:
        Loads all username/password pairs from user_pass.json.

    Parameters:
        None

    Returns:
        dict → {username: password}
        Returns empty dict if file is missing or invalid.
    """
    try:
        infile = open("user_pass.json", "r")
        users = json.load(infile)
        infile.close()
        return users
    except FileNotFoundError:
        print("Error: user_pass.json not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: user_pass.json is invalid.")
        return {}


def ensure_user_folders(users):
    """
    What it does:
        Creates a folder for each user if it does not already exist.

    Parameters:
        users (dict) → dictionary of usernames

    Returns:
        None
    """
    for username in users:
        if not os.path.exists(username):
            os.mkdir(username)


def validate_user(username, password, users):
    """
    What it does:
        Checks if the provided username and password are valid.

    Parameters:
        username (str) username from client
        password (str) password from client
        users (dict) dictionary of valid users

    Returns:
        bool True if valid, False otherwise
    """
    if username in users:
        if users[username] == password:
            return True
    return False

# Message Send and Receive

def send_text(conn: socket.socket, message: str):
    """
    What it does:
        Sends a plain (unencrypted) message to the client.

    Parameters:
        conn (socket) connection to client
        message (str) message to send

    Returns:
        None
    """
    encodedMsg = message.encode("ascii")
    sizeStr = "{:010d}".format(len(encodedMsg)).encode("ascii") # Add size to the message

    conn.sendall(sizeStr + encodedMsg)


def recv_exact(conn: socket.socket, size: int):
    """Receives and returns exactly size bytes of data."""
    
    data = b""

    while len(data) < size: # Loop to make sure the whole message is received
        packet = conn.recv(size - len(data))

        if not packet:  # Connection closed
            return None
            
        data += packet

    return data


def recv(conn: socket.socket):
    """
    Receives a message from the client, checking its size to
    ensure the whole message is received.
    """
    sizeHeader = recv_exact(conn, 10) # Message length header, in bytes

    if not sizeHeader:  # Connection closed
        return None
        
    size = int(sizeHeader.decode("ascii"))

    message = recv_exact(conn, size)
    return message


def recv_text(conn: socket.socket):
    """
    What it does:
        Receives a plain (unencrypted) message from the client.

    Parameters:
        conn (socket) connection to client

    Returns:
        str received message
    """
    data = recv(conn)
    return data.decode()


def send_encrypted(conn: socket.socket, message: str, sym_key: str):
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

    sizeHeader = "{:010d}".format(len(encrypted_message)).encode()

    conn.sendall(sizeHeader + encrypted_message.encode())


def recv_decrypted(conn, sym_key):
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
    data = recv(conn).decode()
    return aes_decrypt(data, sym_key)


# Email Helpers

def clean_filename(text):
    """
    What it does:
        Removes characters that may cause problems in filenames.

    Parameters:
        text (str) text to clean

    Returns:
        str cleaned filename text
    """
    bad_chars = '\\/:*?"<>|'
    cleaned = ""

    i = 0
    while i < len(text):
        if text[i] not in bad_chars:
            cleaned += text[i]
        i += 1

    return cleaned


def parse_email(email_data):
    """
    What it does:
        Parses a raw email string received from the client.

    Parameters:
        email_data (str) raw email text

    Returns:
        dict containing parsed fields if valid
        None if required fields are missing or invalid
    """
    lines = email_data.split("\n")

    email_info = {
        "from": "",
        "to": [],
        "title": "",
        "content_length": 0,
        "content": ""
    }

    content_start = -1
    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("From:"):
            email_info["from"] = line[5:].strip()

        elif line.startswith("To:"):
            to_line = line[3:].strip()
            email_info["to"] = to_line.split(";")

        elif line.startswith("Title:"):
            email_info["title"] = line[6:].strip()

        elif line.startswith("Content Length:"):
            length_text = line[15:].strip()
            try:
                email_info["content_length"] = int(length_text)
            except ValueError:
                return None

        elif line.startswith("Content:"):
            content_start = i + 1
            break

        i += 1

    if email_info["from"] == "":
        return None
    if len(email_info["to"]) == 0:
        return None
    if email_info["title"] == "":
        return None
    if content_start == -1:
        return None

    content = ""
    i = content_start
    while i < len(lines):
        content += lines[i]
        if i < len(lines) - 1:
            content += "\n"
        i += 1

    email_info["content"] = content

    if len(email_info["content"]) != email_info["content_length"]:
        return None

    return email_info


def format_saved_email(sender, destinations, title, content, received_time):
    """
    What it does:
        Builds the email text that will be stored on the server.

    Parameters:
        sender (str) sender username
        destinations (list) recipient usernames
        title (str) email title
        content (str) email body
        received_time (str) server timestamp

    Returns:
        str formatted email text for saving
    """
    to_line = ""
    i = 0
    while i < len(destinations):
        to_line += destinations[i].strip()
        if i < len(destinations) - 1:
            to_line += ";"
        i += 1

    result = ""
    result += "From: " + sender + "\n"
    result += "To: " + to_line + "\n"
    result += "Title: " + title + "\n"
    result += "Content Length: " + str(len(content)) + "\n"
    result += "Time and Date: " + received_time + "\n"
    result += "Content:\n"
    result += content

    return result


def save_email(sender, destinations, title, email_data):
    """
    What it does:
        Saves the email into each destination user's folder as a file.

    Parameters:
        sender (str) username of sender
        destinations (list) list of recipient usernames
        title (str) email title
        email_data (str) full email content

    Returns:
        None
    """
    safe_title = clean_filename(title)
    timestamp_text = datetime.now().strftime("%Y%m%d_%H%M%S")

    i = 0
    while i < len(destinations):
        destination = destinations[i].strip()

        if destination != "" and os.path.exists(destination):
            filename = sender + "_" + safe_title + "_" + timestamp_text + ".txt"
            path = os.path.join(destination, filename)

            outfile = open(path, "w")
            outfile.write(email_data)
            outfile.close()

        i += 1


def parse_saved_email(path):
    """
    What it does:
        Reads and parses a saved email file from disk.

    Parameters:
        path (str) path to saved email file

    Returns:
        dict containing parsed fields
        None if file is invalid
    """
    try:
        infile = open(path, "r")
        file_data = infile.read()
        infile.close()
    except FileNotFoundError:
        return None

    lines = file_data.split("\n")

    email_info = {
        "from": "",
        "to": [],
        "title": "",
        "content_length": 0,
        "time_and_date": "",
        "content": ""
    }

    content_start = -1
    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("From:"):
            email_info["from"] = line[5:].strip()

        elif line.startswith("To:"):
            to_line = line[3:].strip()
            email_info["to"] = to_line.split(";")

        elif line.startswith("Title:"):
            email_info["title"] = line[6:].strip()

        elif line.startswith("Content Length:"):
            length_text = line[15:].strip()
            try:
                email_info["content_length"] = int(length_text)
            except ValueError:
                return None

        elif line.startswith("Time and Date:"):
            email_info["time_and_date"] = line[14:].strip()

        elif line.startswith("Content:"):
            content_start = i + 1
            break

        i += 1

    if content_start == -1:
        return None

    content = ""
    i = content_start
    while i < len(lines):
        content += lines[i]
        if i < len(lines) - 1:
            content += "\n"
        i += 1

    email_info["content"] = content

    if len(email_info["content"]) != email_info["content_length"]:
        return None

    return email_info


def get_inbox_list(username):
    """
    What it does:
        Retrieves parsed email information for all emails in the user's folder.

    Parameters:
        username (str) user whose inbox is being accessed

    Returns:
        list list of dictionaries containing email information
    """
    inbox = []

    if os.path.exists(username):
        filenames = os.listdir(username)

        i = 0
        while i < len(filenames):
            filename = filenames[i]
            path = os.path.join(username, filename)

            parsed_email = parse_saved_email(path)

            if parsed_email is not None:
                parsed_email["filename"] = filename
                inbox.append(parsed_email)

            i += 1

    # Sort inbox by received time/date
    inbox.sort(key=lambda email: email["time_and_date"])

    return inbox


def get_email_contents(username, index):
    """
    What it does:
        Retrieves the contents of a selected email by index.

    Parameters:
        username (str) user whose inbox is being accessed
        index (int) index of selected email

    Returns:
        str email contents OR error message if index is invalid
    """
    inbox = get_inbox_list(username)

    if index < 0 or index >= len(inbox):
        return "Invalid email index."

    filename = inbox[index]["filename"]
    path = os.path.join(username, filename)

    infile = open(path, "r")
    contents = infile.read()
    infile.close()

    return contents

# Menu Handlers

def handle_send_email(conn, username, sym_key):
    """
    What it does:
        Handles sending an email from the client to one or more recipients.

    Parameters:
        conn (socket) connection to client
        username (str) sender username
        sym_key (str) symmetric encryption key

    Returns:
        None
    """
    send_encrypted(conn, "Send the email", sym_key)

    email_data = recv_decrypted(conn, sym_key)

    print("Received email from", username)
    print(email_data)

    parsed_email = parse_email(email_data)

    if parsed_email is None:
        send_encrypted(conn, "Invalid email format.", sym_key)
        return

    if parsed_email["from"] != username:
        send_encrypted(conn, "Invalid sender.", sym_key)
        return

    destinations = parsed_email["to"]
    title = parsed_email["title"]
    content = parsed_email["content"]

    received_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    saved_email = format_saved_email(
        username,
        destinations,
        title,
        content,
        received_time
    )

    save_email(username, destinations, title, saved_email)

    send_encrypted(conn, "Email saved successfully.", sym_key)


def handle_inbox_list(conn, username, sym_key):
    """
    What it does:
        Sends the list of emails in the user's inbox to the client.

    Parameters:
        conn (socket) connection to client
        username (str) user whose inbox is being accessed
        sym_key (str) symmetric encryption key

    Returns:
        None
    """
    inbox = get_inbox_list(username)

    message = ""
    i = 0
    while i < len(inbox):
        message += str(i + 1) + ". "
        message += "From: " + inbox[i]["from"] + "    "
        message += "Date: " + inbox[i]["time_and_date"] + "    "
        message += "Title: " + inbox[i]["title"] + "\n"
        i += 1

    if message == "":
        message = "Inbox is empty."

    send_encrypted(conn, message, sym_key)

    ok_msg = recv_decrypted(conn, sym_key)
    print("Inbox acknowledgement from", username + ":", ok_msg)


def handle_view_email(conn, username, sym_key):
    """
    What it does:
        Sends the contents of a selected email to the client.

        Flow:
        1. Requests email index from client
        2. Receives selected index
        3. Retrieves corresponding email file
        4. Sends email contents

    Parameters:
        conn (socket) connection to client
        username (str) user whose inbox is being accessed
        sym_key (str) symmetric encryption key

    Returns:
        None
    """
    send_encrypted(conn, "the server request email index", sym_key)

    index_text = recv_decrypted(conn, sym_key)

    try:
        index_value = int(index_text) - 1
    except ValueError:
        send_encrypted(conn, "Invalid email index.", sym_key)
        return

    email_contents = get_email_contents(username, index_value)
    send_encrypted(conn, email_contents, sym_key)
    
# Client Session

def handle_client(conn, users):
    """
    What it does:
        Handles the full interaction with one client.

        Flow:
        1. Receives encrypted login credentials
        2. Decrypts and validates username/password
        3. Generates symmetric key for session
        4. Sends symmetric key to client
        5. Waits for client acknowledgement

        Note:
        - Login parsing is placeholder
        - Encryption functions are placeholders

    Parameters:
        conn (socket) connection to client
        users (dict) dictionary of valid username/password pairs

    Returns:
        None
    """
    username = ""
    sym_key = ""
    server_private_key = load_private_key("server_private.pem")
    #Login Phase
    #login_data = recv_text(conn)
    #login_data = rsa_decrypt(login_data)
    login_data = conn.recv(BUFFER_SIZE)
    login_data = rsa_decrypt(server_private_key, login_data)

    # Placeholder login parsing:
    # expected format: username\npassword
    parts = login_data.split("\n")
    if len(parts) >= 2:
        username = parts[0].strip()
        password = parts[1].strip()
    else:
        send_text(conn, "Invalid username or password")
        conn.close()
        return

    if not validate_user(username, password, users):
        print("Invalid connection attempt.")
        send_text(conn, "Invalid username or password")
        conn.close()
        return

    sym_key = generate_sym_key()
    public_key = load_public_key(f"{username}_public.pem")
    encrypted_key = rsa_encrypt(public_key, sym_key)
    #send_text(conn, encrypted_key)
    conn.sendall(encrypted_key)

    print("Connection Accepted and Symmetric Key Generated for client:", username)

    ok_message = recv_decrypted(conn, sym_key)
    print("Client acknowledgement:", ok_message)

    # Menu Loop
    running = True
    while running:
        menu = "Select the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\n"
        send_encrypted(conn, menu, sym_key)

        choice = recv_decrypted(conn, sym_key).strip()

        if choice == "1":
            handle_send_email(conn, username, sym_key)
        elif choice == "2":
            handle_inbox_list(conn, username, sym_key)
        elif choice == "3":
            handle_view_email(conn, username, sym_key)
        elif choice == "4":
            print("Terminating connection with", username + ".")
            running = False
        else:
            send_encrypted(conn, "Invalid menu choice.", sym_key)

    conn.close()


# Main Server


def main():
    """
    What it does:
        Initializes and runs the server.

        Flow:
        1. Loads user credentials
        2. Creates user folders if needed
        3. Sets up TCP socket on specified port
        4. Waits for incoming client connections
        5. Uses fork() to handle multiple clients concurrently

    Parameters: None

    Returns: None
    """
    #generators the public and private keys from the key_generator.py file if they do not already exist
    key_generator.main()
    # Load valid users from JSON file
    users = load_users()
    # Ensure each user has a folder for storing emails
    ensure_user_folders(users)
    # Create TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket to all network interfaces on given port
    server_socket.bind(("", PORT))
    # Start listening for incoming connections (max 5 queued)
    server_socket.listen(5)
    print("Server is listening on port", PORT)
    while True:
        # Accept new client connection
        conn, addr = server_socket.accept()
        print("Connection received from", addr)
        # Create a new process to handle this client
        pid = os.fork()
        if pid == 0:
            # Child process handles the client
            # Close the listening socket in child (not needed here)
            server_socket.close()
            # Handle full client session
            handle_client(conn, users)
            # Exit child process after handling client
            sys.exit(0)
        else:
            # Parent process continues listening for new clients
            # Close client connection in parent (child handles it)
            conn.close()


if __name__ == "__main__":
    main() 
