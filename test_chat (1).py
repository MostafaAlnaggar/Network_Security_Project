import socket
import threading
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore

# Initialize colorama
init()

closed = False
def handle_messaging(peer_socket, peer_name, session_key):
    def receive_messages():
        global closed
        while True:
            try:
                if closed == True:
                    return
                encrypted_message = peer_socket.recv(1024)
                # Decrypt the message
                decrypted_message = decrypt_message(encrypted_message, session_key)
                if not decrypted_message or decrypted_message == ":q":
                    print(Fore.RED + f"{peer_name} has ended the chat.")
                    closed = True
                    break
                print(f"{peer_name}: {decrypted_message}")
            except ConnectionResetError:
                print(f"{peer_name} disconnected.")
                break
        peer_socket.close()

    def send_messages():
        global closed
        while True:
            try:
                if closed == True:
                    return
                user_input = input(Fore.LIGHTBLUE_EX + "You: ")
                if user_input == ":q":
                    closed = True
                    peer_socket.send(encrypt_message(user_input, session_key))
                    print("You have ended the chat.")
                    break
                # Encrypt the message
                encrypted_message = encrypt_message(user_input, session_key)
                peer_socket.send(encrypted_message)
            except ConnectionResetError:
                print("Connection lost.")
                break
        peer_socket.close()

    # Start threads for sending and receiving messages
    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()

def encrypt_message(message, session_key):
    # Ensure the key is 8 bytes long (DES uses 8-byte keys)
    session_key = session_key.encode('utf-8').ljust(8, b'\0')  # Padding key to 8 bytes
    cipher = DES.new(session_key, DES.MODE_CBC)  # CBC mode
    padded_message = pad(message.encode('utf-8'), DES.block_size)  # Pad message to block size
    encrypted_message = cipher.encrypt(padded_message)
    return cipher.iv + encrypted_message  # Send the IV along with the message for decryption

def decrypt_message(encrypted_message, session_key):
    session_key = session_key.encode('utf-8').ljust(8, b'\0')  # Ensure key is 8 bytes long
    iv = encrypted_message[:8]  # Extract the IV from the beginning
    encrypted_message = encrypted_message[8:]  # Get the actual encrypted message
    cipher = DES.new(session_key, DES.MODE_CBC, iv)  # Use the same IV for decryption
    decrypted_message = unpad(cipher.decrypt(encrypted_message), DES.block_size)  # Remove padding
    return decrypted_message.decode('utf-8')

# Server Code
def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")

    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")
    session_key = "security"
    handle_messaging(client_socket, "Client", session_key)


# Client Code
def run_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 12345))
    print("Connected to the server.")
    session_key = "security"
    handle_messaging(client_socket, "Server", session_key)


# Main Entry Point
if __name__ == "__main__":
    role = input("Enter role (server/client): ").strip().lower()
    if role == "server":
        run_server()
    elif role == "client":
        run_client()
    else:
        print("Invalid role. Please enter 'server' or 'client'.")
