import ssl
import json
import sys
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore

client_socket = None

# Initialize colorama
init()

closed = False


def handle_messaging(peer_socket, peer_name, session_key):
    def receive_messages():
        global closed
        while True:
            try:
                if closed:
                    return
                encrypted_message = peer_socket.recv(1024)
                # Decrypt the message
                decrypted_message = decrypt_session_message(encrypted_message, session_key)
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
                if closed:
                    return
                user_input = input(Fore.LIGHTBLUE_EX + "You: ")
                if user_input == ":q":
                    closed = True
                    peer_socket.send(encrypt_session_message(user_input, session_key))
                    print("You have ended the chat.")
                    break
                # Encrypt the message
                encrypted_message = encrypt_session_message(user_input, session_key)
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


def encrypt_session_message(message, session_key):
    # Ensure the key is 8 bytes long (DES uses 8-byte keys)
    session_key = session_key.encode('utf-8').ljust(8, b'\0')  # Padding key to 8 bytes
    cipher = DES.new(session_key, DES.MODE_CBC)  # CBC mode
    padded_message = pad(message.encode('utf-8'), DES.block_size)  # Pad message to block size
    encrypted_message = cipher.encrypt(padded_message)
    return cipher.iv + encrypted_message  # Send the IV along with the message for decryption


def decrypt_session_message(encrypted_message, session_key):
    session_key = session_key.encode('utf-8').ljust(8, b'\0')  # Ensure key is 8 bytes long
    iv = encrypted_message[:8]  # Extract the IV from the beginning
    encrypted_message = encrypted_message[8:]  # Get the actual encrypted message
    cipher = DES.new(session_key, DES.MODE_CBC, iv)  # Use the same IV for decryption
    decrypted_message = unpad(cipher.decrypt(encrypted_message), DES.block_size)  # Remove padding
    return decrypted_message.decode('utf-8')


def encrypt_message_by_private(recipient_public_key_pem, message):
    """Encrypts a message using the recipient's public key with OAEP padding."""
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(  # Using OAEP padding for better security
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()


def decrypt_message_by_public(private_key_pem, encrypted_message_hex):
    """Decrypts a message using the private key with OAEP padding."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(  # Must match the padding used during encryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')


def register(conn, username, password):
    """Registers a new user with the server."""
    message = {
        "command": "REGISTER",
        "payload": {
            "username": username,
            "password": password
        }
    }
    try:
        send_command(conn, message)
        response = receive_response()
        if response and response.get('status', '').lower() == 'success':
            print(f"Server: {response.get('message')}")
        else:
            print(f"Server: {response.get('message', 'Registration failed.')}")
    except Exception as e:
        print(f"Error during registration: {e}")


def setup_client_socket():
    """
    Creates a global socket, binds it to a dynamic port, and starts a thread to listen for messages.
    Returns the dynamically assigned client IP and port.
    """
    global client_socket

    # Get the client IP dynamically
    client_ip = socket.gethostbyname(socket.gethostname())

    # Create a global socket with a dynamic port
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((client_ip, 0))  # Bind to any available port
    client_socket.listen(1)  # Set up the socket to listen for incoming connections

    # Get the dynamically assigned port
    client_port = client_socket.getsockname()[1]

    # Start a thread to listen for messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(client_socket,))
    listener_thread.daemon = True  # Ensure thread stops when the main program exits
    listener_thread.start()

    return client_ip, client_port


def listen_for_messages(sock):
    """
    Thread function to listen for incoming messages and handle the described sequence.
    """
    try:
        with open("client.key", "r") as f:
            private_key_pem = f.read()
    except FileNotFoundError:
        print("Private key file 'client.key' not found.")
        sys.exit(1)

    HEADER_SIZE = 20  # Fixed size for the header
    HEADER_IDENTIFIER = "SESSION_KEY"  # Unique identifier for session key messages

    print("Listening for incoming messages...")
    while True:
        try:
            conn, addr = sock.accept()  # Accept incoming connections
            print(f"Connection established with {addr}")

            while True:
                # Step 1: Receive the fixed-size header
                header = conn.recv(HEADER_SIZE).decode('utf-8').strip()
                if not header:
                    print(f"Connection closed by {addr}")
                    break

                # Step 2: Check the header identifier
                if header == HEADER_IDENTIFIER:
                    # Step 3: Receive the full message
                    full_message = conn.recv(1024)
                    print(f"Received encrypted session key message from {addr}.")

                    try:
                        # Step 4: Decrypt the message using the private key
                        decrypted_message = decrypt_message_by_public(private_key_pem, full_message.decode('utf-8'))
                        print(f"Decrypted message from {addr}: {decrypted_message}")

                        # Step 5: Parse the decrypted message to extract the session key
                        message_data = json.loads(decrypted_message)
                        session_key = message_data.get("session_key")
                        if session_key:
                            print(f"Extracted session key from {addr}: {session_key}")
                        else:
                            print(f"Session key not found in decrypted message from {addr}.")
                            continue

                        # Step 5: Send a challenge to Client A
                        challenge = "3 + 5"  # Example challenge
                        print(f"Sending challenge to {addr}: {challenge}")

                        # Encrypt challenge using the session key (if applicable)
                        encrypted_challenge = encrypt_session_message(challenge, session_key)
                        conn.sendall(encrypted_challenge)

                        # Step 6: Wait for and verify the solution
                        encrypted_solution = conn.recv(1024)
                        if not encrypted_solution:
                            print(f"Connection closed by {addr}")
                            break

                        # Decrypt the solution using the session key
                        solution = decrypt_session_message(encrypted_solution, session_key)
                        print(f"Received decrypted solution from {addr}: {solution}")

                        # Verify the solution
                        expected_solution = str(eval(challenge))
                        if solution == expected_solution:
                            print(f"Challenge solved correctly by {addr}.")
                            encrypted_ack = encrypt_session_message("Correct solution!", session_key)
                            conn.sendall(encrypted_ack)
                            handle_messaging(conn, "sender", session_key)

                        else:
                            print(f"Incorrect solution by {addr}.")
                            encrypted_ack = encrypt_session_message("Incorrect solution.", session_key)
                            conn.sendall(encrypted_ack)
                    except Exception as e:
                        print(f"Error decrypting the session key or handling challenge: {e}")
                        conn.sendall("Error handling session key.".encode('utf-8'))
                else:
                    print(f"Unknown message type from {addr} with header: {header}")
                    conn.sendall("Unknown message type.".encode('utf-8'))
        except BlockingIOError:
            # No incoming connection or data, continue
            pass
        except Exception as e:
            print(f"Error in listener thread: {e}")
            break


def login(conn, username, password):
    """
    Logs in an existing user, opens a global socket, and sends client IP and port to the server.
    """
    try:
        # Set up the client socket and start listening
        client_ip, client_port = setup_client_socket()

        # Prepare the login message
        message = {
            "command": "LOGIN",
            "payload": {
                "username": username,
                "password": password,
                "client_ip": client_ip,
                "client_port": client_port
            }
        }

        # Send the login command
        send_command(conn, message)
        response = receive_response()
        if response and response.get('status', '').lower() == 'success':
            print(f"Server: {response.get('message')}")
            return True
        else:
            print(f"Server: {response.get('message', 'Login failed.')}")
            return False
    except Exception as e:
        print(f"Error during login: {e}")
        return False


def request_session(conn, id_A, id_B):
    """Requests a secure session between two users."""
    message = {
        "command": "REQUEST_SESSION",
        "payload": {
            "id_A": id_A,
            "id_B": id_B
        }
    }
    try:
        send_command(conn, message)
        response = receive_response()
        if response and response.get('status', '').lower() == 'success':
            encrypted_messages = response.get('encrypted_messages', {})
            client_B_info = response.get('client_B_info', {})
            to_A = encrypted_messages.get('to_A')
            to_B = encrypted_messages.get('to_B')
            return to_A, to_B, client_B_info
        else:
            print(f"Server: {response.get('message', 'Session request failed.')}")
            return None, None, None
    except Exception as e:
        print(f"Error during session request: {e}")
        return None, None, None


def send_command(conn, message):
    """Sends a JSON-encoded command to the server."""
    try:
        conn.sendall(json.dumps(message).encode('utf-8'))
    except Exception as e:
        print(f"Error sending command: {e}")


def receive_response():
    """Receives and parses a JSON-encoded response from the server."""
    try:
        response = conn.recv(8192).decode('utf-8')
        print(f"Received raw response: {response}")  # Debugging aid
        response_data = json.loads(response)
        return response_data
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Received data: {response}")
        return None
    except Exception as e:
        print(f"Error receiving response: {e}")
        return None


def encrypt_with_session_key(session_key, message):
    """
    Encrypts a message using a session key.
    Note: XOR encryption is insecure. Replace with AES for production.
    """
    try:
        encrypted = ''.join(
            chr(b ^ session_key[i % len(session_key)]) for i, b in enumerate(message.encode('utf-8'))
        )
        return encrypted
    except Exception as e:
        print(f"Error encrypting with session key: {e}")
        return ""


def decrypt_with_session_key(session_key, encrypted_message):
    """
    Decrypts a message using a session key.
    Note: XOR decryption is insecure. Replace with AES for production.
    """
    try:
        decrypted = ''.join(
            chr(b ^ session_key[i % len(session_key)]) for i, b in enumerate(encrypted_message.encode('utf-8'))
        )
        return decrypted
    except Exception as e:
        print(f"Error decrypting with session key: {e}")
        return ""


def send_session_key(client_B_ip, client_B_port, session_key, to_B, id_B):
    """
    Sends the session key and handles challenge-response authentication with Client B.
    """
    HEADER_IDENTIFIER = "SESSION_KEY"

    try:
        with socket.create_connection((client_B_ip, client_B_port)) as client_B_conn:
            # Step 1: Send the session key message with a header
            header = f"{HEADER_IDENTIFIER:<20}"  # Fixed-size header with unique identifier
            client_B_conn.sendall(header.encode('utf-8') + to_B.encode('utf-8'))
            print(f"Sent session key message to Client B at {client_B_ip}:{client_B_port}.")

            # Step 2: Wait for the encrypted challenge from Client B
            encrypted_challenge = client_B_conn.recv(1024)
            if not encrypted_challenge:
                print(f"Connection closed by {client_B_ip}:{client_B_port}")
                return

            challenge = decrypt_session_message(encrypted_challenge, session_key)
            print(f"Received encrypted challenge from Client B: {challenge}")

            # Step 3: Solve the challenge
            try:
                solution = str(eval(challenge))
            except Exception as e:
                print(f"Error solving the challenge: {e}")
                solution = "Error"

            # Step 4: Encrypt the solution and send it back
            encrypted_solution = encrypt_session_message(solution, session_key)
            client_B_conn.sendall(encrypted_solution)
            print(f"Sent encrypted solution to Client B: {solution}")

            # Step 5: Wait for acknowledgment from Client B
            encrypted_ack = client_B_conn.recv(1024)
            acknowledgment = decrypt_session_message(encrypted_ack, session_key)
            print(f"Received acknowledgment from Client B: {acknowledgment}")
            if acknowledgment == "Correct solution!":
                handle_messaging(client_B_conn, "sender", session_key)

    except Exception as e:
        print(f"Error sending session key to Client B: {e}")


def communicate(conn, private_key_pem, session_keys):
    """Handles user commands and interactions."""
    while True:
        try:
            command = input("Enter command (session/exit): ").strip().lower()
            if command == "session":
                # After requesting session:
                id_A = input("Enter your username: ").strip()
                id_B = input("Enter recipient username: ").strip()
                to_A, to_B, client_B_info = request_session(conn, id_A, id_B)
                if to_A and to_B and client_B_info:
                    # Decrypt message1 with own private key to get session key
                    decrypted_message1 = decrypt_message_by_public(private_key_pem, to_A)
                    try:
                        message1 = json.loads(decrypted_message1)
                        session_key = message1.get("session_key")
                        if not session_key:
                            print("Session key not found in decrypted message.")
                            continue
                        print(f"Session key established with {id_B}.")

                        # Store session_key for future use
                        session_keys[id_B] = session_key

                        # Connect to client_B using IP and port
                        client_B_ip = client_B_info.get("ip")
                        client_B_port = int(client_B_info.get("port"))

                        send_session_key(client_B_ip, client_B_port, session_key, to_B, id_B)

                    except json.JSONDecodeError as e:
                        print(f"JSON decode error after decrypting message1: {e}")
                        print(f"Decrypted message1: {decrypted_message1}")
            elif command == "exit":
                message = {"command": "EXIT", "payload": {}}
                try:
                    send_command(conn, message)
                    response = receive_response()
                    if response and response.get('status', '').lower() == 'success':
                        print("Disconnecting from the server.")
                    else:
                        print(f"Server: {response.get('message', 'Failed to exit gracefully.')}")
                except Exception as e:
                    print(f"Error during exit: {e}")
                break
            else:
                print("Unknown command. Available commands: session, send, rotate, revoke, exit")
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received. Exiting.")
            break
        except Exception as e:
            print(f"Error during communication: {e}")
            break
    # Close the connection after exiting the loop
    try:
        conn.close()
    except:
        pass
    print("Client shut down.")


def start_client():
    """Initializes the client connection and starts the interaction."""
    host = '127.0.0.1'  # Server address
    port = 12345  # Server port

    # Configure SSL context for the client
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.pem')
    context.load_cert_chain(certfile='client.pem', keyfile='client.key')  # Client's cert and key

    # Enforce TLS versions
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Ensure that the server's hostname matches the certificate's SAN
    context.check_hostname = True

    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Wrap socket with SSL
        global conn  # Make conn global to be accessible in receive_response
        conn = context.wrap_socket(client_socket, server_hostname='localhost')  # 'localhost' matches SAN
        conn.connect((host, port))
        print("Connected to server with mTLS")
        print("Choose an option:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter choice (1/2/3): ").strip()

        if choice == '1':
            username = input("Enter desired username: ").strip()
            password = input("Enter desired password: ").strip()
            register(conn, username, password)
        elif choice == '2':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            success = login(conn, username, password)
            if success:
                print("You can now send messages. Type 'exit' to disconnect.")
                # Load private key
                try:
                    with open("client.key", "r") as f:
                        private_key_pem = f.read()
                except FileNotFoundError:
                    print("Private key file 'client.key' not found.")
                    conn.close()
                    sys.exit(1)
                # Initialize session keys dictionary
                session_keys = {}
                # Start communication
                communicate(conn, private_key_pem, session_keys)
            else:
                print("Login failed. Exiting.")
        elif choice == '3':
            message = {"command": "EXIT", "payload": {}}
            try:
                send_command(conn, message)
                response = receive_response()
                if response and response.get('status', '').lower() == 'success':
                    print("Disconnecting from the server.")
                else:
                    print(f"Server: {response.get('message', 'Failed to exit gracefully.')}")
            except Exception as e:
                print(f"Error during exit: {e}")
        else:
            print("Invalid choice. Exiting.")

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except ConnectionRefusedError:
        print("Connection refused. Ensure the server is running.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        print("Client shut down.")


if __name__ == "__main__":
    start_client()
