import hashlib
import ssl
import json
import sys
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

class ChatClient:
    def __init__(self, server_host='127.0.0.1', server_port=12345):
        self.server_host = server_host
        self.server_port = server_port
        self.conn = None  # SSL-wrapped socket
        self.private_key_pem = ""
        self.session_keys = {}  # Stores session keys with other users
        self.running = True  # Flag to control the client loop
        self.in_session = False  # Flag to indicate if in messaging mode
        self.peer_socket = None  # Socket connected to the peer
        self.peer_name = ""  # Name of the peer
        self.receive_thread = None  # Thread for receiving messages
        self.session_established = threading.Event()  # Event to signal session establishment
        self.username = ""

    def start(self):
        """Initialize the client connection and start the interaction."""
        # Configure SSL context for the client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.pem')
        try:
            context.load_cert_chain(certfile='client.pem', keyfile='client.key')  # Client's cert and key
        except Exception as e:
            print(Fore.RED + f"Error loading certificates: {e}")
            sys.exit(1)

        # Enforce TLS versions
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Ensure that the server's hostname matches the certificate's SAN
        context.check_hostname = True

        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Wrap socket with SSL
            self.conn = context.wrap_socket(client_socket, server_hostname='localhost')  # 'localhost' matches SAN
            self.conn.connect((self.server_host, self.server_port))
            print(Fore.GREEN + "Connected to server with mTLS" + Fore.RESET)

            self.show_main_menu()

        except ssl.SSLError as e:
            print(Fore.RED + f"SSL error: {e}" + Fore.RESET)
        except ConnectionRefusedError:
            print(Fore.RED + "Connection refused. Ensure the server is running." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}" + Fore.RESET)
        finally:
            self.shutdown()

    def show_main_menu(self):
        """Display the main menu and handle user choices."""
        while self.running:
            print("\nChoose an option:")
            print("1. Register")
            print("2. Login")
            print("3. Exit")

            choice = input("Enter choice (1/2/3): ").strip()

            if choice == '1':
                self.handle_register()
            elif choice == '2':
                if self.handle_login():
                    # Start the input loop after successful login
                    self.input_loop()
            elif choice == '3':
                self.send_exit()
                break
            else:
                print(Fore.YELLOW + "Invalid choice. Please enter 1, 2, or 3." + Fore.RESET)

    def handle_register(self):
        """Handle user registration."""
        username = input("Enter desired username: ").strip()
        password = input("Enter desired password: ").strip()
        self.register_user(username, password)

    def handle_login(self):
        """Handle user login."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        success = self.login_user(username, password)
        if success:
            self.username = username
            print(Fore.GREEN + "Login successful." + Fore.RESET)
            # Load private key
            try:
                with open("client.key", "r") as f:
                    self.private_key_pem = f.read()
            except FileNotFoundError:
                print(Fore.RED + "Private key file 'client.key' not found." + Fore.RESET)
                self.running = False
                return False
            return True
        else:
            print(Fore.RED + "Login failed." + Fore.RESET)
            return False

    def input_loop(self):
        """Handle user commands and messaging."""
        while self.running:
            if not self.in_session:
                # Command mode
                prompt = "\nEnter command (session/exit): "
            else:
                # Messaging mode
                prompt = Fore.LIGHTBLUE_EX + "You: " + Fore.RESET

            try:
                user_input = input(prompt).strip()
            except EOFError:
                # Handle unexpected EOF (e.g., Ctrl+D)
                self.send_exit()
                break
            except KeyboardInterrupt:
                # Handle Ctrl+C gracefully
                self.send_exit()
                break

            # After receiving input, check the current session state
            if self.in_session:
                # Messaging mode: Treat input as a message
                if user_input == ":q":
                    self.send_message(":q")
                    self.in_session = False
                elif user_input:
                    self.send_message(user_input)
            else:
                # Command mode: Treat input as a command
                if user_input.lower() == "session":
                    self.start_session()
                    if self.in_session:
                        print(Fore.GREEN + "Session established. You can start messaging." + Fore.RESET)
                    else:
                        print(Fore.RED + "Session initiation failed." + Fore.RESET)
                elif user_input.lower() == "exit":
                    self.send_exit()
                    break
                else:
                    print(Fore.YELLOW + "Unknown command. Available commands: session, exit" + Fore.RESET)


    def start_session(self):
        """Initiate a session with another user."""
        id_A = self.username.strip()
        id_B = input("Enter recipient username: ").strip()
        to_A, to_B, client_B_info = self.request_session(id_A, id_B)
        if to_A and to_B and client_B_info:
            # Decrypt message1 with own private key to get session key
            decrypted_message1 = self.decrypt_message_by_private(self.private_key_pem, to_A)
            try:
                message1 = json.loads(decrypted_message1)
                session_key = message1.get("session_key")
                if not session_key:
                    print(Fore.RED + "Session key not found in decrypted message." + Fore.RESET)
                    return
                print(Fore.GREEN + f"Session key established with {id_B}." + Fore.RESET)

                # Store session_key for future use
                self.session_keys[id_B] = session_key

                # Connect to client_B using IP and port
                client_B_ip = client_B_info.get("ip")
                client_B_port = int(client_B_info.get("port"))

                # Establish connection to Client B
                self.connect_to_peer(client_B_ip, client_B_port, session_key, to_B, id_B)

            except json.JSONDecodeError as e:
                print(Fore.RED + f"JSON decode error after decrypting message1: {e}" + Fore.RESET)
                print(f"Decrypted message1: {decrypted_message1}")

    def connect_to_peer(self, client_B_ip, client_B_port, session_key, to_B, id_B):
        """Connect to the peer and perform challenge-response."""
        HEADER_IDENTIFIER = "SESSION_KEY"

        try:
            peer_socket = socket.create_connection((client_B_ip, client_B_port))
            self.peer_socket = peer_socket
            self.peer_name = id_B

            # Step 1: Send the session key message with a header
            header = f"{HEADER_IDENTIFIER:<20}"  # Fixed-size header with unique identifier
            encrypted_session_key = to_B.encode('utf-8')  # Assuming to_B is already encrypted
            peer_socket.sendall(header.encode('utf-8') + encrypted_session_key)
            print(Fore.GREEN + f"Sent session key message to Client B at {client_B_ip}:{client_B_port}." + Fore.RESET)

            # Step 2: Wait for the encrypted challenge from Client B
            encrypted_challenge = peer_socket.recv(1024)
            if not encrypted_challenge:
                print(Fore.RED + f"Connection closed by {client_B_ip}:{client_B_port}" + Fore.RESET)
                peer_socket.close()
                return

            challenge = self.decrypt_session_message(encrypted_challenge, session_key)
            print(Fore.CYAN + f"Received encrypted challenge from Client B: {challenge}" + Fore.RESET)

            # Step 3: Solve the challenge
            try:
                solution = str(eval(challenge))
            except Exception as e:
                print(Fore.RED + f"Error solving the challenge: {e}" + Fore.RESET)
                solution = "Error"

            # Step 4: Encrypt the solution and send it back
            encrypted_solution = self.encrypt_session_message(solution, session_key)
            peer_socket.sendall(encrypted_solution)
            print(Fore.GREEN + f"Sent encrypted solution to Client B: {solution}" + Fore.RESET)

            # Step 5: Wait for acknowledgment from Client B
            encrypted_ack = peer_socket.recv(1024)
            acknowledgment = self.decrypt_session_message(encrypted_ack, session_key)
            print(Fore.CYAN + f"Received acknowledgment from Client B: {acknowledgment}" + Fore.RESET)
            if acknowledgment == "Correct solution!":
                print(Fore.GREEN + "Challenge solved correctly. You are now connected." + Fore.RESET)
                self.in_session = True
                self.session_established.set()  # Signal that session is established
                # Start a thread to receive messages from the peer
                self.receive_thread = threading.Thread(target=self.receive_messages, args=(peer_socket, id_B, session_key), daemon=True)
                self.receive_thread.start()
            else:
                print(Fore.RED + "Incorrect solution. Connection terminated." + Fore.RESET)
                peer_socket.close()

        except Exception as e:
            print(Fore.RED + f"Error sending session key to Client B: {e}" + Fore.RESET)

    def request_session(self, id_A, id_B):
        """Requests a secure session between two users."""
        message = {
            "command": "REQUEST_SESSION",
            "payload": {
                "id_A": id_A,
                "id_B": id_B
            }
        }
        try:
            self.send_command(self.conn, message)
            response = self.receive_response()
            if response and response.get('status', '').lower() == 'success':
                encrypted_messages = response.get('encrypted_messages', {})
                client_B_info = response.get('client_B_info', {})
                to_A = encrypted_messages.get('to_A')
                to_B = encrypted_messages.get('to_B')
                return to_A, to_B, client_B_info
            else:
                print(Fore.RED + f"Server: {response.get('message', 'Session request failed.')}" + Fore.RESET)
                return None, None, None
        except Exception as e:
            print(Fore.RED + f"Error during session request: {e}" + Fore.RESET)
            return None, None, None

    def send_message(self, message):
        """Send a message to the peer."""
        if not self.peer_socket:
            print(Fore.RED + "No active session to send messages." + Fore.RESET)
            return
        session_key = self.session_keys.get(self.peer_name)
        print(
            Fore.BLUE + f"Attempting to send message to '{self.peer_name}' with session key: '{session_key}'" + Fore.RESET)  # Debugging
        if not session_key:
            print(Fore.RED + "Session key not found." + Fore.RESET)
            return
        try:
            # 1. Generate the hash of the message
            hash_obj = hashlib.sha256(message.encode('utf-8'))
            message_hash = hash_obj.digest()  # Get the hash as bytes

            # 2. Combine the message and its hash
            combined_data = message.encode('utf-8') + b"::" + message_hash

            # 3. Encrypt the combined data
            encrypted_message = self.encrypt_session_message(combined_data.decode('latin1'), session_key)

            # 4. Send the encrypted message
            self.peer_socket.sendall(encrypted_message)

            if message == ":q":
                self.in_session = False
                self.peer_socket.close()
                print(Fore.RED + "You have ended the chat." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"Error sending message: {e}" + Fore.RESET)
            self.in_session = False
            self.peer_socket.close()

    def receive_messages(self, peer_socket, peer_name, session_key):
        """Thread function to receive messages from the peer."""
        while self.running and self.in_session:
            try:
                encrypted_message = peer_socket.recv(1024)
                if not encrypted_message:
                    print(Fore.RED + f"{peer_name} disconnected." + Fore.RESET)
                    self.in_session = False
                    break

                # 1. Decrypt the message
                decrypted_data = self.decrypt_session_message(encrypted_message, session_key)
                if not decrypted_data:
                    print(Fore.RED + f"{peer_name} has ended the chat." + Fore.RESET)
                    print("\nEnter command (session/exit): ")
                    self.in_session = False
                    break

                # 2. Separate the message and hash
                try:
                    message, received_hash = decrypted_data.rsplit("::", 1)
                    if message == ":q":
                        print(Fore.RED + f"{peer_name} has ended the chat." + Fore.RESET)
                        print("\nEnter command (session/exit): ", end="")
                        self.in_session = False
                        break
                    received_hash_bytes = bytes(received_hash, encoding='latin1')
                except ValueError:
                    print(Fore.RED + "Malformed message received." + Fore.RESET)
                    continue

                # 3. Generate a new hash of the message
                computed_hash = hashlib.sha256(message.encode('utf-8')).digest()

                # 4. Verify integrity
                if received_hash_bytes != computed_hash:
                    print(Fore.RED + "Message integrity verification failed!" + Fore.RESET)
                else:
                    print(Fore.MAGENTA + f"{peer_name}: {message}" + Fore.RESET)
            except ConnectionResetError:
                print(Fore.RED + f"{peer_name} disconnected abruptly." + Fore.RESET)
                self.in_session = False
                break
            except Exception as e:
                self.in_session = False
                break
        peer_socket.close()

    def encrypt_session_message(self, message, session_key):
        """Encrypts a message using DES with the provided session key."""
        # Ensure the key is 8 bytes long (DES uses 8-byte keys)
        session_key_bytes = session_key.encode('utf-8')[:8]  # Truncate or pad to 8 bytes
        cipher = DES.new(session_key_bytes, DES.MODE_CBC)
        padded_message = pad(message.encode('utf-8'), DES.block_size)  # Pad message to block size
        encrypted_message = cipher.encrypt(padded_message)
        return cipher.iv + encrypted_message  # Send the IV along with the message for decryption

    def decrypt_session_message(self, encrypted_message, session_key):
        """Decrypts a message using DES with the provided session key."""
        try:
            session_key_bytes = session_key.encode('utf-8')[:8]  # Truncate or pad to 8 bytes
            iv = encrypted_message[:8]  # Extract the IV from the beginning
            encrypted_payload = encrypted_message[8:]  # Get the actual encrypted message
            cipher = DES.new(session_key_bytes, DES.MODE_CBC, iv)  # Use the same IV for decryption
            decrypted_padded = cipher.decrypt(encrypted_payload)
            decrypted_message = unpad(decrypted_padded, DES.block_size).decode('utf-8')
            return decrypted_message
        except ValueError:
            print(Fore.RED + "Incorrect decryption." + Fore.RESET)
            return ""
        except Exception as e:
            print(Fore.RED + f"Error during decryption: {e}" + Fore.RESET)
            return ""

    def decrypt_message_by_private(self, private_key_pem, encrypted_message_hex):
        """Decrypts a message using the private key with OAEP padding."""
        try:
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
        except Exception as e:
            print(Fore.RED + f"Error decrypting message with private key: {e}" + Fore.RESET)
            return ""

    def register_user(self, username, password):
        """Registers a new user with the server."""
        message = {
            "command": "REGISTER",
            "payload": {
                "username": username,
                "password": password
            }
        }
        try:
            self.send_command(self.conn, message)
            response = self.receive_response()
            if response and response.get('status', '').lower() == 'success':
                print(Fore.GREEN + f"Server: {response.get('message')}" + Fore.RESET)
            else:
                print(Fore.RED + f"Server: {response.get('message', 'Registration failed.')}" + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"Error during registration: {e}" + Fore.RESET)

    def login_user(self, username, password):
        """Logs in an existing user."""
        try:
            # Set up the client socket and start listening
            client_ip, client_port = self.setup_client_socket()

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
            self.send_command(self.conn, message)
            response = self.receive_response()
            if response and response.get('status', '').lower() == 'success':
                print(Fore.GREEN + f"Server: {response.get('message')}" + Fore.RESET)
                return True
            else:
                print(Fore.RED + f"Server: {response.get('message', 'Login failed.')}" + Fore.RESET)
                return False
        except Exception as e:
            print(Fore.RED + f"Error during login: {e}" + Fore.RESET)
            return False

    def setup_client_socket(self):
        """
        Creates a socket, binds it to a dynamic port, and starts a thread to listen for messages.
        Returns the dynamically assigned client IP and port.
        """
        # Get the client IP dynamically
        try:
            client_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            client_ip = '127.0.0.1'  # Fallback to localhost

        # Create a socket with a dynamic port
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind((client_ip, 0))  # Bind to any available port
        client_socket.listen(5)  # Listen for incoming connections

        # Get the dynamically assigned port
        client_port = client_socket.getsockname()[1]

        print(Fore.GREEN + f"Listening for incoming connections on {client_ip}:{client_port}" + Fore.RESET)

        # Start a thread to listen for messages
        listener_thread = threading.Thread(target=self.listen_for_messages, args=(client_socket,), daemon=True)
        listener_thread.start()

        return client_ip, client_port

    def listen_for_messages(self, sock):
        """
        Thread function to listen for incoming messages and handle the described sequence.
        """
        HEADER_SIZE = 20  # Fixed size for the header
        HEADER_IDENTIFIER = "SESSION_KEY"  # Unique identifier for session key messages

        print(Fore.YELLOW + "Listening for incoming messages..." + Fore.RESET)
        while self.running:
            try:
                conn, addr = sock.accept()  # Accept incoming connections
                print(Fore.GREEN + f"Connection established with {addr}" + Fore.RESET)

                # Step 1: Receive the fixed-size header
                header = conn.recv(HEADER_SIZE).decode('utf-8').strip()
                if not header:
                    print(Fore.RED + f"Connection closed by {addr}" + Fore.RESET)
                    conn.close()
                    continue

                # Step 2: Check the header identifier
                if header == HEADER_IDENTIFIER:
                    # Step 3: Receive the full message
                    full_message = conn.recv(1024)
                    print(Fore.CYAN + f"Received encrypted session key message from {addr}." + Fore.RESET)

                    try:
                        # Step 4: Decrypt the message using the private key
                        decrypted_message = self.decrypt_message_by_private(self.private_key_pem, full_message.decode('utf-8'))
                        print(Fore.CYAN + f"Decrypted message from {addr}: {decrypted_message}" + Fore.RESET)

                        # Step 5: Parse the decrypted message to extract the session key and id_A
                        message_data = json.loads(decrypted_message)
                        session_key = message_data.get("session_key")
                        id_A = message_data.get("id_A")
                        if not session_key or not id_A:
                            print(Fore.RED + f"Session key or id_A not found in decrypted message from {addr}." + Fore.RESET)
                            conn.close()
                            continue

                        print(Fore.GREEN + f"Extracted session key from {addr}: {session_key}" + Fore.RESET)

                        # Store session_key under id_A
                        self.session_keys[id_A] = session_key
                        self.peer_name = id_A
                        print(Fore.BLUE + f"Session keys updated: {self.session_keys}" + Fore.RESET)  # Debugging

                        # Step 5: Send a challenge to Client A
                        challenge = "3 + 5"  # Example challenge
                        print(Fore.CYAN + f"Sending challenge to {addr}: {challenge}" + Fore.RESET)

                        # Encrypt challenge using the session key
                        encrypted_challenge = self.encrypt_session_message(challenge, session_key)
                        conn.sendall(encrypted_challenge)

                        # Step 6: Wait for and verify the solution
                        encrypted_solution = conn.recv(1024)
                        if not encrypted_solution:
                            print(Fore.RED + f"Connection closed by {addr}" + Fore.RESET)
                            conn.close()
                            continue

                        # Decrypt the solution using the session key
                        solution = self.decrypt_session_message(encrypted_solution, session_key)
                        print(Fore.CYAN + f"Received decrypted solution from {addr}: {solution}" + Fore.RESET)

                        # Verify the solution
                        expected_solution = str(eval(challenge))
                        if solution == expected_solution:
                            print(Fore.GREEN + f"Challenge solved correctly by {addr}." + Fore.RESET)
                            encrypted_ack = self.encrypt_session_message("Correct solution!", session_key)
                            conn.sendall(encrypted_ack)
                            # Start messaging with the peer
                            self.session_established.set()  # Signal that session is established
                            self.in_session = True
                            self.peer_socket = conn
                            self.peer_name = message_data.get("id_A")  # Set to the actual sender's username
                            print(Fore.BLUE + f"Peer name set to: {self.peer_name}" + Fore.RESET)  # Debugging
                            # Start a thread to receive messages from the peer
                            self.receive_thread = threading.Thread(target=self.receive_messages, args=(conn, self.peer_name, session_key), daemon=True)
                            self.receive_thread.start()
                        else:
                            print(Fore.RED + f"Incorrect solution by {addr}." + Fore.RESET)
                            encrypted_ack = self.encrypt_session_message("Incorrect solution.", session_key)
                            conn.sendall(encrypted_ack)
                            conn.close()
                    except Exception as e:
                        print(Fore.RED + f"Error decrypting the session key or handling challenge: {e}" + Fore.RESET)
                        try:
                            conn.sendall("Error handling session key.".encode('utf-8'))
                        except:
                            pass
                        conn.close()
                else:
                    print(Fore.RED + f"Unknown message type from {addr} with header: {header}" + Fore.RESET)
                    try:
                        conn.sendall("Unknown message type.".encode('utf-8'))
                    except:
                        pass
                    conn.close()
            except Exception as e:
                print(Fore.RED + f"Error in listener thread: {e}" + Fore.RESET)
                break
        sock.close()


    def send_exit(self):
        """Send an exit command to the server and stop the client."""
        message = {"command": "EXIT", "payload": {}}
        try:
            self.send_command(self.conn, message)
            print(Fore.GREEN + "Disconnecting from the server." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"Error during exit: {e}" + Fore.RESET)
        self.running = False
        # Close peer connection if active
        if self.peer_socket:
            try:
                self.peer_socket.close()
            except:
                pass
        # Wait for receiving thread to finish
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join()

    def send_command(self, conn, message):
        """Sends a JSON-encoded command to the server."""
        try:
            conn.sendall(json.dumps(message).encode('utf-8'))
        except Exception as e:
            print(Fore.RED + f"Error sending command: {e}" + Fore.RESET)

    def receive_response(self):
        """Receives and parses a JSON-encoded response from the server."""
        try:
            response = self.conn.recv(8192).decode('utf-8')
            print(Fore.BLUE + f"Received raw response: {response}" + Fore.RESET)  # Debugging aid
            response_data = json.loads(response)
            return response_data
        except json.JSONDecodeError as e:
            print(Fore.RED + f"JSON decode error: {e}" + Fore.RESET)
            return None
        except Exception as e:
            print(Fore.RED + f"Error receiving response: {e}" + Fore.RESET)
            return None

    def shutdown(self):
        """Shut down the client gracefully."""
        self.running = False
        try:
            if self.conn:
                self.conn.close()
        except:
            pass
        print(Fore.RED + "Client shut down." + Fore.RESET)


if __name__ == "__main__":
    client = ChatClient()
    client.start()


