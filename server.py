import threading
import socket
import ssl
import pymongo
import hashlib
import os
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding  # Corrected import
from cryptography.hazmat.primitives import hashes
import generate_certs_crypto
from colorama import init, Fore


# Initialize colorama
init(autoreset=True)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "secure_comm"
COLLECTION_NAME = "users"

# Hashing Configuration
HASH_NAME = 'sha256'
ITERATIONS = 100000  # Number of iterations for key stretching


def connect_db():
    try:
        client = pymongo.MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        return collection
    except Exception as e:
        print(Fore.RED + f"Failed to connect to MongoDB: {e}" + Fore.RESET)
        sys.exit(1)


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # 16 bytes salt
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    pwd_hash = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    return {
        'salt': salt.hex(),
        'hash': pwd_hash.hex()
    }


def get_public_key_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    public_key = cert.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key.decode('utf-8')


def register_user(collection, username, password):
    # Check if username already exists
    if collection.find_one({"username": username}):
        return {"status": "error", "message": "Username already exists."}

    # Hash the password with salt
    hashed = hash_password(password)

    # Load CA certificate and key
    with open("ca.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open("ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    generate_certs_crypto.generate_certificate(username, username, ca_cert, ca_key, is_server=False)

        # Read the generated certificate from the file
    cert_filename = f"{username}.pem"
    with open(cert_filename, "rb") as f:
        cert_pem = f.read()
    # Extract public key from client certificate
    public_key = get_public_key_from_cert(cert_pem.decode('utf-8'))

    # Store user with hashed password, salt, and public key
    user = {
        "username": username,
        "password_hash": hashed['hash'],
        "salt": hashed['salt'],
        "public_key": public_key,
        "key_status": "active"
    }

    try:
        collection.insert_one(user)
        return {"status": "success", "message": "User registered successfully."}
    except Exception as e:
        return {"status": "error", "message": f"Registration failed: {e}"}


def login_user(collection, username, password, client_ip, client_port):
    # Find user by username
    user = collection.find_one({"username": username})
    if not user:
        return {"status": "error", "message": "Invalid username or password."}
    
    # Check if user is already logged in
    if user.get('logged_in', False):
        return {"status": "error", "message": "User already logged in."}

    # Retrieve salt and hash the input password
    salt = user.get('salt')
    if not salt:
        return {"status": "error", "message": "User data corrupted (missing salt)."}

    hashed_input = hash_password(password, salt)

    # Compare the hashed input with stored hash
    if hashed_input['hash'] != user.get('password_hash'):
        return {"status": "error", "message": "Invalid username or password."}
    
    # Update database with client IP and port
    try:
        collection.update_one(
            {"username": username},
            {"$set": {"client_ip": client_ip, "client_port": client_port, "logged_in": True}}
        )
    except Exception as e:
        return {"status": "error", "message": f"Failed to update client IP, port, and login status:: {e}"}

    return {"status": "success", "message": "Login successful."}


def handle_client(connstream, collection, connected_clients, lock):
    try:

        # Initialize authentication state
        authenticated = False
        username = None

        while True:
            # Receive data
            data = connstream.recv(8192).decode('utf-8')
            if not data:
                break  # Connection closed by client

            # Parse JSON message
            try:
                message = json.loads(data)
                command = message.get("command")
                payload = message.get("payload")
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Invalid JSON format."}
                connstream.sendall(json.dumps(response).encode('utf-8'))
                continue

            # Handle commands based on authentication state
            if not authenticated:
                if command == "REGISTER":
                    # Handle user registration
                    reg_username = payload.get("username")
                    reg_password = payload.get("password")
                    if not reg_username or not reg_password:
                        response = {"status": "error",
                                    "message": "Username and password are required for registration."}
                    else:
                        reg_response = register_user(collection, reg_username, reg_password);
                        response = reg_response
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "LOGIN":
                    # Handle user login
                    login_username = payload.get("username")
                    login_password = payload.get("password")
                    client_ip = payload.get("client_ip")
                    client_port = payload.get("client_port")
                    if not login_username or not login_password:
                        response = {"status": "error", "message": "Username and password are required for login."}
                    else:
                        login_response = login_user(collection, login_username, login_password,
                                                    client_ip, client_port)
                        if login_response['status'] == "success":
                            authenticated = True
                            username = login_username
                            with lock:
                                connected_clients[username] = connstream
                        response = login_response
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                else:
                    response = {"status": "error", "message": "Please register or login first."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

            else:
                if command == "REQUEST_SESSION":
                    # Handle session request
                    id_A = payload.get("id_A")
                    id_B = payload.get("id_B")
                    if not id_A or not id_B:
                        response = {"status": "error", "message": "Both id_A and id_B are required."}
                    else:
                        user_A = collection.find_one({"username": id_A, "key_status": "active"})
                        user_B = collection.find_one({"username": id_B, "key_status": "active"})
                        if not user_A or not user_B:
                            response = {"status": "error", "message": "User not found"}
                        else:
                            # Check if user_B has IP and port stored
                            client_ip = user_B.get("client_ip")
                            client_port = user_B.get("client_port")
                            if not client_ip or not client_port:
                                response = {"status": "error",
                                            "message": f"User {id_B} is not reachable (missing IP/port)."}
                            else:
                                # Generate a random session key (8 bytes for DES)
                                session_key = os.urandom(4).hex()
                                # Encrypt {id_A, id_B, session_key} with A's public key
                                message1 = json.dumps({
                                    "id_A": id_A,
                                    "id_B": id_B,
                                    "session_key": session_key
                                })
                                public_key_A = serialization.load_pem_public_key(user_A['public_key'].encode('utf-8'))
                                encrypted_message1 = public_key_A.encrypt(
                                    message1.encode('utf-8'),
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                ).hex()
                                # Encrypt {id_A, session_key} with B's public key
                                message2 = json.dumps({
                                    "id_A": id_A,
                                    "session_key": session_key
                                })
                                public_key_B = serialization.load_pem_public_key(user_B['public_key'].encode('utf-8'))
                                encrypted_message2 = public_key_B.encrypt(
                                    message2.encode('utf-8'),
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                ).hex()
                                # Send both encrypted messages to A along with B's IP and port
                                response = {
                                    "status": "success",
                                    "encrypted_messages": {
                                        "to_A": encrypted_message1,
                                        "to_B": encrypted_message2
                                    },
                                    "client_B_info": {
                                        "ip": client_ip,
                                        "port": client_port
                                    }
                                }
                    connstream.sendall(json.dumps(response).encode('utf-8'))

    except ssl.SSLError as e:
        print( Fore.RED +f"SSL error: {e}" + Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"An error occurred while handling client '{username}': {e}" + Fore.RESET)
    finally:
        if authenticated and username:
            with lock:
                if username in connected_clients:
                    del connected_clients[username]
                    collection.update_one({"username": username}, {"$set": {"logged_in": False}})
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except:
            pass
        connstream.close()
        print(Fore.GREEN + f"Connection with user '{username}' closed." + Fore.RESET)


def start_server():
    host = '127.0.0.1'  # Localhost
    port = 12345  # Arbitrary non-privileged port

    # Connect to MongoDB
    collection = connect_db()

    # Configure SSL context for the server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #context.verify_mode = ssl.CERT_NONE
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
    context.load_cert_chain(certfile='server.pem', keyfile='server.key')
    context.load_verify_locations(cafile='ca.pem')  # CA certificate to verify client

    # Enforce TLS versions
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Listen for up to 5 connections

    print(Fore.GREEN + f"Server started on {host}:{port}" + Fore.RESET)
    print(Fore.YELLOW + "Waiting for a connection..." + Fore.RESET)

    connected_clients = {}  # Dictionary to track active clients
    connected_clients_lock = threading.Lock()  # Thread lock for connected_clients

    while True:
        try:
            newsocket, fromaddr = server_socket.accept()
            print(Fore.GREEN + f"Connection established with {fromaddr}" + Fore.RESET)

            # Wrap the socket with SSL
            connstream = context.wrap_socket(newsocket, server_side=True)
            print(Fore.GREEN + "SSL established." + Fore.RESET)

            # Handle client in a separate thread
            client_thread = threading.Thread(target=handle_client,
                                             args=(connstream, collection, connected_clients, connected_clients_lock))
            client_thread.start()

        except KeyboardInterrupt:
            print(Fore.RED +  "\nServer is shutting down." + Fore.RESET)
            break
        except ssl.SSLError as e:
            print(Fore.RED + f"SSL error during connection: {e}" + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}" + Fore.RESET)

    server_socket.close()
    print(Fore.RED + "Server shut down." + Fore.RESET)


if __name__ == "__main__":
    start_server()
