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
        print(f"Failed to connect to MongoDB: {e}")
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


def register_user(collection, username, password, client_cert_pem):
    # Check if username already exists
    if collection.find_one({"username": username}):
        return {"status": "error", "message": "Username already exists."}

    # Hash the password with salt
    hashed = hash_password(password)

    # Extract public key from client certificate
    public_key = get_public_key_from_cert(client_cert_pem)

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


def login_user(collection, username, password, client_cert_pem, client_ip, client_port):
    # Find user by username
    user = collection.find_one({"username": username})
    if not user:
        return {"status": "error", "message": "Invalid username or password."}

    # Retrieve salt and hash the input password
    salt = user.get('salt')
    if not salt:
        return {"status": "error", "message": "User data corrupted (missing salt)."}

    hashed_input = hash_password(password, salt)

    # Compare the hashed input with stored hash
    if hashed_input['hash'] != user.get('password_hash'):
        return {"status": "error", "message": "Invalid username or password."}

    # Extract public key from client certificate
    public_key = get_public_key_from_cert(client_cert_pem)

    # Verify client public key matches the stored public key
    if public_key != user.get("public_key"):
        return {"status": "error", "message": "Client certificate does not match the registered user."}

    # Update database with client IP and port
    try:
        collection.update_one(
            {"username": username},
            {"$set": {"client_ip": client_ip, "client_port": client_port}}
        )
    except Exception as e:
        return {"status": "error", "message": f"Failed to update client IP and port: {e}"}

    return {"status": "success", "message": "Login successful."}



def handle_client(connstream, collection, connected_clients, lock):
    try:
        # Extract the client's certificate in PEM format
        client_cert = connstream.getpeercert(binary_form=True)
        client_cert_pem = ssl.DER_cert_to_PEM_cert(client_cert)

        # Extract public key from certificate
        client_public_key = get_public_key_from_cert(client_cert_pem)

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
                        reg_response = register_user(collection, reg_username, reg_password, client_cert_pem)
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
                        login_response = login_user(collection, login_username, login_password, client_cert_pem, client_ip, client_port)
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
                # Handle authenticated commands
                if command == "REGISTER":
                    response = {"status": "error", "message": "Already logged in."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "LOGIN":
                    response = {"status": "error", "message": "Already logged in."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "REQUEST_SESSION":
                    # Handle session request
                    id_A = payload.get("id_A")
                    id_B = payload.get("id_B")
                    if not id_A or not id_B:
                        response = {"status": "error", "message": "Both id_A and id_B are required."}
                    else:
                        user_A = collection.find_one({"username": id_A, "key_status": "active"})
                        user_B = collection.find_one({"username": id_B, "key_status": "active"})
                        if not user_A or not user_B:
                            response = {"status": "error", "message": "One or both users not found or key revoked."}
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

                elif command == "SEND_SESSION_KEY":
                    # Handle sending session key to B
                    recipient = payload.get("to")
                    encrypted_message2 = payload.get("message2")
                    if not recipient or not encrypted_message2:
                        response = {"status": "error", "message": "Recipient and message2 are required."}
                    else:
                        with lock:
                            recipient_conn = connected_clients.get(recipient)
                        if not recipient_conn:
                            response = {"status": "error", "message": "Recipient is not online."}
                        else:
                            # Forward the encrypted_message2 to B
                            forward_message = {
                                "command": "SESSION_KEY",
                                "payload": {
                                    "from": username,
                                    "message2": encrypted_message2
                                }
                            }
                            recipient_conn.sendall(json.dumps(forward_message).encode('utf-8'))
                            response = {"status": "success", "message": "Session key forwarded to recipient."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "CHALLENGE":
                    # Handle sending challenge to A
                    to_user = payload.get("to")
                    challenge = payload.get("challenge")
                    if not to_user or not challenge:
                        response = {"status": "error", "message": "Recipient and challenge are required."}
                    else:
                        with lock:
                            recipient_conn = connected_clients.get(to_user)
                        if not recipient_conn:
                            response = {"status": "error", "message": "Recipient is not online."}
                        else:
                            # Forward the challenge to A
                            forward_message = {
                                "command": "CHALLENGE",
                                "payload": {
                                    "from": username,
                                    "challenge": challenge
                                }
                            }
                            recipient_conn.sendall(json.dumps(forward_message).encode('utf-8'))
                            response = {"status": "success", "message": "Challenge forwarded to recipient."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "RESPONSE":
                    # Handle receiving response from A
                    to_user = payload.get("to")
                    response_msg = payload.get("response")
                    if not to_user or not response_msg:
                        response = {"status": "error", "message": "Recipient and response are required."}
                    else:
                        with lock:
                            recipient_conn = connected_clients.get(to_user)
                        if not recipient_conn:
                            response = {"status": "error", "message": "Recipient is not online."}
                        else:
                            # Forward the response to B
                            forward_message = {
                                "command": "RESPONSE",
                                "payload": {
                                    "from": username,
                                    "response": response_msg
                                }
                            }
                            recipient_conn.sendall(json.dumps(forward_message).encode('utf-8'))
                            response = {"status": "success", "message": "Response forwarded to recipient."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "ROTATE_KEYS":
                    # Handle key rotation from client
                    new_public_key = payload.get("new_public_key")
                    if not new_public_key:
                        response = {"status": "error", "message": "New public key is required."}
                    else:
                        # Update user's public key in the database
                        collection.update_one(
                            {"username": username},
                            {"$set": {"public_key": new_public_key}}
                        )
                        # Update connected_clients if necessary (not shown here)
                        response = {"status": "success", "message": "Key rotation successful."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

                elif command == "REVOKE_KEY":
                    # Handle key revocation from client
                    collection.update_one(
                        {"username": username},
                        {"$set": {"key_status": "revoked"}}
                    )
                    response = {"status": "success", "message": "Key revoked successfully."}
                    connstream.sendall(json.dumps(response).encode('utf-8'))
                    # Disconnect the user
                    print(f"User '{username}' has revoked their key. Disconnecting.")
                    break

                elif command == "EXIT":
                    # Handle client exit
                    print(f"User '{username}' has disconnected.")
                    break

                else:
                    response = {"status": "error", "message": f"Unknown command: {command}"}
                    connstream.sendall(json.dumps(response).encode('utf-8'))

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"An error occurred while handling client '{username}': {e}")
    finally:
        if authenticated and username:
            with lock:
                if username in connected_clients:
                    del connected_clients[username]
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except:
            pass
        connstream.close()
        print(f"Connection with user '{username}' closed.")


def start_server():
    host = '127.0.0.1'  # Localhost
    port = 12345  # Arbitrary non-privileged port

    # Connect to MongoDB
    collection = connect_db()

    # Configure SSL context for the server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
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

    print(f"Server started on {host}:{port}")
    print("Waiting for a connection...")

    connected_clients = {}  # Dictionary to track active clients
    connected_clients_lock = threading.Lock()  # Thread lock for connected_clients

    while True:
        try:
            newsocket, fromaddr = server_socket.accept()
            print(f"Connection established with {fromaddr}")

            # Wrap the socket with SSL
            connstream = context.wrap_socket(newsocket, server_side=True)
            print("SSL established.")

            # Handle client in a separate thread
            client_thread = threading.Thread(target=handle_client,
                                             args=(connstream, collection, connected_clients, connected_clients_lock))
            client_thread.start()

        except KeyboardInterrupt:
            print("\nServer is shutting down.")
            break
        except ssl.SSLError as e:
            print(f"SSL error during connection: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    server_socket.close()
    print("Server shut down.")


if __name__ == "__main__":
    start_server()
