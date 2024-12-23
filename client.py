import socket


def start_client():
    host = '127.0.0.1'  # Server address
    port = 12345  # Server port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    print(f"Connected to server at {host}:{port}")
    print("Type 'exit' to disconnect.")

    while True:
        message = input("You: ")
        client_socket.send(message.encode('utf-8'))
        if message.lower() == 'exit':
            print("Disconnecting from the server.")
            break
        data = client_socket.recv(1024).decode('utf-8')
        if not data or data.lower() == 'exit':
            print("Server has closed the connection.")
            break
        print(f"Server: {data}")

    client_socket.close()
    print("Client shut down.")


if __name__ == "__main__":
    start_client()
