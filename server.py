import socket


def start_server():
    host = '127.0.0.1'  # Localhost
    port = 12345        # Arbitrary non-privileged port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server started on {host}:{port}")
    print("Waiting for a connection...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data or data.lower() == 'exit':
            print("Client has disconnected.")
            break
        print(f"Client: {data}")
        message = input("You: ")
        conn.send(message.encode('utf-8'))
        if message.lower() == 'exit':
            print("Closing connection.")
            break

    conn.close()
    server_socket.close()
    print("Server shut down.")


if __name__ == "__main__":
    start_server()
