import socket
import os

def receive_file():
    host = '0.0.0.0'  # Replace with the server's IP address
    port = 12345  # Choose a port for the server to listen on
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for one incoming connection

    print(f"Server listening on {host}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    file_name = client_socket.recv(1024).decode()
    file_size = int(client_socket.recv(1024).decode())

    print(f"Receiving file: {file_name} ({file_size} bytes)")

    with open(file_name, 'wb') as file:
        data = client_socket.recv(1024)
        while data:
            file.write(data)
            data = client_socket.recv(1024)

    print(f"File received successfully: {file_name}")

    client_socket.close()
    server_socket.close()

if __name__ == '__main__':
    receive_file()
