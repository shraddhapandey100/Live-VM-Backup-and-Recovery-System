import socket
import os

def send_file(file_name, server_address, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_address, server_port))

    # Send the file name as bytes (UTF-8 encoded)
    client_socket.send(file_name.encode('utf-8'))

    save_directory = ''
    file_path = os.path.join(save_directory, file_name)

    with open(file_path, 'rb') as file:
        while True:
            data = file.read(1024)
            if not data:
                break
            client_socket.send(data)

    client_socket.close()

if __name__ == '__main__':
    file_name = 'Hello.txt'  # Replace with the file you want to send
    server_address = '192.168.43.27'  # Replace with the server's IP address
    server_port = 12345  # Port on which the server is listening

    send_file(file_name, server_address, server_port)