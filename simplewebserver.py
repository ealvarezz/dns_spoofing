import socket

try:

    host = ''
    port = 80

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    c.bind((host, port))

    c.listen(1)

    while True:
        
        client_connection, client_address = c.accept()
        print "Received from " + str(client_address)
        request = client_connection.recv(1024)
        client_connection.send('HTTP/1.0 200 OK\n\n')
        client_connection.send('<html><head><title>Welcome!</title></head>')
        client_connection.send('<body><h1>Thanks for your money!</h1></body></html>')
        client_connection.close()

except KeyboardInterrupt:
    print "Closing this wack server"
    client_connection.close()
