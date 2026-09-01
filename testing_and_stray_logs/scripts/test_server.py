import socketserver

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"Connection from: {self.client_address[0]}")
        self.request.sendall(b"Hello, the connection is working!\n")
        print("Sent 'Hello' message and closing connection.")

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 3306
    socketserver.TCPServer.allow_reuse_address = True
    print(f"Starting simple test server on port {PORT}...")
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
