import socketserver
import requests
import json
import logging
import random

# ================= 1. CONFIGURATION =================
LLM_ENDPOINT = "http://localhost:8080/completion"
HOST, PORT = "0.0.0.0", 3306
LOG_FILENAME = 'mysql_honeypot.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILENAME),
        logging.StreamHandler()
    ]
)
SYSTEM_PROMPT = "You are a MySQL server. Respond to the SQL query."
# ====================================================

# ================= 2. LLM INTERACTION =================
def get_llm_response(query_text):
    full_prompt = f"""{SYSTEM_PROMPT}

Received SQL Query: `{query_text}`
MySQL Server Response (as a single, formatted text block):"""

    payload = {
        "prompt": full_prompt,
        "n_predict": 384,
        "temperature": 0.2,
        "stop": ["\n\n", "Received SQL Query:", "MySQL Server Response:"]
    }
    
    try:
        response = requests.post(LLM_ENDPOINT, json=payload, timeout=60)
        response_data = response.json()
        raw_text = response_data.get('content', '')
        
        # vv DEFINITIVE FIX: The Smart Re-formatter based on your idea vv
        if '\n' not in raw_text and ('|' in raw_text and '+' in raw_text):
            # 1. Add a newline between a closing pipe and a new plus: |+ -> |\n+
            reformatted_text = raw_text.replace('|+', '|\n+')
            # 2. Add a newline between a closing plus and a new pipe: +| -> +\n|
            reformatted_text = reformatted_text.replace('+|', '+\n|')
            return reformatted_text
        else:
            # If it's already multi-line, just normalize it
            lines = raw_text.splitlines()
            return "\n".join(lines)
        # ^^ DEFINITIVE FIX: The Smart Re-formatter based on your idea ^^
        
    except Exception as e:
        logging.error(f"llama-server connection error: {e}")
        return "ERROR 2013 (HY000): Lost connection to LLM server"

# ================= 3. SERVER HANDLER =================
class LLMMySQLServer(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        logging.info(f"New connection from: {client_ip}")

        connection_id = random.randint(10, 1000)
        server_version = "8.0.21-LLM-Honeypot"

        welcome_message = (
            f"Welcome to the MySQL monitor.  Commands end with ; or \\g.\n"
            f"Your MySQL connection id is {connection_id}\n"
            f"Server version: {server_version} (Ubuntu)\n\n"
            f"Copyright (c) 2000, 2025, Oracle and/or its affiliates.\n\n"
            f"Type 'help;' or '\\h' for help.\n"
        )
        self.request.sendall(welcome_message.encode('utf-8'))
        
        while True:
            try:
                self.request.sendall(b"mysql> ")
                data = self.request.recv(4096).strip()
                if not data:
                    break
                
                query = data.decode('utf-8', errors='ignore')
                
                if query:
                    logging.warning(f"QUERY from {client_ip}: {query}")
                    response_text = get_llm_response(query)
                    self.request.sendall(b'\n' + response_text.encode('utf-8') + b'\n')

            except ConnectionResetError:
                logging.warning(f"Connection reset by {client_ip}")
                break
            except Exception as e:
                logging.error(f"Exception during connection with {client_ip}: {e}")
                break
        
        logging.info(f"Connection closed by {client_ip}")
# =====================================================

# ================= 4. START SERVER =================
if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    logging.info(f"Starting LLM MySQL Honeypot on {HOST}:{PORT}...")
    with socketserver.ThreadingTCPServer((HOST, PORT), LLMMySQLServer) as server:
        server.serve_forever()
# ===================================================
