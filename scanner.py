
import socket    
import threading    


SERVICE_MAP = {
    20:    "FTP-DATA",
    21:    "FTP",
    22:    "SSH",
    23:    "TELNET",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPCBIND",
    119:   "NNTP",
    123:   "NTP",
    135:   "MSRPC",
    137:   "NETBIOS-NS",
    138:   "NETBIOS-DGM",
    139:   "NETBIOS-SSN",
    143:   "IMAP",
    161:   "SNMP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    512:   "REXEC",
    513:   "RLOGIN",
    514:   "SYSLOG",
    515:   "LPD",
    587:   "SMTP-TLS",
    631:   "IPP",
    636:   "LDAPS",
    873:   "RSYNC",
    990:   "FTPS",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    1723:  "PPTP",
    2049:  "NFS",
    2121:  "FTP-ALT",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5985:  "WinRM",
    6379:  "Redis",
    6667:  "IRC",
    8080:  "HTTP-ALT",
    8443:  "HTTPS-ALT",
    8888:  "HTTP-DEV",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}


def scan_port(ip, port, timeout=0.5):
    """
    Attempt a TCP connection to ip:port.
    - If connection succeeds   → port is OPEN
    - If connection refused    → port is CLOSED
    - If connection times out  → port is FILTERED (firewall blocking)
    """
    try:
       
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  

     
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return "open"    
        else:
            return "closed"    

    except socket.timeout:
        return "filtered"      

    except Exception:
        return "closed"        




def get_service(port):
    """
    Look up the service name for a port.
    If unknown, return 'Unknown'.
    """
    return SERVICE_MAP.get(port, "Unknown")



def scan_target(ip, ports, callback=None, stop_flag=None):
    """
    Scan all ports in the 'ports' list on the target IP.

    Parameters:
    - ip       : Target IP address (e.g., "192.168.1.1")
    - ports    : List of port numbers to scan
    - callback : Function to call when a port result is ready
    - stop_flag: A list [False] that becomes [True] to stop scanning

    Returns:
    - List of result dictionaries
    """
    results = []        
    lock = threading.Lock()  

    def scan_single(port):
       
        if stop_flag and stop_flag[0]:
            return

      
        status  = scan_port(ip, port)
        service = get_service(port)

        result = {
            "port":     port,
            "status":   status,
            "service":  service,
            "protocol": "TCP",
        }

        
        with lock:
            results.append(result)

        
        if callback:
            callback(result)

   
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_single, args=(port,))
        threads.append(t)
        t.start()

   
    for t in threads:
        t.join()

    return results



def validate_ip(ip):
    """
    Returns True if ip is a valid IPv4 address.
    Example: "192.168.1.1" → True
             "999.x.y.z"   → False
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
