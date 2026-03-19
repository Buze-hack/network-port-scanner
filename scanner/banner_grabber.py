"""
attempts to retrieve a service banner from open ports by identifying the sprcific software running on the port and sending a request to it. The response is then analyzed to extract the banner information, which can provide insights into the service version  

"""

import socket
from typing import Optional, Dict

class BannerGrabber:
    """
    Service Banner Grabber for identifying services on open ports.

    Different services require different methods to retrieve banners:
    - Some services (SSH, FTP, SMTP) send banners immediately on connection
    - HTTP services require sending a request first
    - Some services require specific protocol handshake

    """
    # services that require sending a request to get a response
    REQUEST_REQUIRED_SERVICES: Dict[int, bytes] = {
        80: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",  
        443: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        8080: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        8443: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        3128: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    }

    IMMEDIATE_BANNER_SERVICES: Dict[int, str] = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
    }

    def __init__(self, timeout: float = 2.0, buffer_size: int = 1024):
        """
        timeout: Socket timeout in seconds (longer than scan timeout)
        buffer_size: Maximum bytes to receive

        """
        self.timeout = timeout
        self.buffer_size = buffer_size

    def grab_banner(self, host: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            if port in self.REQUEST_REQUIRED_SERVICES:
                sock.send(self.REQUEST_REQUIRED_SERVICES[port])
            
            banner = sock.recv(self.buffer_size)
            sock.close()

            if banner:
                return self._clean_banner(banner) #Decode and clean banner
            
            return None
        
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception:
            return None
    
    def _clean_banner(self, banner: bytes) -> str:
        """
        clean and format raw banner

        """
        try:
            decoded = banner.decode('utf-8', errors='ignore')
        except:
            decoded = banner.decode('latin-1', errors='ignore')

        cleaned = ''.join(
            char if char.isprintable() or char in '\n\r\t' else ' '
            for char in decoded
        )

        if len(cleaned) > 200:
            cleaned = cleaned[:200] + '...'

        return cleaned.strip()
    
    def grab_http_banner(self, host: str, port: int=80) -> Optional[str]:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            request = f"HEAD /HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(self.buffer_size).decode('utf-8', errors='ignore')
            sock.close()

            #extract Server header

            for line in response.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()

            # If no Server header, return first line (HTTP version)    
            first_line = response.split('\r\n')[0]
            return first_line.strip() if first_line else None
    
        except Exception:
            return None
        
    def grab_ssh_banner(self, host: str, port: int=22) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            banner = sock.recv(self.buffer_size).decode('utf-8', errors='ignore')
            sock.close()

            # SSH banner should start with "SSH-"
            if banner.startswith('SSH-'):
                return banner.strip()
            
            return banner.strip() if banner else None
        
        except Exception:
            return None



        



