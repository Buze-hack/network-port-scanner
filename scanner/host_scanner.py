"""
Host scanner model 
performsm ICMP ping sweep to identify live hosts in the network
"""

import os
import socket
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from pythonping import ping
    PYTHONPING_AVAILABLE = True
except ImportError:
    PYTHONPING_AVAILABLE = False

class HostScanner:
    def __init__(self, timeout: float = 1.0, max_threads: Optional[int] = None):
        self.timeout = timeout
        self.max_threads = max_threads or min(100, (os.cpu_count() or 4) * 5)

    def _icm_ping(self, host: str) -> bool:
        if not PYTHONPING_AVAILABLE:
            return False
        
        try:
            response = ping(host, count=1, timeout=self.timeout)
            return response.success()
        except Exception:
            return False
        
    def _tcp_ping(self, host: str, ports: List[int] = [80, 443, 22]) -> bool:
        """
        fallback method to check if host is alive by attempting TCP connection on common ports
        """
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0 or result == 111: 
                    # 111 means connection refused, which indicates host is alive
                    return True
            except socket.error:
                continue

        return False

    def ping_host(self, host: str) -> bool:
        """
        Check if a host is alive using ICMP or TCP ping.
        
        First attempts ICMP ping (if available and has privileges),
        then falls back to TCP ping on common ports
        """
        if self._icm_ping(host):
            return True
        return self._tcp_ping(host)
    
    def discover_host(self, hosts: List[str], progress=None, task=None) -> List[str]:
        """
        Discover alive hosts from a list of IP addresses or hostnames.

        """

        with ThreadPoolExecutor(max_threads=self.max_threads) as executor:
            future_to_host = {
                executor.submit(self.ping_host, host): host 
                for host in hosts
            }

             # Collect results as they complete
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                
                try:
                    if future.result():
                        alive_hosts.append(host)
                except Exception:
                    # Host check failed, treat as down
                    pass
                    
                # Update progress if provided
                if progress and task is not None:
                    progress.advance(task)

        return sorted(alive_hosts, key=lambda x: [int(i) for i in x.split('.')])