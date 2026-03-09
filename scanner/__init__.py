"""
Port Scanner Package
Performs network port scanning to identify open ports and services on target hosts.

"""

import socket
import os
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

@dataclass
class ScanResult:
    host: str
    port: int
    state: PortState
    service: Optional[str] = None
    banner: Optional[str] = None

class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: Optional[int] = None):
        """"
        timeout: Connection timeout in seconds (default: 1.0)
        max_threads: Maximum number of concurrent threads (default: min(100, CPU cores * 5))
        
        """
        
        self.timeout = timeout
        self.max_threads = max_threads or min(100, (os.cpu_count() or 4) * 5)
    
    def scan_port(self, host: str, port: int) -> bool:
        """"
        port: target port no
        host: target host IP or hostname
        Returns True if the port is open, False if closed or filtered.

        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            #Attempt connection 
            result = sock.connect_ex((host, port))

            sock.close()

            return result == 0 

        except socket.gaierror:
            return False # Hostname could not be resolved
        except socket.error:
            return False # connection error
        except Exception:
            return False # Any other exception treated as closed/filtered

        def scan_port_detailed(self, host: str, port: int) -> Tuple [PortState, Optional[str]]:

            #scan a single port and retain detailed information
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    return PortState.OPEN, None
                elif result == 111:
                    return PortState.CLOSED, "Connection refused"
                else:
                    return PortState.FILTERED, f"Error code: {result}"
                
            except socket.gaierror:
                return PortState.FILTERED, f"DNS error: {e}"
            except socket.timeout:
                return PortState.FILTERED, "Connection timed out"
            except socket.error as e:
                return PortState.FILTERED, f"Socket error: {e}"
            except Exception as e:
                return PortState.FILTERED, f"Unexpected error: {e}"
            
        def scan_ports(self, host: str, port: List[int], callback=None) -> List[ScanResult]:
            """
            Scan multiple targets
            callback = optional callback function called for each result 
            returns a list of ScanResult objects of open ports

            """
            results = []

            with ThreadPoolExecutor(max_threads=self.max_threads) as executor:
                #submit all port scans
                future_to_port = {
                    executor.submit(self.scan_port_detailed, host, port): port for port in ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]

                    try:
                        state, error = future.result()

                        result = ScanResult(
                            host=host,
                            port=port,
                            state=state,                        
                        )

                        if state == PortState.OPEN:
                            results.append(result)
                        if callback:
                            callback(result)

                    except Exception as e:
                        if callback:
                            callback(ScanResult(
                                host=host,
                                port=port,
                                state=PortState.FILTERED,                                
                            ))
            return sorted(results, key=lambda x: x.port)
    
    def scan_hosts(self, hosts: List[str], ports: List[int], callback=None) -> List[ScanResult]:
        #Scan multiple ports 
        #returns a list of ScanResult objects of open ports across all hosts

        all_results = []

        for host in hosts:
            results = self.scan_ports(host, ports, callback)
            all_results.extend(results)

        return all_results 