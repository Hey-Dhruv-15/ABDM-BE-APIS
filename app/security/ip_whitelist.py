"""
IP Whitelist checking for incoming requests.
"""
import ipaddress
from typing import List, Any
from fastapi import Request
from app.core.exceptions import SecurityError
from app.logging.logger import get_logger

logger = get_logger(__name__)

class IPWhitelist:
    """
    Validates that the source IP address of a request is within an allowed range.
    """

    def __init__(self, allowed_ips_or_cidrs: List[str]):
        self.allowed_networks = []
        for item in allowed_ips_or_cidrs:
            try:
                self.allowed_networks.append(ipaddress.ip_network(item))
            except ValueError as e:
                logger.error("Invalid IP/CIDR in whitelist configuration", entry=item, error=str(e))

    async def validate(self, request: Request):
        """
        Validate source IP against whitelist.
        """
        if not self.allowed_networks:
            return True # If no whitelist, allow all
            
        client_ip = ipaddress.ip_address(request.client.host)
        
        is_allowed = any(client_ip in network for network in self.allowed_networks)
        
        if not is_allowed:
            logger.warning("IP address blocked by whitelist", client_ip=str(client_ip))
            raise SecurityError(f"Access denied from IP: {client_ip}")
            
        return True
