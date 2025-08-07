import random
import asyncio
import time
import hashlib
import requests
from typing import Dict, Tuple, Optional
from utils.tor_proxy import TorProxy
from utils.crypto import generate_rsa_keypair
from utils.blacklist import IPBlacklist
from utils.geoip import GeoIPValidator
from utils.logger import log

class IPRotationProtocol:
    def __init__(self, node, tor_port: int = 9050):
        self.node = node
        self.tor = TorProxy(tor_port)
        self.blacklist = IPBlacklist()
        self.geo_validator = GeoIPValidator()
        self.rotation_history: Dict[str, float] = {}
        self.current_ip = self._get_public_ip()
        self.identity_keys = generate_rsa_keypair()
        self.rotation_lock = asyncio.Lock()
        self.last_rotation = 0
        self.rotation_count = 0

    def _get_public_ip(self) -> str:
        """Retrieve current public IP using multiple fallback services"""
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
        return "127.0.0.1"

    async def rotate_ip(self, force: bool = False) -> str:
        """Rotate node IP with advanced security features"""
        async with self.rotation_lock:
            # Check rotation cooldown
            current_time = time.time()
            if not force and current_time - self.last_rotation < self.node.config.min_rotation_interval:
                raise RotationCooldownError("Rotation too frequent")
                
            # Validate rotation count
            if self.rotation_count >= self.node.config.max_daily_rotations:
                raise RotationQuotaExceeded("Daily rotation limit reached")
            
            # Generate new IP candidate
            new_ip = self._generate_ip_candidate()
            
            # Validate IP through multiple checks
            validation_result = await self._validate_ip(new_ip)
            if not validation_result["valid"]:
                raise InvalidIPException(f"IP validation failed: {validation_result['reason']}")
            
            # Execute IP rotation
            self._apply_ip_rotation(new_ip)
            
            # Update rotation metadata
            self.rotation_history[new_ip] = current_time
            self.rotation_count += 1
            self.last_rotation = current_time
            
            # Notify network about identity change
            await self._announce_new_identity()
            
            return new_ip

    def _generate_ip_candidate(self) -> str:
        """Generate IP candidate using multiple strategies"""
        # Strategy 1: Tor circuit rotation
        if self.node.config.use_tor:
            new_ip = self.tor.rotate_circuit()
            if new_ip:
                return new_ip
        
        # Strategy 2: Algorithmic generation
        if self.node.config.algorithmic_rotation:
            return self._generate_algorithmic_ip()
        
        # Strategy 3: External VPN API
        if self.node.config.vpn_api_key:
            return self._request_vpn_ip()
        
        # Fallback: Random generation
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}." \
               f"{random.randint(1, 255)}.{random.randint(1, 255)}"

    def _generate_algorithmic_ip(self) -> str:
        """Generate IP using secure algorithm"""
        # Create hash from node identity and timestamp
        seed = f"{self.node.id}-{time.time_ns()}".encode()
        h = hashlib.sha3_256(seed).hexdigest()
        
        # Convert hash to IP components
        parts = [
            str(1 + int(h[0:2], 16) % 255),
            str(1 + int(h[2:4], 16) % 255),
            str(1 + int(h[4:6], 16) % 255),
            str(1 + int(h[6:8], 16) % 255)
        ]
        
        return ".".join(parts)

    async def _validate_ip(self, ip: str) -> dict:
        """Perform comprehensive IP validation"""
        result = {"valid": False, "reason": ""}
        
        # Format validation
        if not self._is_valid_ip_format(ip):
            result["reason"] = "Invalid IP format"
            return result
        
        # Blacklist check
        if self.blacklist.is_blacklisted(ip):
            result["reason"] = "IP is blacklisted"
            return result
        
        # Geo-location validation
        geo_result = self.geo_validator.validate(ip)
        if not geo_result["allowed"]:
            result["reason"] = f"Restricted location: {geo_result['country']}"
            return result
        
        # Reputation check (simulated)
        if self._check_ip_reputation(ip) < self.node.config.min_reputation_score:
            result["reason"] = "Poor IP reputation"
            return result
        
        # Network test
        if not await self._test_ip_connectivity(ip):
            result["reason"] = "Connectivity test failed"
            return result
        
        result["valid"] = True
        return result

    def _is_valid_ip_format(self, ip: str) -> bool:
        """Validate IP address structure"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
            
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
                
        # Prevent reserved IP ranges
        first_octet = int(parts[0])
        if first_octet == 0 or first_octet == 10 or first_octet == 127 or \
           first_octet == 169 and int(parts[1]) == 254 or \
           first_octet == 172 and 16 <= int(parts[1]) <= 31 or \
           first_octet == 192 and int(parts[1]) == 168:
            return False
            
        return True

    async def _test_ip_connectivity(self, ip: str) -> bool:
        """Test IP connectivity through network checks"""
        try:
            # Test DNS resolution
            await asyncio.get_event_loop().getaddrinfo(ip, self.node.port, timeout=3)
            
            # Test outbound connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.node.port),
                timeout=5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    def _apply_ip_rotation(self, new_ip: str):
        """Execute the IP rotation process"""
        # Update node configuration
        self.node.host = new_ip
        self.current_ip = new_ip
        
        # Update server binding
        self.node.server.update_binding(new_ip, self.node.port)
        
        # Generate new cryptographic identity
        self.identity_keys = generate_rsa_keypair()
        
        # Clear peer connections
        self.node.peers.clear()
        self.node.connection_pool.clear()

    async def _announce_new_identity(self):
        """Notify network about identity change"""
        message = {
            "type": "identity_rotation",
            "node_id": self.node.id,
            "new_ip": self.current_ip,
            "public_key": self.identity_keys["public_key"],
            "timestamp": int(time.time()),
            "rotation_proof": self._generate_rotation_proof()
        }
        await self.node._secure_broadcast(message)

    def _generate_rotation_proof(self) -> str:
        """Generate cryptographic proof of rotation"""
        data = f"{self.node.id}{self.current_ip}{time.time_ns()}".encode()
        return hashlib.blake2b(data, key=self.node.wallet.private_key[:32]).hexdigest()

    def get_current_ip(self) -> str:
        """Get current validated IP address"""
        return self.current_ip

    def get_rotation_history(self) -> dict:
        """Get rotation history with timestamps"""
        return self.rotation_history.copy()

    def reset_rotation_quota(self):
        """Reset daily rotation counter"""
        self.rotation_count = 0


# Custom Exceptions
class RotationCooldownError(Exception):
    pass

class RotationQuotaExceeded(Exception):
    pass

class InvalidIPException(Exception):
    pass


# Implementation for dependencies
class IPBlacklist:
    def __init__(self):
        self.blacklist = set()
        self._load_blacklists()
    
    def _load_blacklists(self):
        # Load from internal database
        self.blacklist |= self._load_internal_blacklist()
        
        # Fetch from external sources
        asyncio.create_task(self._fetch_external_blacklists())
    
    def is_blacklisted(self, ip: str) -> bool:
        return ip in self.blacklist
    
    def _load_internal_blacklist(self) -> set:
        # Would load from persistent storage
        return set()
    
    async def _fetch_external_blacklists(self):
        # Fetch from public blacklists
        sources = [
            "https://lists.blocklist.de/lists/all.txt",
            "https://myip.ms/files/blacklist/general/latest_blacklist.txt"
        ]
        
        for url in sources:
            try:
                response = await asyncio.to_thread(requests.get, url, timeout=10)
                if response.status_code == 200:
                    ips = set(response.text.splitlines())
                    self.blacklist.update(ips)
            except:
                continue

class GeoIPValidator:
    def __init__(self):
        self.allowed_countries = {"US", "DE", "JP", "CA", "SG", "CH", "GB"}
        self.restricted_ranges = set()
    
    def validate(self, ip: str) -> dict:
        # In real implementation, use GeoIP database
        country = self._simulate_geo_lookup(ip)
        return {
            "allowed": country in self.allowed_countries,
            "country": country
        }
    
    def _simulate_geo_lookup(self, ip: str) -> str:
        # This would be replaced with real GeoIP lookup
        octets = ip.split('.')
        country_index = int(octets[0]) % len(self.allowed_countries)
        return list(self.allowed_countries)[country_index]
