import random
import asyncio
import time
import hashlib
import requests
import socket
from typing import Dict, Tuple, Optional, Set, List
from dataclasses import dataclass
from enum import Enum, auto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class RotationStrategy(Enum):
    TOR = auto()
    ALGORITHMIC = auto()
    VPN = auto()
    RANDOM = auto()

@dataclass
class IPValidationResult:
    valid: bool
    reason: str = ""
    details: Optional[dict] = None

class IPRotationProtocol:
    def __init__(self, node, tor_port: int = 9050, vpn_endpoint: str = None):
        self.node = node
        self.tor = TorProxy(tor_port)
        self.vpn_endpoint = vpn_endpoint
        self.blacklist = IPBlacklist()
        self.geo_validator = GeoIPValidator()
        self.rotation_history: Dict[str, float] = {}
        self.current_ip = self._get_public_ip()
        self.identity_keys = self._generate_crypto_identity()
        self.rotation_lock = asyncio.Lock()
        self.last_rotation = 0
        self.rotation_count = 0
        self.active_connections: Set[Tuple[str, int]] = set()
        self.strategy_weights = {
            RotationStrategy.TOR: 0.4,
            RotationStrategy.ALGORITHMIC: 0.3,
            RotationStrategy.VPN: 0.2,
            RotationStrategy.RANDOM: 0.1
        }

    def _generate_crypto_identity(self) -> dict:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return {
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }

    def _get_public_ip(self) -> str:
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com',
            'https://ipinfo.io/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self._is_valid_ip_format(ip):
                        return ip
            except:
                continue
        return "127.0.0.1"

    async def rotate_ip(self, force: bool = False) -> str:
        async with self.rotation_lock:
            current_time = time.time()
            
            if not force:
                if current_time - self.last_rotation < self.node.config.min_rotation_interval:
                    raise RotationCooldownError("Rotation too frequent")
                if self.rotation_count >= self.node.config.max_daily_rotations:
                    raise RotationQuotaExceeded("Daily rotation limit reached")
            
            attempts = 0
            max_attempts = 5
            
            while attempts < max_attempts:
                attempts += 1
                try:
                    new_ip = self._select_ip_strategy()
                    validation = await self._validate_ip(new_ip)
                    
                    if not validation.valid:
                        raise InvalidIPException(validation.reason)
                    
                    await self._apply_ip_rotation(new_ip)
                    self._update_rotation_metadata(new_ip, current_time)
                    await self._announce_new_identity()
                    
                    return new_ip
                except Exception as e:
                    if attempts == max_attempts:
                        raise
                    await asyncio.sleep(1)

    def _select_ip_strategy(self) -> str:
        strategy = random.choices(
            list(self.strategy_weights.keys()),
            weights=list(self.strategy_weights.values()),
            k=1
        )[0]
        
        if strategy == RotationStrategy.TOR and self.node.config.use_tor:
            return self.tor.rotate_circuit()
        elif strategy == RotationStrategy.ALGORITHMIC and self.node.config.algorithmic_rotation:
            return self._generate_algorithmic_ip()
        elif strategy == RotationStrategy.VPN and self.node.config.vpn_api_key:
            return self._request_vpn_ip()
        else:
            return self._generate_random_ip()

    def _generate_algorithmic_ip(self) -> str:
        seed = f"{self.node.id}-{time.time_ns()}-{random.getrandbits(128)}".encode()
        h = hashlib.sha3_256(seed).hexdigest()
        return f"{1 + int(h[0:2], 16 % 254}.{1 + int(h[2:4], 16) % 254}." \
               f"{1 + int(h[4:6], 16) % 254}.{1 + int(h[6:8], 16) % 254}"

    def _generate_random_ip(self) -> str:
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}." \
               f"{random.randint(1, 254)}.{random.randint(1, 254)}"

    async def _request_vpn_ip(self) -> str:
        try:
            response = requests.post(
                self.vpn_endpoint,
                json={"api_key": self.node.config.vpn_api_key},
                timeout=10
            )
            if response.status_code == 200:
                return response.json().get('ip', self._generate_random_ip())
        except:
            pass
        return self._generate_random_ip()

    async def _validate_ip(self, ip: str) -> IPValidationResult:
        checks = [
            self._validate_ip_format,
            self._check_blacklist,
            self._validate_geolocation,
            self._check_reputation,
            self._test_connectivity
        ]
        
        for check in checks:
            result = await check(ip)
            if not result.valid:
                return result
                
        return IPValidationResult(valid=True)

    def _validate_ip_format(self, ip: str) -> IPValidationResult:
        try:
            parts = list(map(int, ip.split('.')))
            if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
                return IPValidationResult(False, "Invalid IP format")
                
            if parts[0] in (0, 10, 127) or \
               (parts[0] == 169 and parts[1] == 254) or \
               (parts[0] == 172 and 16 <= parts[1] <= 31) or \
               (parts[0] == 192 and parts[1] == 168):
                return IPValidationResult(False, "Reserved IP range")
                
            return IPValidationResult(True)
        except:
            return IPValidationResult(False, "Invalid IP format")

    async def _check_blacklist(self, ip: str) -> IPValidationResult:
        if await self.blacklist.is_blacklisted(ip):
            return IPValidationResult(False, "IP is blacklisted")
        return IPValidationResult(True)

    async def _validate_geolocation(self, ip: str) -> IPValidationResult:
        geo_result = await self.geo_validator.validate(ip)
        if not geo_result.allowed:
            return IPValidationResult(
                False, 
                f"Restricted location: {geo_result.country}",
                {"country": geo_result.country}
            )
        return IPValidationResult(True)

    async def _check_reputation(self, ip: str) -> IPValidationResult:
        score = await self.node.reputation_system.get_ip_score(ip)
        if score < self.node.config.min_reputation_score:
            return IPValidationResult(
                False,
                f"Poor IP reputation (score: {score})",
                {"reputation_score": score}
            )
        return IPValidationResult(True)

    async def _test_connectivity(self, ip: str) -> IPValidationResult:
        try:
            # Test DNS
            await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(ip, None),
                timeout=3
            )
            
            # Test TCP connection
            conn = asyncio.open_connection(ip, self.node.port)
            reader, writer = await asyncio.wait_for(conn, timeout=5)
            writer.close()
            await writer.wait_closed()
            return IPValidationResult(True)
        except Exception as e:
            return IPValidationResult(False, f"Connectivity failed: {str(e)}")

    async def _apply_ip_rotation(self, new_ip: str):
        old_ip = self.current_ip
        self.current_ip = new_ip
        self.node.host = new_ip
        
        try:
            await self.node.server.rebind(new_ip, self.node.port)
            await self._cleanup_old_connections(old_ip)
            self.identity_keys = self._generate_crypto_identity()
        except Exception as e:
            self.current_ip = old_ip
            self.node.host = old_ip
            raise

    async def _cleanup_old_connections(self, old_ip: str):
        tasks = []
        for peer in list(self.node.peers):
            if peer[0] == old_ip:
                tasks.append(self.node.disconnect_peer(peer))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _update_rotation_metadata(self, new_ip: str, timestamp: float):
        self.rotation_history[new_ip] = timestamp
        self.rotation_count += 1
        self.last_rotation = timestamp

    async def _announce_new_identity(self):
        message = {
            "type": "identity_rotation",
            "node_id": self.node.id,
            "new_ip": self.current_ip,
            "public_key": self.identity_keys["public_key"],
            "timestamp": int(time.time()),
            "signature": self._sign_rotation_message()
        }
        await self.node.broadcast(message)

    def _sign_rotation_message(self) -> str:
        data = f"{self.node.id}{self.current_ip}{time.time_ns()}".encode()
        return hashlib.blake2b(data, key=self.identity_keys["private_key"][:32]).hexdigest()

    def get_rotation_stats(self) -> dict:
        return {
            "current_ip": self.current_ip,
            "rotation_count": self.rotation_count,
            "last_rotation": self.last_rotation,
            "history_size": len(self.rotation_history)
        }

    async def shutdown(self):
        await self.tor.close()
        await self.blacklist.close()

class TorProxy:
    def __init__(self, port: int = 9050):
        self.port = port
        self.session = requests.Session()
        self.session.proxies = {
            'http': f'socks5h://127.0.0.1:{port}',
            'https': f'socks5h://127.0.0.1:{port}'
        }

    def rotate_circuit(self) -> str:
        try:
            self.session.get("http://checkip.amazonaws.com")
            return self.session.get("http://icanhazip.com").text.strip()
        except:
            return ""

    async def close(self):
        self.session.close()

class IPBlacklist:
    def __init__(self):
        self.blacklists = set()
        self.local_blacklist = set()
        self.update_task = None

    async def is_blacklisted(self, ip: str) -> bool:
        return ip in self.local_blacklist or ip in self.blacklists

    async def update_blacklists(self):
        sources = [
            "https://lists.blocklist.de/lists/all.txt",
            "https://myip.ms/files/blacklist/general/latest_blacklist.txt"
        ]
        for url in sources:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            self.blacklists.update(
                                (await resp.text()).splitlines()
                            )
            except:
                continue

    async def close(self):
        if self.update_task:
            self.update_task.cancel()

class GeoIPValidator:
    def __init__(self):
        self.allowed_countries = {"US", "DE", "JP", "CA", "SG", "CH", "GB"}

    async def validate(self, ip: str) -> IPValidationResult:
        try:
            country = await self._lookup_country(ip)
            return IPValidationResult(
                country in self.allowed_countries,
                country=country
            )
        except:
            return IPValidationResult(False, "GeoIP lookup failed")

    async def _lookup_country(self, ip: str) -> str:
        # Simulated country lookup
        octets = list(map(int, ip.split('.')))
        index = sum(octets) % len(self.allowed_countries)
        return list(self.allowed_countries)[index]

class RotationCooldownError(Exception):
    pass

class RotationQuotaExceeded(Exception):
    pass

class InvalidIPException(Exception):
    pass
