import ipaddress
import os
import subprocess
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .utils import WGUtilsMixin
from .exceptions import InterfaceError
from .config import WGConfig, WGInterfaceConfig, WGPeerConfig


class WGInterface(WGUtilsMixin):
    """
    Implementation of wireguard interface
    """

    def __init__(self,
                 config: WGConfig = None) -> None:
        """
        Interface initialization.
        Args:
            config(WGConfig): Config object of the interface

        """
        self.config = config

    @classmethod
    def create(cls,
               config_path: os.PathLike,
               network: ipaddress.IPv4Network,
               listen_port: int,
               address: ipaddress.IPv4Address = None):
        """
        Create new interface, which not conflict with others, with given size of subnetwork.
        Args:
            config_path(PathLike): Configuration file path.
            network(IPv4Network): Interface subnetwork.
            address(IPv4Address): Interface address.
            listen_port(int): Interface port.

        """
        if address and address not in network:
            raise InterfaceError(f"Address {address} not in given network {network}")
        private_key = cls._generate_private_key()
        interface_config = WGInterfaceConfig(network=network,
                                             address=address,
                                             listen_port=listen_port,
                                             private_key=private_key)
        config = WGConfig(path=config_path, interface_config=interface_config)
        interface = cls(config)
        if not address:
            address = interface._free_ip()
            interface.config.interface_config.address = address
        return interface

    def run(self):
        process = subprocess.run(['wg-quick', 'up', self.config.path], capture_output=True)
        if not process.returncode:
            raise InterfaceError(f'wg-quick returned an error:\n{process.stderr}')

    def update(self) -> None:
        self.config.save()
        process = subprocess.Popen(f'wg syncconf {self.config.name} <(wg-quick strip {self.config.path})',
                                   shell=True,
                                   executable='/bin/bash',
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        process.wait()
        if not process.returncode:
            raise InterfaceError(f'wg-quick returned an error:\n{process.stderr}')

    def stop(self) -> None:
        process = subprocess.run(['wg-quick', 'down', self.config.path], capture_output=True)

        if process.returncode:
            raise InterfaceError(f'wg-quick returned an error:\n{process.stderr}')

    def delete(self) -> None:
        """
        Gracefully remove interface.

        Raises:
            FileNotFoundError: if configuration file does not exist
        """
        self.stop()
        self.config.delete()

    def _free_ip(self) -> ipaddress.IPv4Address:
        ip_range = list(self.config.interface_config.network.hosts())
        occupied_addresses = []
        if self.config.peer_configs:
            occupied_addresses = [peer.allowed_ips_address for peer in self.config.peer_configs]
            occupied_addresses.append(self.config.interface_config.address)
        ip = min(list(filter(lambda x: x not in occupied_addresses, ip_range)))
        return ip

    @staticmethod
    def _generate_private_key() -> X25519PrivateKey:
        """
        Generate wireguard private key.

        Returns:
            X25519PrivateKey: Wireguard private key.

        """
        return X25519PrivateKey.generate()

    def create_peer(self,
                    name: str,
                    allowed_ips_network: ipaddress.IPv4Network = None,
                    allowed_ips_address: ipaddress.IPv4Address = None,
                    private_key: X25519PrivateKey = None,
                    persistent_keep_alive: int = None):
        if not allowed_ips_address or not allowed_ips_network:
            allowed_ips_address = self._free_ip()
            allowed_ips_network = ipaddress.ip_network(f'{allowed_ips_address}/{32}', strict=False)
        else:
            if allowed_ips_address not in allowed_ips_address:
                raise InterfaceError(f"Address {allowed_ips_address} not in given network {allowed_ips_network}")
            if allowed_ips_address not in self.config.interface_config.network:
                raise InterfaceError(
                    f"Address {allowed_ips_address} not in interface network {self.config.interface_config.address}")
        if not private_key:
            private_key = self._generate_private_key()

        peer_config = WGPeerConfig(allowed_ips_network, allowed_ips_address, name, private_key, persistent_keep_alive)
        self.config.peer_configs.append(peer_config)
        return peer_config

    def generate_peer_config(self, peer: WGPeerConfig, endpoint):
        interface_config = WGInterfaceConfig(network=peer.allowed_ips_network,
                                             address=peer.allowed_ips_address,
                                             private_key=peer.private_key,
                                             dns=self.config.interface_config.dns,
                                             mtu=self.config.interface_config.mtu)
        peer_config = WGPeerConfig(ipaddress.ip_network('0.0.0.0/0'),
                                   ipaddress.ip_address('0.0.0.0'),
                                   private_key=self.config.interface_config.private_key,
                                   endpoint=f'{endpoint}:{self.config.interface_config.listen_port}')
        return WGConfig(interface_config=interface_config, peer_configs=[peer_config]).stringify()
