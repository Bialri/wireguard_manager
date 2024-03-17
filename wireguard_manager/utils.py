from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import socket
import ipaddress
from pathlib import Path


class WGUtilsMixin:
    """
    Wireguard Utils methods to manage interfaces and execute with common wireguard functions
    """

    @staticmethod
    def _get_host_ip() -> str:
        """
        Current IP address according to a hostname.

        Returns:
            str: Current IP address.

        """
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address

    @staticmethod
    def _get_interfaces_addresses(config_dir: Path) -> tuple[ipaddress.IPv4Network, ...]:
        """
        Subnets of the interfaces in given dir.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.

        Returns:
            tuple[IPv4Network]: Interfaces subnets.

        """
        interface_paths = config_dir.glob('*.conf')
        addresses = []
        for interface_path in interface_paths:
            with open(interface_path, 'r') as file:
                for line in file:
                    if 'Address = ' in line:
                        address = line.split('= ')[1].rstrip()
                        addresses.append(ipaddress.ip_network(address, strict=False))
        return tuple(addresses)

    @staticmethod
    def _get_interfaces_names(config_dir: Path) -> list[str]:
        """
        Names of the interfaces in given directory.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.

        Returns:
            list[str]: Interfaces names.

        """
        interface_paths = config_dir.glob('*.conf')
        return [interface_path.stem.split('.')[0] for interface_path in interface_paths]

    @staticmethod
    def _get_interfaces_ports(config_dir: Path) -> list[int]:
        """
        Occupied interfaces ports in given directory.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.

        Returns:
            list[int]: occupied ports

        """
        interface_paths = list(config_dir.glob('*.conf'))
        ports = []
        for interface_path in interface_paths:
            with open(interface_path, 'r') as file:
                for line in file:
                    if 'ListenPort = ' in line:
                        port = line.split('= ')[1].rstrip()
                        ports.append(int(port))
        return ports


    @classmethod
    def _get_free_interface_name(cls, config_dir: Path, prefix: str) -> str:
        """
        Generate free interface name to avoid duplication.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.
            prefix(str): Name prefix, for example 'wg0'.

        Returns:
            str: Free interface name.

        """
        existing_names = cls._get_interfaces_names(config_dir)
        for i in range(0, 2 * 16):
            name = f'{prefix}{i}'
            if name not in existing_names:
                return name
