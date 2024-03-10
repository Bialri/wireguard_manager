from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import socket
import ipaddress
from pathlib import Path


class WGUtilsMixin:
    """
    Wireguard Utils methods to manage interfaces and execute with common wireguard functions
    """
    @staticmethod
    def _generate_private_key() -> X25519PrivateKey:
        """
        Generate wireguard private key.

        Returns:
            X25519PrivateKey: Wireguard private key.

        """
        return X25519PrivateKey.generate()

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
    def _get_free_port(cls,
                       config_dir: Path,
                       range_start: int = 51820,
                       range_end: int = 65535) -> int:
        """
        Get free port in range allocated for interfaces.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.
            range_start(int): Ports, allocated for interfaces, range start.
            range_end(int): Ports, allocated for interfaces, range end.

        Returns:
            int: First available port in range.

        """
        existing_ports = cls._get_interfaces_ports(config_dir)
        port_range = range(range_start, range_end)
        for port in port_range:
            if port not in existing_ports:
                return port

    @classmethod
    def _get_free_subnetwork(cls, config_dir: Path, network_prefix: int) -> ipaddress.IPv4Network:
        """
        Get free subnetwork with given prefix.
        Args:
            config_dir(Path): Directory, contains interfaces configurations.
            network_prefix(int): Subnetwork size need to be allocated.

        Returns:
            IPv4Network: Allocated free subnetwork.

        """
        local_network = ipaddress.ip_network('10.0.0.0/8')
        subnets = local_network.subnets(new_prefix=network_prefix)
        existing_subnets = cls._get_interfaces_addresses(config_dir)
        for subnet in subnets:
            if not any(subnet.overlaps(existing_subnet) for existing_subnet in existing_subnets):
                return subnet

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
