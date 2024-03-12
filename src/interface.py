import ipaddress
from collections import Counter
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import codecs
from pathlib import Path
import os
import subprocess

from .peer import WGPeer
from .utils import WGUtilsMixin
from .exceptions import TemplateError


class WGInterface(WGUtilsMixin):
    """
    Implementation of wireguard interface
    """

    def __init__(self,
                 interface_name: str = None,
                 network: ipaddress.IPv4Network | str = None,
                 address: ipaddress.IPv4Address | str = None,
                 listen_port: int = None,
                 private_key: X25519PrivateKey = None,
                 mtu: int = None,
                 post_up_commands: list[str] = None,
                 post_down_commands: list[str] = None,
                 peers: list[WGPeer] = None,
                 peers_prefix: int = 32,
                 config_dir: Path | str = None) -> None:
        """
        Interface initialization.
        Args:
            interface_name(str): Name of wireguard interface.
            address(IPv4Network): Interface subnetwork.
            listen_port(int): Port allocated for interface.
            private_key(X25519PrivateKey): Interface private key.
            mtu(int): Interface MTU.
            post_up_commands(list[str]): Interface post up commands.
            post_down_commands(list[str]): Interface post down commands.
            peers(WGPeer): list of peers associated with initializing interface
            config_dir(Path): Directory, contains interfaces configurations.

        """
        self.name = interface_name
        if isinstance(network, str):
            network = ipaddress.ip_network(network)
        self.network = network
        if isinstance(address, str):
            address = ipaddress.ip_address(address)
        self.address = address
        self.listen_port = listen_port
        self.private_key = private_key
        self.mtu = mtu
        self.post_up_commands = post_up_commands
        if not post_up_commands:
            self.post_up_commands = []
        self.post_down_commands = post_down_commands
        if not post_down_commands:
            self.post_down_commands = []
        self.peers = peers
        if not peers:
            self.peers = []
        if isinstance(config_dir, str):
            config_dir = Path(config_dir)
        self.peers_prefix = peers_prefix
        self.config_dir = config_dir

    @classmethod
    def load_existing(cls, configuration_path: Path | str) -> "WGInterface":
        """
        Create interface object from configuration file.
        Args:
            configuration_path(Path | str): Path to configuration to load.

        Returns:
            WGInterface: interface loaded from config file.

        """
        return load_config(configuration_path)

    @classmethod
    def create_new(cls,
                   prefix: str,
                   network_prefix: int,
                   config_dir: Path | str,
                   mtu: int = None,
                   post_up_command_templates: list[str] = None,
                   post_down_command_templates: list[str] = None,
                   peers_prefix: int = 32) -> "WGInterface":
        """
        Create new interface, which not conflict with others, with given size of subnetwork.
        Args:
            prefix(str): Name prefix.
            network_prefix: Interface subnetwork size.
            config_dir(Path): Directory, contains interfaces configurations.
            mtu(int): interface MTU
            post_up_command_templates(list[str]): Templates for post up commands(will be filled with right values).
            post_down_command_templates: Templates for post down commands(will be filled with right values).

        Returns:
            WGInterface: New interface.

        """
        return create_new_interface(prefix, network_prefix, config_dir, mtu, post_up_command_templates,
                                    post_down_command_templates, peers_prefix)

    def delete_config(self) -> None:
        """
        Gracefully remove interface.

        Raises:
            FileNotFoundError: if configuration file does not exist
        """
        config_path = os.path.join(self.config_dir, f'{self.name}.conf')
        self.stop_interface()
        try:
            os.remove(config_path)
        except FileNotFoundError:
            raise FileNotFoundError(f'Configuration file {config_path} does not exist')

    def convert_command_templates(self, command_templates: list[str]) -> tuple[str, ...]:
        commands = []
        for command_template in command_templates:
            command_template = command_template.replace('%wg_interface', self.name)
            command = command_template.replace('%wg_port', str(self.listen_port))
            commands.append(command)
        for command in commands:
            if '%wg' in command:
                placeholder = command.split('%', 1)[0].split(' ')[0]
                raise TemplateError(f"Unsupported placeholder {placeholder}")
        return tuple(commands)

    @staticmethod
    def _get_matching_config_line(configuration_path: Path, option: str) -> str | None:
        with open(configuration_path, 'r') as file:
            for line in file:
                if option == line.split(' ', 1)[0]:
                    value = line.split('= ', 1)[1].rstrip()
                    return value
        return None

    @staticmethod
    def _get_matching_config_lines(configuration_path: Path, option: str) -> list[str]:
        with open(configuration_path, 'r') as file:
            values = []
            for line in file:
                if option == line.split(' ', 1)[0]:
                    value = line.split('= ', 1)[1].rstrip()
                    values.append(value)
            return values

    def _config_network(self, configuration_path: Path) -> ipaddress.IPv4Network | None:
        value = self._get_matching_config_line(configuration_path, 'Address')
        if value:
            return ipaddress.ip_network(value, strict=False)
        return None

    def _config_address(self, configuration_path: Path) -> ipaddress.IPv4Address | None:
        value = self._get_matching_config_line(configuration_path, 'Address')
        if value:
            without_prefix = value.split('/', 1)[0]
            return ipaddress.ip_address(without_prefix)
        return None

    @staticmethod
    def _config_name(configuration_path: Path) -> str:
        filename = configuration_path.name
        return filename.split('.')[0]

    def _config_listen_port(self, configuration_path: Path) -> int | None:
        value = self._get_matching_config_line(configuration_path, 'ListenPort')
        if value:
            return int(value)
        return None

    def _config_private_key(self, configuration_path: Path) -> X25519PrivateKey | None:
        value = self._get_matching_config_line(configuration_path, 'PrivateKey')
        if value:
            decoded_key = codecs.decode(value.encode('utf8'), 'base64')
            private_key = X25519PrivateKey.from_private_bytes(decoded_key)
            return private_key
        return None

    def _config_mtu(self, configuration_path: Path) -> int | None:
        value = self._get_matching_config_line(configuration_path, 'MTU')
        if value:
            return int(value)
        return None

    def _config_postup_commands(self, configuration_path: Path) -> list[str]:
        values = self._get_matching_config_lines(configuration_path, 'PostUp')
        return values

    def _config_postdown_commands(self, configuration_path: Path) -> list[str]:
        values = self._get_matching_config_lines(configuration_path, 'PostDown')
        return values

    @staticmethod
    def _config_peers(configuration_path: Path) -> list[WGPeer]:
        with open(configuration_path, 'r') as file:
            config = file.read()
            peer_configs = config.split('[Peer]')[1:]
            peers = []
            for peer_config in peer_configs:
                peer = WGPeer.from_config(peer_config)
                peers.append(peer)
            return peers

    def _set_most_common_peers_prefix(self):
        prefixes = [peer.allowed_ips.prefixlen for peer in self.peers]
        if prefixes:
            counter = Counter(prefixes)
            return counter.most_common(1)[0][0]
        return 32

    def _free_ip(self) -> list[ipaddress.IPv4Network]:
        ip_range = list(self.network.hosts())
        occupied_addresses = [peer.allowed_ips.network_address for peer in self.peers]
        occupied_addresses.append(self.address)
        ip = min(list(filter(lambda x: x not in occupied_addresses, ip_range)))
        return ip

    def add_peer(self, peer) -> None:
        self.peers.append(peer)

    def delete_peer(self, peer):
        self.peers.remove(peer)
        self.save_config()
        self.update_config()

    def create_peer(self, name: str = None) -> WGPeer:
        address = self._free_ip()
        address_with_prefix = str(address) + f"/{self.peers_prefix}"
        allowed_ips = ipaddress.ip_network(address_with_prefix)
        peer = WGPeer(allowed_ips=allowed_ips, name=name)
        peer.set_key()
        self.peers.append(peer)
        self.save_config()
        self.update_config()
        return peer

    def save_config(self) -> None:
        config_path = os.path.join(self.config_dir, f'{self.name}.conf')
        with open(config_path, 'w') as file:
            file.write(self.generate_config())
        self.update_config()

    @staticmethod
    def _generate_config_line(option: str, value: str | None) -> str:
        if value:
            return f'{option} = {str(value)}\n'
        return ''

    @classmethod
    def _generate_config_lines(cls, option: str, values: list[str]) -> str:
        if values:
            return ''.join([cls._generate_config_line(option, value) for value in values])
        return ''

    def generate_config(self) -> str:
        address_with_prefix = str(self.address) + f'/{self.network.prefixlen}'
        address = self._generate_config_line('Address', address_with_prefix)
        listen_port = self._generate_config_line('ListenPort', str(self.listen_port))

        if self.private_key:
            bytes_ = self.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            private_key = codecs.encode(bytes_, 'base64').decode('utf8').strip()
            private_key = self._generate_config_line("PrivateKey", private_key)
        else:
            private_key = ''

        mtu = self._generate_config_line('MTU', self.mtu)

        post_up = self._generate_config_lines('PostUp', self.post_up_commands)
        post_down = self._generate_config_lines('PostDown', self.post_down_commands)

        peers = '\n\n'.join([peer.generate_peer_config() for peer in self.peers])
        config = f'[Interface]\n{address}{listen_port}{private_key}{mtu}{post_up}{post_down}\n\n{peers}'
        return config

    def generate_peer_config(self,
                             peer: WGPeer,
                             allowed_ips: ipaddress.IPv4Network = ipaddress.ip_network('0.0.0.0/0', strict=False),
                             domain_name: str = None,
                             dns: ipaddress.IPv4Address = None):
        if peer in self.peers:
            args = []
            if dns:
                args.append(dns)
            peer_interface = peer.generate_interface_config(*args)
            if self.private_key:
                public_key = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                        format=serialization.PublicFormat.Raw)
                public_encoded = codecs.encode(public_key, 'base64').decode('utf8').strip()
                public_key = self._generate_config_line("PublicKey", public_encoded)
            else:
                public_key = ''

            allowed_ips = self._generate_config_line("AllowedIPs", str(allowed_ips))

            if not domain_name:
                domain_name = self._get_host_ip()
            port = self.listen_port
            interface_socket = f'{domain_name}:{port}'
            interface_socket = self._generate_config_line('Endpoint', interface_socket)

            config = f'{peer_interface}[Peer]\n{public_key}{allowed_ips}{interface_socket}'
            return config

    def update_config(self) -> None:
        config_path = os.path.join(self.config_dir, f'{self.name}.conf')
        process = subprocess.Popen(f'wg syncconf {self.name} <(wg-quick strip {config_path})',
                                   shell=True,
                                   executable='/bin/bash',
                                   stdout=subprocess.PIPE)
        process.wait()

    def run_interface(self) -> None:
        config_path = os.path.join(self.config_dir, f'{self.name}.conf')
        subprocess.run(['wg-quick', 'up', config_path], capture_output=True)

    def stop_interface(self) -> None:
        config_path = os.path.join(self.config_dir, f'{self.name}.conf')
        subprocess.run(['wg-quick', 'down', config_path], capture_output=True)

    def _generate_server_address(self):
        addresses = iter(self.network.hosts())
        return next(addresses)


def load_config(configuration_path: Path | str) -> WGInterface:
    interface = WGInterface()
    if isinstance(configuration_path, str):
        configuration_path = Path(configuration_path)
    if not configuration_path.exists():
        raise Exception
    interface.config_dir = os.path.dirname(configuration_path)
    interface.network = interface._config_network(configuration_path)
    interface.address = interface._config_address(configuration_path)
    interface.name = interface._config_name(configuration_path)
    interface.listen_port = interface._config_listen_port(configuration_path)
    interface.private_key = interface._config_private_key(configuration_path)
    interface.mtu = interface._config_mtu(configuration_path)
    interface.post_up_commands = interface._config_postup_commands(configuration_path)
    interface.post_down_commands = interface._config_postdown_commands(configuration_path)
    interface.peers = interface._config_peers(configuration_path)
    interface.peers_prefix = interface._set_most_common_peers_prefix()
    return interface


def create_new_interface(prefix: str,
                         network_prefix: int,
                         config_dir: Path | str,
                         mtu: int = None,
                         post_up_command_templates: list[str] = None,
                         post_down_command_templates: list[str] = None,
                         peers_prefix: int = 32) -> "WGInterface":
    interface = WGInterface()
    if isinstance(config_dir, str):
        config_dir = Path(config_dir)
    interface.config_dir = config_dir
    interface.name = interface._get_free_interface_name(config_dir, prefix)
    interface.network = interface._get_free_subnetwork(config_dir, network_prefix)
    interface.address = interface._generate_server_address()
    interface.listen_port = interface._get_free_port(config_dir)
    interface.private_key = interface._generate_private_key()
    interface.mtu = mtu
    if not post_up_command_templates:
        post_up_commands = []
    else:
        post_up_commands = interface.convert_command_templates(post_up_command_templates)
    interface.post_up_commands = post_up_commands

    if not post_down_command_templates:
        post_down_commands = []
    else:
        post_down_commands = interface.convert_command_templates(post_down_command_templates)
    interface.post_down_commands = post_down_commands
    interface.peers_prefix = peers_prefix
    return interface
