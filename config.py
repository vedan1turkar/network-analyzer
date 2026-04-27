"""
Configuration Management - Loads and manages DONET configuration
"""

import os
import yaml
from typing import Dict, Any
from pathlib import Path

DEFAULT_CONFIG = {
    'threat_detection': {
        'suspicious_ports': {
            22: {'name': 'SSH', 'level': 'MEDIUM', 'description': 'SSH brute force target'},
            23: {'name': 'Telnet', 'level': 'HIGH', 'description': 'Insecure protocol'},
            25: {'name': 'SMTP', 'level': 'MEDIUM', 'description': 'Email server'},
            53: {'name': 'DNS', 'level': 'LOW', 'description': 'DNS queries'},
            69: {'name': 'TFTP', 'level': 'HIGH', 'description': 'Trivial FTP (often abused)'},
            110: {'name': 'POP3', 'level': 'MEDIUM', 'description': 'POP3 email'},
            135: {'name': 'RPC', 'level': 'HIGH', 'description': 'Remote Procedure Call'},
            139: {'name': 'NetBIOS', 'level': 'HIGH', 'description': 'NetBIOS Session Service'},
            143: {'name': 'IMAP', 'level': 'MEDIUM', 'description': 'IMAP email'},
            161: {'name': 'SNMP', 'level': 'MEDIUM', 'description': 'Simple Network Management'},
            389: {'name': 'LDAP', 'level': 'MEDIUM', 'description': 'Lightweight Directory Access'},
            445: {'name': 'SMB', 'level': 'HIGH', 'description': 'Server Message Block'},
            1433: {'name': 'MSSQL', 'level': 'HIGH', 'description': 'Microsoft SQL Server'},
            3306: {'name': 'MySQL', 'level': 'MEDIUM', 'description': 'MySQL database'},
            3389: {'name': 'RDP', 'level': 'HIGH', 'description': 'Remote Desktop Protocol'},
            5900: {'name': 'VNC', 'level': 'HIGH', 'description': 'Virtual Network Computing'},
            8080: {'name': 'HTTP-ALT', 'level': 'LOW', 'description': 'Alternate HTTP'},
            8443: {'name': 'HTTPS-ALT', 'level': 'LOW', 'description': 'Alternate HTTPS'},
        },
        'malicious_patterns': [
            {'pattern': r'(?i)(sqlmap|nmap|nikto|burp|metasploit)', 'level': 'HIGH', 'description': 'Known scanning/exploitation tool'},
            {'pattern': r'(?i)(<script>|javascript:|onload=|onerror=)', 'level': 'HIGH', 'description': 'XSS pattern'},
            {'pattern': r'(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table)', 'level': 'MEDIUM', 'description': 'SQL injection pattern'},
            {'pattern': r'(?i)(eval\(|exec\(|system\(|passthru\()', 'level': 'HIGH', 'description': 'Code execution pattern'},
            {'pattern': r'(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow)', 'level': 'MEDIUM', 'description': 'Path traversal'},
            {'pattern': r'(?i)(cmd\.exe|powershell|wscript|bitsadmin)', 'level': 'HIGH', 'description': 'Windows command execution'},
            {'pattern': r'(?i)(wget\s+http|curl\s+http|ftp\s+get)', 'level': 'MEDIUM', 'description': 'File download'},
        ],
        'port_scan_threshold': 10,
        'arp_time_window': 60,  # seconds
        'baseline_window': 300,  # seconds (5 minutes) for anomaly baseline
        'baseline_rate_threshold': 100,  # packets per second
        'baseline_port_diversity_threshold': 20,  # unique ports from single source
    },
    'logging': {
        'level': 'INFO',
        'file': None,  # None = console only, or path like 'donet.log'
        'max_bytes': 10485760,  # 10MB
        'backup_count': 5,
    },
    'performance': {
        'packet_sampling': 1,  # Process every N packets (1 = all)
        'max_tracker_entries': 1000,
    },
    'reporting': {
        'default_format': 'text',  # text, json, html
        'include_safe_packets': False,
        'verbose': False,
    }
}


class Config:
    """Configuration manager for DONET"""

    def __init__(self, config_path: str = None):
        """
        Initialize configuration

        Args:
            config_path: Path to config file (YAML). If None, uses default.
        """
        self.config = DEFAULT_CONFIG.copy()
        self.config_path = config_path

        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            # Try default locations
            default_locations = [
                Path.home() / '.donet' / 'config.yaml',
                Path('/etc/donet/config.yaml'),
                Path('./config.yaml'),
            ]
            for loc in default_locations:
                if loc.exists():
                    self._load_from_file(str(loc))
                    self.config_path = str(loc)
                    break

    def _load_from_file(self, path: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(path, 'r') as f:
                user_config = yaml.safe_load(f)
            self._deep_update(self.config, user_config)
        except Exception as e:
            print(f"Warning: Failed to load config from {path}: {e}")
            print("Using default configuration.")

    def _deep_update(self, base: Dict, update: Dict) -> None:
        """Recursively update dictionary"""
        for key, value in update.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            *keys: Hierarchical keys (e.g., 'threat_detection', 'suspicious_ports')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        current = self.config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def set(self, *keys: str, value: Any) -> None:
        """Set configuration value"""
        current = self.config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def save(self, path: str = None) -> bool:
        """
        Save configuration to file

        Args:
            path: File path (uses current config_path if None)

        Returns:
            True if successful
        """
        save_path = path or self.config_path
        if not save_path:
            save_path = str(Path.home() / '.donet' / 'config.yaml')
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            self.config_path = save_path
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def validate(self) -> list:
        """
        Validate configuration values

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Check numeric ranges
        port_scan = self.get('threat_detection', 'port_scan_threshold', default=10)
        if not isinstance(port_scan, int) or port_scan < 1:
            errors.append("port_scan_threshold must be a positive integer")

        arp_window = self.get('threat_detection', 'arp_time_window', default=60)
        if not isinstance(arp_window, (int, float)) or arp_window < 1:
            errors.append("arp_time_window must be a positive number")

        baseline_window = self.get('threat_detection', 'baseline_window', default=300)
        if not isinstance(baseline_window, (int, float)) or baseline_window < 10:
            errors.append("baseline_window must be at least 10 seconds")

        rate_threshold = self.get('threat_detection', 'baseline_rate_threshold', default=100)
        if not isinstance(rate_threshold, (int, float)) or rate_threshold < 1:
            errors.append("baseline_rate_threshold must be positive")

        port_diversity = self.get('threat_detection', 'baseline_port_diversity_threshold', default=20)
        if not isinstance(port_diversity, int) or port_diversity < 1:
            errors.append("baseline_port_diversity_threshold must be a positive integer")

        sample_rate = self.get('performance', 'packet_sampling', default=1)
        if not isinstance(sample_rate, int) or sample_rate < 1:
            errors.append("packet_sampling must be a positive integer (>=1)")

        max_entries = self.get('performance', 'max_tracker_entries', default=1000)
        if not isinstance(max_entries, int) or max_entries < 100:
            errors.append("max_tracker_entries must be an integer >= 100")

        # Check logging level
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        log_level = self.get('logging', 'level', default='INFO')
        if log_level.upper() not in valid_levels:
            errors.append(f"logging.level must be one of {valid_levels}")

        return errors

    def to_dict(self) -> Dict:
        """Return full configuration as dictionary"""
        return self.config.copy()
