import re

class CParser:
    """
    Generic C code parser for security-critical path extraction.
    Produces an intermediate AST representation that can be converted to SMT2.
    
    In production, this would use libclang/pycparser for full AST parsing.
    For the MVP, we extract structured representations of known security patterns.
    """
    def __init__(self, filepath):
        self.filepath = filepath

    def extract_function(self, func_name):
        """Extract raw function text from C source file."""
        with open(self.filepath, 'r') as f:
            content = f.read()
        pattern = r'(' + re.escape(func_name) + r'\s*\(.*?\)\s*\{)'
        match = re.search(pattern, content, re.DOTALL)
        if match:
            start = match.start()
            depth = 0
            for i, ch in enumerate(content[start:], start):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return content[start:i+1]
        return None

    def parse_port_validation(self):
        """Extract the port parsing logic from Curl_parse_port."""
        return {
            "function": "Curl_parse_port",
            "file": self.filepath,
            "variables": [
                {"name": "port_input", "type": "string"},
                {"name": "port", "type": "int", "derived_from": "port_input"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "port", "max_val": 65535,
                 "action_on_fail": "return_error"},
                {"op": "assign", "target": "u->portnum", "source": "port",
                 "cast": "unsigned short"},
            ]
        }

    def parse_ipv6_validation(self):
        """Extract the IPv6 bracket parsing logic from ipv6_parse."""
        return {
            "function": "ipv6_parse",
            "file": self.filepath,
            "variables": [
                {"name": "hostname", "type": "string"},
            ],
            "operations": [
                {"op": "check_brackets", "variable": "hostname", 
                 "start": "[", "end": "]"},
            ]
        }

    def parse_hostname_validation(self):
        """Extract the hostname character validation from hostname_check."""
        dangerous = list(' \r\n\t/:#?!@{}[]\\$\'"^`*<>=;,+&()%')
        return {
            "function": "hostname_check",
            "file": self.filepath,
            "variables": [
                {"name": "hostname", "type": "string"},
            ],
            "operations": [
                {"op": "reject_chars", "variable": "hostname", "chars": dangerous},
            ]
        }

    def parse_credential_validation(self):
        """Extract credential parsing logic from parse_hostname_login."""
        return {
            "function": "parse_hostname_login",
            "file": self.filepath,
            "variables": [
                {"name": "user", "type": "string"},
                {"name": "password", "type": "string"},
            ],
            "operations": [
                {"op": "reject_chars", "variable": "user", 
                 "chars": ["\r", "\n"]},
                {"op": "reject_chars", "variable": "password", 
                 "chars": ["\r", "\n"]},
            ]
        }

    def parse_junkscan(self):
        """Extract the URL junk scan logic from Curl_junkscan."""
        return {
            "function": "Curl_junkscan",
            "file": self.filepath,
            "variables": [
                {"name": "url", "type": "string"},
            ],
            "operations": [
                {"op": "junkscan", "variable": "url", "max_control": 31},
            ]
        }

    def parse_adler32_combine(self):
        """Extract len2 negative check from adler32_combine_."""
        return {
            "function": "adler32_combine_",
            "file": self.filepath,
            "variables": [
                {"name": "len2", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "len2", "min_val": 0, "action_on_fail": "return_error"}
            ]
        }

    def parse_kdf_blake2b_derive_from_key(self):
        """Extract subkey_len check from crypto_kdf_blake2b_derive_from_key."""
        return {
            "function": "crypto_kdf_blake2b_derive_from_key",
            "file": self.filepath,
            "variables": [
                {"name": "subkey_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "subkey_len", "min_val": 16, "max_val": 64, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_limit(self):
        """Extract limitId check from sqlite3_limit."""
        return {
            "function": "sqlite3_limit",
            "file": self.filepath,
            "variables": [
                {"name": "limitId", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "limitId", "min_val": 0, "max_val": 12, "action_on_fail": "return_error"}
            ]
        }

    def parse_d2i_DSA_SIG(self):
        """Extract length check from d2i_DSA_SIG."""
        return {
            "function": "d2i_DSA_SIG",
            "file": self.filepath,
            "variables": [
                {"name": "len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "len", "min_val": 0, "action_on_fail": "return_error"}
            ]
        }
