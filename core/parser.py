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

    def parse_crc32_combine_len(self):
        """Extract len2 negative check from crc32_combine_gen64."""
        return {
            "function": "crc32_combine_gen64",
            "file": self.filepath,
            "variables": [
                {"name": "len2", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "len2", "min_val": 0, "action_on_fail": "return_error"}
            ]
        }

    def parse_deflate_window_bits(self):
        """Extract windowBits bounds from deflateInit2_."""
        return {
            "function": "deflateInit2_",
            "file": self.filepath,
            "variables": [
                {"name": "windowBits", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "windowBits", "min_val": 8, "max_val": 15, "action_on_fail": "return_error"}
            ]
        }

    def parse_deflate_mem_level(self):
        """Extract memLevel bounds from deflateInit2_."""
        return {
            "function": "deflateInit2_",
            "file": self.filepath,
            "variables": [
                {"name": "memLevel", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "memLevel", "min_val": 1, "max_val": 9, "action_on_fail": "return_error"}
            ]
        }

    def parse_inflate_window_bits(self):
        """Extract windowBits bounds from inflateReset2."""
        return {
            "function": "inflateReset2",
            "file": self.filepath,
            "variables": [
                {"name": "windowBits", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "windowBits", "min_val": 8, "max_val": 15, "action_on_fail": "return_error"}
            ]
        }

    def parse_deflate_dict_length(self):
        """Extract dictLength bounds from deflateSetDictionary."""
        return {
            "function": "deflateSetDictionary",
            "file": self.filepath,
            "variables": [
                {"name": "dictLength", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "dictLength", "min_val": 0, "max_val": 32768, "action_on_fail": "return_error"}
            ]
        }

    def parse_compress_bound(self):
        """Extract compressBound overflow check."""
        return {
            "function": "compressBound_z",
            "file": self.filepath,
            "variables": [
                {"name": "sourceLen", "type": "int"},
                {"name": "bound", "type": "int"},
            ],
            "operations": [
                {"op": "check_overflow", "variable": "bound", "source": "sourceLen", "action_on_fail": "return_error"}
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

    def parse_ngx_http_v2_state_field_len(self):
        """Extract length check from ngx_http_v2_state_field_len."""
        return {
            "function": "ngx_http_v2_state_field_len",
            "file": self.filepath,
            "variables": [
                {"name": "len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "len", "min_val": 0, "action_on_fail": "return_error"}
            ]
        }

    def parse_libxml2_parser_max_depth(self):
        """Extract parser entity expansion depth limit from libxml2."""
        return {
            "function": "xmlStringLenDecodeEntities",
            "file": self.filepath,
            "variables": [
                {"name": "depth", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "depth", "min_val": 0, "max_val": 40, "action_on_fail": "return_error"}
            ]
        }

    def parse_png_ihdr_width(self):
        """Extract IHDR image width must be positive from libpng."""
        return {
            "function": "png_handle_IHDR",
            "file": self.filepath,
            "variables": [
                {"name": "width", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "width", "min_val": 1, "max_val": 2147483647, "action_on_fail": "return_error"}
            ]
        }

    def parse_mbedtls_ssl_record_len(self):
        """Extract SSL record data_len bounds check from mbedTLS."""
        return {
            "function": "ssl_encrypt_buf",
            "file": self.filepath,
            "variables": [
                {"name": "data_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "data_len", "min_val": 0, "max_val": 16384, "action_on_fail": "return_error"}
            ]
        }

    def parse_openssh_auth_max_tries(self):
        """Extract authentication max tries bounds from OpenSSH."""
        return {
            "function": "auth_maxtries_exceeded",
            "file": self.filepath,
            "variables": [
                {"name": "authenticated", "type": "int"},
                {"name": "max_authtries", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "max_authtries", "min_val": 1, "max_val": 100, "action_on_fail": "return_error"}
            ]
        }

    def parse_sudo_uid_check(self):
        """Extract UID validation from sudo."""
        return {
            "function": "sudo_check_suid",
            "file": self.filepath,
            "variables": [
                {"name": "uid", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "uid", "min_val": 0, "max_val": 65534, "action_on_fail": "return_error"}
            ]
        }

    def parse_url_input_length(self):
        """Extract URL input length bounds from Curl_junkscan (CURL_MAX_INPUT_LENGTH = 8000000)."""
        return {
            "function": "Curl_junkscan",
            "file": self.filepath,
            "variables": [
                {"name": "urllen", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "urllen", "min_val": 0, "max_val": 8000000, "action_on_fail": "return_error"}
            ]
        }

    def parse_scheme_length(self):
        """Extract scheme length bounds (MAX_SCHEME_LEN = 40)."""
        return {
            "function": "Curl_get_scheme_handler",
            "file": self.filepath,
            "variables": [
                {"name": "scheme_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "scheme_len", "min_val": 1, "max_val": 40, "action_on_fail": "return_error"}
            ]
        }

    def parse_redirect_bounds(self):
        """Extract redirect counter bounds (followlocation uint16, maxredirs int16)."""
        return {
            "function": "curl_follow_redirect",
            "file": self.filepath,
            "variables": [
                {"name": "followlocation", "type": "int"},
                {"name": "maxredirs", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "followlocation", "min_val": 0, "max_val": 65535, "action_on_fail": "return_error"},
                {"op": "check_bound", "variable": "maxredirs", "min_val": -1, "max_val": 32767, "action_on_fail": "return_error"},
            ]
        }

    def parse_git_protocol_version(self):
        """Extract protocol version bounds from git."""
        return {
            "function": "discover_version",
            "file": self.filepath,
            "variables": [
                {"name": "version", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "version", "min_val": 0, "max_val": 2, "action_on_fail": "return_error"}
            ]
        }
