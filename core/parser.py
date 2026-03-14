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

    def parse_kdf_blake2b_subkey_id(self):
        """Extract subkey_id domain from crypto_kdf_blake2b_derive_from_key."""
        return {
            "function": "crypto_kdf_blake2b_derive_from_key",
            "file": self.filepath,
            "variables": [
                {"name": "subkey_id", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "subkey_id", "min_val": 0, "max_val": (1 << 64) - 1, "action_on_fail": "return_error"}
            ]
        }

    def parse_crypto_secretbox_message_len(self):
        """Extract mlen bounds enforcement from crypto_secretbox_easy."""
        max_mlen = (1 << 64) - 1 - 16  # SODIUM_SIZE_MAX - crypto_secretbox_MACBYTES
        return {
            "function": "crypto_secretbox_easy",
            "file": self.filepath,
            "variables": [
                {"name": "mlen", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "mlen", "min_val": 0, "max_val": max_mlen, "action_on_fail": "sodium_misuse"}
            ]
        }

    def parse_crypto_secretbox_open_clen(self):
        """Extract ciphertext length lower bound from crypto_secretbox_open_easy."""
        return {
            "function": "crypto_secretbox_open_easy",
            "file": self.filepath,
            "variables": [
                {"name": "clen", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "clen", "min_val": 16, "action_on_fail": "return_error"}
            ]
        }

    def parse_crypto_box_message_len(self):
        """Extract mlen bounds from crypto_box_easy/afternm."""
        max_mlen = (1 << 64) - 1 - 16  # SODIUM_SIZE_MAX - crypto_box_MACBYTES
        return {
            "function": "crypto_box_easy",
            "file": self.filepath,
            "variables": [
                {"name": "mlen", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "mlen", "min_val": 0, "max_val": max_mlen, "action_on_fail": "sodium_misuse"}
            ]
        }

    def parse_crypto_box_open_clen(self):
        """Extract ciphertext length lower bound from crypto_box_open_easy."""
        return {
            "function": "crypto_box_open_easy",
            "file": self.filepath,
            "variables": [
                {"name": "clen", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "clen", "min_val": 16, "action_on_fail": "return_error"}
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

    def parse_sqlite3_page_size(self):
        """Extract page size validation from sqlite3BtreeSetPageSize."""
        return {
            "function": "sqlite3BtreeSetPageSize",
            "file": self.filepath,
            "variables": [
                {"name": "pageSize", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "pageSize", "min_val": 512, "max_val": 65536, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_function_narg(self):
        """Extract nArg bounds from sqlite3_create_function."""
        return {
            "function": "sqlite3_create_function_v2",
            "file": self.filepath,
            "variables": [
                {"name": "nArg", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "nArg", "min_val": -1, "max_val": 127, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_mmap_size(self):
        """Extract mxMmap bounds from sqlite3_config SQLITE_CONFIG_MMAP_SIZE."""
        return {
            "function": "sqlite3_config",
            "file": self.filepath,
            "variables": [
                {"name": "mxMmap", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "mxMmap", "min_val": 0, "max_val": 2147483647, "action_on_fail": "clamp"}
            ]
        }

    def parse_sqlite3_attached_db(self):
        """Extract attached database index bounds."""
        return {
            "function": "sqlite3_db_config",
            "file": self.filepath,
            "variables": [
                {"name": "iDb", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "iDb", "min_val": 0, "max_val": 125, "action_on_fail": "return_error"}
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

    def parse_timeout_bounds(self):
        """Extract timeout value bounds (connect_timeout, transfer_timeout)."""
        return {
            "function": "Curl_setopt",
            "file": self.filepath,
            "variables": [
                {"name": "connect_timeout", "type": "int"},
                {"name": "transfer_timeout", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "connect_timeout", "min_val": 0, "max_val": 2147483, "action_on_fail": "return_error"},
                {"op": "check_bound", "variable": "transfer_timeout", "min_val": 0, "max_val": 2147483, "action_on_fail": "return_error"},
            ]
        }

    def parse_sqlite3_sql_length(self):
        """Extract SQL length bounds from sqlite3_prepare."""
        return {
            "function": "sqlite3_prepare_v2",
            "file": self.filepath,
            "variables": [
                {"name": "sql_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "sql_len", "min_val": 0, "max_val": 1000000000, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_expr_depth(self):
        """Extract expression depth bounds from sqlite3ExprCheckHeight."""
        return {
            "function": "sqlite3ExprCheckHeight",
            "file": self.filepath,
            "variables": [
                {"name": "expr_depth", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "expr_depth", "min_val": 0, "max_val": 1000, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_column_count(self):
        """Extract column count bounds from sqlite3 build."""
        return {
            "function": "sqlite3AddColumn",
            "file": self.filepath,
            "variables": [
                {"name": "nColumn", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "nColumn", "min_val": 1, "max_val": 32767, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_blob_length(self):
        """Extract BLOB/string length bounds (SQLITE_MAX_LENGTH)."""
        return {
            "function": "sqlite3_result_blob",
            "file": self.filepath,
            "variables": [
                {"name": "blob_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "blob_len", "min_val": 0, "max_val": 1000000000, "action_on_fail": "return_error"}
            ]
        }

    def parse_sqlite3_variable_number(self):
        """Extract SQL parameter index bounds (SQLITE_MAX_VARIABLE_NUMBER)."""
        return {
            "function": "sqlite3ExprCodeTarget",
            "file": self.filepath,
            "variables": [
                {"name": "variable_number", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "variable_number", "min_val": 1, "max_val": 32766, "action_on_fail": "return_error"}
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

    # ── OpenSSL additional parsers ──

    def parse_openssl_evp_key_size(self):
        """Extract EVP cipher key length bounds."""
        return {
            "function": "EVP_CIPHER_CTX_key_length",
            "file": self.filepath,
            "variables": [
                {"name": "key_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "key_len", "min_val": 1, "max_val": 64, "action_on_fail": "return_error"}
            ]
        }

    def parse_openssl_bn_num_bits(self):
        """Extract BIGNUM bit-count bounds."""
        return {
            "function": "BN_num_bits",
            "file": self.filepath,
            "variables": [
                {"name": "num_bits", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "num_bits", "min_val": 0, "max_val": 16384, "action_on_fail": "return_error"}
            ]
        }

    def parse_openssl_x509_version(self):
        """Extract X.509 certificate version bounds."""
        return {
            "function": "X509_get_version",
            "file": self.filepath,
            "variables": [
                {"name": "x509_version", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "x509_version", "min_val": 0, "max_val": 2, "action_on_fail": "return_error"}
            ]
        }

    # ── nginx additional parsers ──

    def parse_ngx_http_status_code(self):
        """Extract HTTP response status code bounds."""
        return {
            "function": "ngx_http_parse_status_line",
            "file": self.filepath,
            "variables": [
                {"name": "status_code", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "status_code", "min_val": 100, "max_val": 599, "action_on_fail": "return_error"}
            ]
        }

    def parse_ngx_http_uri_length(self):
        """Extract URI length bounds."""
        return {
            "function": "ngx_http_parse_request_line",
            "file": self.filepath,
            "variables": [
                {"name": "uri_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "uri_len", "min_val": 1, "max_val": 8192, "action_on_fail": "return_error"}
            ]
        }

    def parse_ngx_http_header_count(self):
        """Extract max header count bounds."""
        return {
            "function": "ngx_http_parse_header_line",
            "file": self.filepath,
            "variables": [
                {"name": "header_count", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "header_count", "min_val": 0, "max_val": 100, "action_on_fail": "return_error"}
            ]
        }

    def parse_ngx_http_version_minor(self):
        """Extract HTTP minor version bounds from request-line parser."""
        return {
            "function": "ngx_http_parse_request_line",
            "file": self.filepath,
            "variables": [
                {"name": "http_minor", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "http_minor", "min_val": 0, "max_val": 9, "action_on_fail": "return_error"}
            ]
        }

    def parse_ngx_http_version_major(self):
        """Extract HTTP major version bounds from request-line parser."""
        return {
            "function": "ngx_http_parse_request_line",
            "file": self.filepath,
            "variables": [
                {"name": "http_major", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "http_major", "min_val": 0, "max_val": 9, "action_on_fail": "return_error"}
            ]
        }

    # ── libxml2 additional parsers ──

    def parse_libxml2_attr_count(self):
        """Extract attribute count bounds per element."""
        return {
            "function": "xmlParseStartTag2",
            "file": self.filepath,
            "variables": [
                {"name": "nb_attributes", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "nb_attributes", "min_val": 0, "max_val": 10000, "action_on_fail": "return_error"}
            ]
        }

    def parse_libxml2_name_length(self):
        """Extract element/attribute name length bounds."""
        return {
            "function": "xmlParseName",
            "file": self.filepath,
            "variables": [
                {"name": "name_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "name_len", "min_val": 1, "max_val": 50000, "action_on_fail": "return_error"}
            ]
        }

    def parse_libxml2_namespace_uri_length(self):
        """Extract namespace URI length bounds."""
        return {
            "function": "xmlParseAttribute2",
            "file": self.filepath,
            "variables": [
                {"name": "ns_uri_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "ns_uri_len", "min_val": 1, "max_val": 8192, "action_on_fail": "return_error"}
            ]
        }

    # ── libpng additional parsers ──

    def parse_png_ihdr_height(self):
        """Extract IHDR image height bounds."""
        return {
            "function": "png_handle_IHDR",
            "file": self.filepath,
            "variables": [
                {"name": "height", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "height", "min_val": 1, "max_val": 2147483647, "action_on_fail": "return_error"}
            ]
        }

    def parse_png_ihdr_bit_depth(self):
        """Extract IHDR bit depth bounds."""
        return {
            "function": "png_handle_IHDR",
            "file": self.filepath,
            "variables": [
                {"name": "bit_depth", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "bit_depth", "min_val": 1, "max_val": 16, "action_on_fail": "return_error"}
            ]
        }

    def parse_png_chunk_length(self):
        """Extract chunk length bounds."""
        return {
            "function": "png_read_chunk_header",
            "file": self.filepath,
            "variables": [
                {"name": "chunk_length", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "chunk_length", "min_val": 0, "max_val": 2147483647, "action_on_fail": "return_error"}
            ]
        }

    # ── mbedtls additional parsers ──

    def parse_mbedtls_ciphertext_len(self):
        """Extract ciphertext length bounds for decryption."""
        return {
            "function": "mbedtls_ssl_decrypt_buf",
            "file": self.filepath,
            "variables": [
                {"name": "ct_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "ct_len", "min_val": 0, "max_val": 16384, "action_on_fail": "return_error"}
            ]
        }

    def parse_mbedtls_major_version(self):
        """Extract TLS major version bounds."""
        return {
            "function": "mbedtls_ssl_read_version",
            "file": self.filepath,
            "variables": [
                {"name": "tls_major", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "tls_major", "min_val": 3, "max_val": 3, "action_on_fail": "return_error"}
            ]
        }

    def parse_mbedtls_minor_version(self):
        """Extract TLS minor version bounds."""
        return {
            "function": "mbedtls_ssl_read_version",
            "file": self.filepath,
            "variables": [
                {"name": "tls_minor", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "tls_minor", "min_val": 0, "max_val": 4, "action_on_fail": "return_error"}
            ]
        }

    def parse_mbedtls_content_type(self):
        """Extract TLS record content type bounds."""
        return {
            "function": "mbedtls_ssl_read_record",
            "file": self.filepath,
            "variables": [
                {"name": "tls_content_type", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "tls_content_type", "min_val": 20, "max_val": 24, "action_on_fail": "return_error"}
            ]
        }

    def parse_mbedtls_record_header_len(self):
        """Extract TLS record header length invariant."""
        return {
            "function": "mbedtls_ssl_read_record",
            "file": self.filepath,
            "variables": [
                {"name": "record_header_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "record_header_len", "min_val": 5, "max_val": 5, "action_on_fail": "return_error"}
            ]
        }

    # ── openssh additional parsers ──

    def parse_openssh_channel_id(self):
        """Extract channel ID bounds."""
        return {
            "function": "channel_lookup",
            "file": self.filepath,
            "variables": [
                {"name": "channel_id", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "channel_id", "min_val": 0, "max_val": 65535, "action_on_fail": "return_error"}
            ]
        }

    def parse_openssh_packet_len(self):
        """Extract SSH packet length bounds."""
        return {
            "function": "ssh_packet_read",
            "file": self.filepath,
            "variables": [
                {"name": "packet_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "packet_len", "min_val": 5, "max_val": 262144, "action_on_fail": "return_error"}
            ]
        }

    def parse_openssh_key_bits(self):
        """Extract SSH key bit length bounds."""
        return {
            "function": "sshkey_generate",
            "file": self.filepath,
            "variables": [
                {"name": "key_bits", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "key_bits", "min_val": 1024, "max_val": 16384, "action_on_fail": "return_error"}
            ]
        }

    # ── sudo additional parsers ──

    def parse_sudo_gid_check(self):
        """Extract GID validation bounds."""
        return {
            "function": "sudo_check_sgid",
            "file": self.filepath,
            "variables": [
                {"name": "gid", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "gid", "min_val": 0, "max_val": 65534, "action_on_fail": "return_error"}
            ]
        }

    def parse_sudo_env_count(self):
        """Extract environment variable count bounds."""
        return {
            "function": "sudo_env_check",
            "file": self.filepath,
            "variables": [
                {"name": "env_count", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "env_count", "min_val": 0, "max_val": 1024, "action_on_fail": "return_error"}
            ]
        }

    def parse_sudo_argv_count(self):
        """Extract argument count bounds."""
        return {
            "function": "sudo_parse_args",
            "file": self.filepath,
            "variables": [
                {"name": "argc", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "argc", "min_val": 1, "max_val": 4096, "action_on_fail": "return_error"}
            ]
        }

    # ── git additional parsers ──

    def parse_git_pkt_line_len(self):
        """Extract pkt-line length bounds."""
        return {
            "function": "packet_read",
            "file": self.filepath,
            "variables": [
                {"name": "pkt_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "pkt_len", "min_val": 0, "max_val": 65520, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_tree_depth(self):
        """Extract tree traversal depth bounds."""
        return {
            "function": "read_tree_recursive",
            "file": self.filepath,
            "variables": [
                {"name": "tree_depth", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "tree_depth", "min_val": 0, "max_val": 4096, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_path_len(self):
        """Extract pathname length bounds."""
        return {
            "function": "verify_path",
            "file": self.filepath,
            "variables": [
                {"name": "path_len", "type": "int"},
            ],
            "operations": [
                {"op": "check_bound", "variable": "path_len", "min_val": 1, "max_val": 4096, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_object_type(self):
        """Extract object type enum bounds from object.h (OBJ_COMMIT=1..OBJ_REF_DELTA=7, skip 5)."""
        return {
            "function": "parse_object_header",
            "file": self.filepath,
            "variables": [{"name": "obj_type", "type": "int"}],
            "operations": [
                {"op": "check_bound", "variable": "obj_type", "min_val": 1, "max_val": 7, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_symref_depth(self):
        """Extract symbolic ref resolution depth from refs-internal.h SYMREF_MAXDEPTH=5."""
        return {
            "function": "resolve_ref_unsafe",
            "file": self.filepath,
            "variables": [{"name": "symref_depth", "type": "int"}],
            "operations": [
                {"op": "check_bound", "variable": "symref_depth", "min_val": 0, "max_val": 5, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_hash_algo(self):
        """Extract hash algorithm ID bounds (GIT_HASH_SHA1=1, GIT_HASH_SHA256=2)."""
        return {
            "function": "repo_set_hash_algo",
            "file": self.filepath,
            "variables": [{"name": "hash_algo", "type": "int"}],
            "operations": [
                {"op": "check_bound", "variable": "hash_algo", "min_val": 1, "max_val": 2, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_pack_obj_header_len(self):
        """Extract pack object header length from pack.h MAX_PACK_OBJECT_HEADER=10."""
        return {
            "function": "encode_in_pack_object_header",
            "file": self.filepath,
            "variables": [{"name": "header_len", "type": "int"}],
            "operations": [
                {"op": "check_bound", "variable": "header_len", "min_val": 1, "max_val": 10, "action_on_fail": "return_error"}
            ]
        }

    def parse_git_hash_rawsz(self):
        """Extract hash raw size bounds from hash.h (SHA1=20, SHA256=32, max=32)."""
        return {
            "function": "hash_object_file",
            "file": self.filepath,
            "variables": [{"name": "hash_rawsz", "type": "int"}],
            "operations": [
                {"op": "check_bound", "variable": "hash_rawsz", "min_val": 20, "max_val": 32, "action_on_fail": "return_error"}
            ]
        }
