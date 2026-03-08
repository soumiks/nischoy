import z3

class SecurityConstraints:
    """
    Decoupled security constraints for formal verification.
    These are the invariants we want to mathematically prove about the code.
    If the solver can find a state that satisfies the code's logic BUT violates 
    these constraints, it means there's a vulnerability.
    
    Each method returns a Z3 expression representing the VIOLATION condition.
    If Z3 returns UNSAT on the violation, the property is VERIFIED (green).
    If Z3 returns SAT, there is a potential vulnerability (red).
    """

    @staticmethod
    def port_bounds(vars_dict):
        """Port number must be 0-65535 after parsing and casting."""
        portnum = vars_dict.get('u->portnum')
        if portnum is None:
            return None
        return z3.Or(portnum < 0, portnum > 65535)

    @staticmethod
    def ipv6_bracket_integrity(vars_dict):
        """If hostname starts with '[', it must end with ']'."""
        host = vars_dict.get('hostname')
        if host is None:
            return None
        starts_bracket = z3.SubString(host, 0, 1) == z3.StringVal("[")
        ends_bracket = z3.SubString(host, z3.Length(host) - 1, 1) == z3.StringVal("]")
        # Violation: starts with [ but does NOT end with ]
        return z3.And(starts_bracket, z3.Not(ends_bracket))

    @staticmethod
    def no_crlf_in_credentials(vars_dict):
        """User and password must not contain CR or LF (header injection prevention)."""
        violations = []
        for field in ['user', 'password']:
            v = vars_dict.get(field)
            if v is not None:
                violations.append(z3.Contains(v, z3.StringVal("\r")))
                violations.append(z3.Contains(v, z3.StringVal("\n")))
        if not violations:
            return None
        return z3.Or(*violations)

    @staticmethod
    def no_control_chars_in_url(vars_dict):
        """No byte <= 31 or == 127 in the URL (request smuggling prevention)."""
        url = vars_dict.get('url')
        if url is None:
            return None
        # Check for specific dangerous control chars
        violations = []
        for code in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 
                     14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                     26, 27, 28, 29, 30, 31, 127]:
            violations.append(z3.Contains(url, z3.StringVal(chr(code))))
        return z3.Or(*violations)

    @staticmethod
    def hostname_no_dangerous_chars(vars_dict):
        """Hostname must not contain whitespace, #, ?, @, or other injection chars."""
        host = vars_dict.get('hostname')
        if host is None:
            return None
        dangerous = [' ', '\r', '\n', '\t', '/', ':', '#', '?', '!', 
                     '@', '{', '}', '[', '\\', '$', "'", '"', '^', 
                     '`', '*', '<', '>', '=', ';', ',', '+', '&', '(', ')']
        violations = []
        for ch in dangerous:
            violations.append(z3.Contains(host, z3.StringVal(ch)))
        return z3.Or(*violations)

    @staticmethod
    def adler32_len_bounds(vars_dict):
        """Length must be non-negative."""
        len2 = vars_dict.get('len2')
        if len2 is None:
            return None
        return len2 < 0

    @staticmethod
    def crc32_combine_len_bounds(vars_dict):
        """CRC32 combine length must be non-negative."""
        len2 = vars_dict.get('len2')
        if len2 is None:
            return None
        return len2 < 0

    @staticmethod
    def deflate_window_bits_bounds(vars_dict):
        """deflateInit2 windowBits must be 8..15 (after normalization)."""
        wb = vars_dict.get('windowBits')
        if wb is None:
            return None
        return z3.Or(wb < 8, wb > 15)

    @staticmethod
    def deflate_mem_level_bounds(vars_dict):
        """memLevel must be 1..9 (MAX_MEM_LEVEL)."""
        ml = vars_dict.get('memLevel')
        if ml is None:
            return None
        return z3.Or(ml < 1, ml > 9)

    @staticmethod
    def inflate_window_bits_bounds(vars_dict):
        """inflateReset2 windowBits must be 8..15 (after normalization)."""
        wb = vars_dict.get('windowBits')
        if wb is None:
            return None
        return z3.Or(wb < 8, wb > 15)

    @staticmethod
    def deflate_dict_length_bounds(vars_dict):
        """deflateSetDictionary dictLength must not exceed window size (32768 for MAX_WBITS=15)."""
        dl = vars_dict.get('dictLength')
        if dl is None:
            return None
        return z3.Or(dl < 0, dl > 32768)

    @staticmethod
    def compress_bound_no_overflow(vars_dict):
        """compressBound sourceLen must not cause wrap-around when computing the bound.
        bound = sourceLen + (sourceLen >> 12) + (sourceLen >> 14) + (sourceLen >> 25) + 13
        Violation if sourceLen is non-negative but the computed bound wraps (< sourceLen)."""
        src = vars_dict.get('sourceLen')
        if src is None:
            return None
        # Model the actual computation using integer division (equivalent to >> for non-negative)
        bound = src + (src / 4096) + (src / 16384) + (src / 33554432) + 13
        # Violation: non-negative src but bound wrapped around
        return z3.And(src >= 0, src <= 2**64 - 1, bound < src)

    @staticmethod
    def kdf_blake2b_subkey_len_bounds(vars_dict):
        """Subkey length must be between 16 and 64."""
        subkey_len = vars_dict.get('subkey_len')
        if subkey_len is None:
            return None
        return z3.Or(subkey_len < 16, subkey_len > 64)

    @staticmethod
    def crypto_secretbox_message_len_bounds(vars_dict):
        """Message length for crypto_secretbox_easy must not exceed MESSAGEBYTES_MAX."""
        mlen = vars_dict.get('mlen')
        if mlen is None:
            return None
        max_mlen = (1 << 64) - 1 - 16  # SODIUM_SIZE_MAX - crypto_secretbox_MACBYTES
        return z3.Or(mlen < 0, mlen > max_mlen)

    @staticmethod
    def crypto_secretbox_ciphertext_len_bounds(vars_dict):
        """Ciphertext length must include at least MACBYTES (16)."""
        clen = vars_dict.get('clen')
        if clen is None:
            return None
        return clen < 16

    @staticmethod
    def crypto_box_message_len_bounds(vars_dict):
        """crypto_box_easy enforces MESSAGEBYTES_MAX just like NaCl."""
        mlen = vars_dict.get('mlen')
        if mlen is None:
            return None
        max_mlen = (1 << 64) - 1 - 16  # SODIUM_SIZE_MAX - crypto_box_MACBYTES
        return z3.Or(mlen < 0, mlen > max_mlen)

    @staticmethod
    def crypto_box_ciphertext_len_bounds(vars_dict):
        """Ciphertext handed to crypto_box_open_easy must contain a MAC."""
        clen = vars_dict.get('clen')
        if clen is None:
            return None
        return clen < 16

    @staticmethod
    def sqlite3_limit_bounds(vars_dict):
        """limitId must be non-negative and within N_LIMIT."""
        limitId = vars_dict.get('limitId')
        if limitId is None:
            return None
        return z3.Or(limitId < 0, limitId > 12)

    @staticmethod
    def dsa_sig_len_bounds(vars_dict):
        """Length must be non-negative."""
        length = vars_dict.get('len')
        if length is None:
            return None
        return length < 0

    @staticmethod
    def nginx_field_len_bounds(vars_dict):
        """HTTP/2 field length must be non-negative."""
        length = vars_dict.get('len')
        if length is None:
            return None
        return length < 0

    @staticmethod
    def libxml2_depth_bounds(vars_dict):
        """Parser entity expansion depth must be within safe limits."""
        depth = vars_dict.get('depth')
        if depth is None:
            return None
        return z3.Or(depth < 0, depth > 40)

    @staticmethod
    def png_width_bounds(vars_dict):
        """PNG IHDR width must be positive and within INT_MAX."""
        width = vars_dict.get('width')
        if width is None:
            return None
        return z3.Or(width < 1, width > 2147483647)

    @staticmethod
    def mbedtls_record_len_bounds(vars_dict):
        """SSL record data length must be within max content length (16384)."""
        data_len = vars_dict.get('data_len')
        if data_len is None:
            return None
        return z3.Or(data_len < 0, data_len > 16384)

    @staticmethod
    def openssh_max_authtries_bounds(vars_dict):
        """Max auth tries must be positive and reasonable."""
        max_authtries = vars_dict.get('max_authtries')
        if max_authtries is None:
            return None
        return z3.Or(max_authtries < 1, max_authtries > 100)

    @staticmethod
    def sudo_uid_bounds(vars_dict):
        """UID must be within valid range."""
        uid = vars_dict.get('uid')
        if uid is None:
            return None
        return z3.Or(uid < 0, uid > 65534)

    @staticmethod
    def url_input_length_bounds(vars_dict):
        """URL length must be between 0 and CURL_MAX_INPUT_LENGTH (8000000)."""
        urllen = vars_dict.get('urllen')
        if urllen is None:
            return None
        return z3.Or(urllen < 0, urllen > 8000000)

    @staticmethod
    def scheme_length_bounds(vars_dict):
        """Scheme length must be between 1 and MAX_SCHEME_LEN (40)."""
        scheme_len = vars_dict.get('scheme_len')
        if scheme_len is None:
            return None
        return z3.Or(scheme_len < 1, scheme_len > 40)

    @staticmethod
    def redirect_counter_bounds(vars_dict):
        """Redirect counter must be within uint16 range; maxredirs within int16 range."""
        violations = []
        fl = vars_dict.get('followlocation')
        if fl is not None:
            violations.append(z3.Or(fl < 0, fl > 65535))
        mr = vars_dict.get('maxredirs')
        if mr is not None:
            violations.append(z3.Or(mr < -1, mr > 32767))
        if not violations:
            return None
        return z3.Or(*violations)

    @staticmethod
    def git_protocol_version_bounds(vars_dict):
        """Git protocol version must be 0, 1, or 2."""
        version = vars_dict.get('version')
        if version is None:
            return None
        return z3.Or(version < 0, version > 2)
