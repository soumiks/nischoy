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
    def deflate_dict_length_uint16_fit(vars_dict):
        """deflateSetDictionary dictLength must fit in uint16-sized copy counters."""
        dl = vars_dict.get('dictLength')
        if dl is None:
            return None
        return z3.Or(dl < 0, dl > 65535)

    @staticmethod
    def kdf_blake2b_subkey_len_bounds(vars_dict):
        """Subkey length must be between 16 and 64."""
        subkey_len = vars_dict.get('subkey_len')
        if subkey_len is None:
            return None
        return z3.Or(subkey_len < 16, subkey_len > 64)

    @staticmethod
    def kdf_blake2b_subkey_id_bounds(vars_dict):
        """Subkey ID must stay within uint64 domain."""
        subkey_id = vars_dict.get('subkey_id')
        if subkey_id is None:
            return None
        return z3.Or(subkey_id < 0, subkey_id > (1 << 64) - 1)

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
    def crypto_box_plaintext_len_nonnegative(vars_dict):
        """After stripping MACBYTES, plaintext length must not underflow."""
        clen = vars_dict.get('clen')
        if clen is None:
            return None
        return (clen - 16) < 0

    @staticmethod
    def sqlite3_limit_bounds(vars_dict):
        """limitId must be non-negative and within N_LIMIT."""
        limitId = vars_dict.get('limitId')
        if limitId is None:
            return None
        return z3.Or(limitId < 0, limitId > 12)

    @staticmethod
    def sqlite3_page_size_bounds(vars_dict):
        """pageSize must be 512..65536 (SQLITE_MAX_PAGE_SIZE)."""
        ps = vars_dict.get('pageSize')
        if ps is None:
            return None
        return z3.Or(ps < 512, ps > 65536)

    @staticmethod
    def sqlite3_sql_length_bounds(vars_dict):
        """SQL statement length must be positive and <= SQLITE_MAX_SQL_LENGTH (1000000000)."""
        sql_len = vars_dict.get('sql_len')
        if sql_len is None:
            return None
        return z3.Or(sql_len < 0, sql_len > 1000000000)

    @staticmethod
    def sqlite3_expr_depth_bounds(vars_dict):
        """Expression tree depth must be within SQLITE_MAX_EXPR_DEPTH (1000)."""
        depth = vars_dict.get('expr_depth')
        if depth is None:
            return None
        return z3.Or(depth < 0, depth > 1000)

    @staticmethod
    def sqlite3_column_count_bounds(vars_dict):
        """Column count must be 1..SQLITE_MAX_COLUMN (2000, hard max 32767)."""
        ncol = vars_dict.get('nColumn')
        if ncol is None:
            return None
        return z3.Or(ncol < 1, ncol > 32767)

    @staticmethod
    def sqlite3_attached_db_bounds(vars_dict):
        """Attached database index must be between 0 and SQLITE_MAX_ATTACHED (125)."""
        iDb = vars_dict.get('iDb')
        if iDb is None:
            return None
        return z3.Or(iDb < 0, iDb > 125)

    @staticmethod
    def sqlite3_blob_length_bounds(vars_dict):
        """BLOB/string length must not exceed SQLITE_MAX_LENGTH (1000000000)."""
        blob_len = vars_dict.get('blob_len')
        if blob_len is None:
            return None
        return z3.Or(blob_len < 0, blob_len > 1000000000)

    @staticmethod
    def sqlite3_function_narg_bounds(vars_dict):
        """nArg must be between -1 (any) and SQLITE_MAX_FUNCTION_ARG (127)."""
        nArg = vars_dict.get('nArg')
        if nArg is None:
            return None
        return z3.Or(nArg < -1, nArg > 127)

    @staticmethod
    def sqlite3_mmap_size_bounds(vars_dict):
        """mxMmap must be non-negative; negative values are clamped to SQLITE_MAX_MMAP_SIZE."""
        mxMmap = vars_dict.get('mxMmap')
        if mxMmap is None:
            return None
        return mxMmap < 0

    @staticmethod
    def sqlite3_variable_number_bounds(vars_dict):
        """SQL parameter index (?NNN) must be between 1 and SQLITE_MAX_VARIABLE_NUMBER (32766)."""
        var_num = vars_dict.get('variable_number')
        if var_num is None:
            return None
        return z3.Or(var_num < 1, var_num > 32766)

    @staticmethod
    def sqlite3_trigger_depth_bounds(vars_dict):
        """Trigger recursion depth must be between 0 and SQLITE_MAX_TRIGGER_DEPTH (1000)."""
        depth = vars_dict.get('trigger_depth')
        if depth is None:
            return None
        return z3.Or(depth < 0, depth > 1000)

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
    def timeout_value_bounds(vars_dict):
        """Connection/transfer timeouts must be non-negative and within long range to prevent overflow in ms conversion."""
        violations = []
        for field in ['connect_timeout', 'transfer_timeout']:
            v = vars_dict.get(field)
            if v is not None:
                # Must be >= 0 and <= 2^31-1 (fits signed 32-bit after sec→ms multiply)
                violations.append(z3.Or(v < 0, v > 2147483))
        if not violations:
            return None
        return z3.Or(*violations)

    @staticmethod
    def dns_name_length_bounds(vars_dict):
        """DNS hostname length must be 1-253 chars per RFC 1035 to prevent buffer overflow in resolver."""
        hostname_len = vars_dict.get('hostname_len')
        if hostname_len is None:
            return None
        return z3.Or(hostname_len < 1, hostname_len > 253)

    @staticmethod
    def dns_label_length_bounds(vars_dict):
        """Each DNS label (between dots) must be 1-63 chars per RFC 1035 §2.3.4."""
        label_len = vars_dict.get('label_len')
        if label_len is None:
            return None
        return z3.Or(label_len < 1, label_len > 63)

    @staticmethod
    def git_protocol_version_bounds(vars_dict):
        """Git protocol version must be 0, 1, or 2."""
        version = vars_dict.get('version')
        if version is None:
            return None
        return z3.Or(version < 0, version > 2)

    # ── OpenSSL additional constraints ──

    @staticmethod
    def openssl_evp_key_size_bounds(vars_dict):
        """EVP cipher key length must be 1-64 bytes."""
        key_len = vars_dict.get('key_len')
        if key_len is None:
            return None
        return z3.Or(key_len < 1, key_len > 64)

    @staticmethod
    def openssl_bn_num_bits_bounds(vars_dict):
        """BIGNUM bit count must be 0-16384."""
        num_bits = vars_dict.get('num_bits')
        if num_bits is None:
            return None
        return z3.Or(num_bits < 0, num_bits > 16384)

    @staticmethod
    def openssl_x509_version_bounds(vars_dict):
        """X.509 version must be 0 (v1), 1 (v2), or 2 (v3)."""
        v = vars_dict.get('x509_version')
        if v is None:
            return None
        return z3.Or(v < 0, v > 2)

    @staticmethod
    def openssl_tls_version_bounds(vars_dict):
        """TLS wire version must be between 0x0300 (SSL 3.0) and 0x0304 (TLS 1.3)."""
        v = vars_dict.get('tls_version')
        if v is None:
            return None
        return z3.Or(v < 0x0300, v > 0x0304)

    # ── nginx additional constraints ──

    @staticmethod
    def nginx_status_code_bounds(vars_dict):
        """HTTP status code must be 100-599."""
        sc = vars_dict.get('status_code')
        if sc is None:
            return None
        return z3.Or(sc < 100, sc > 599)

    @staticmethod
    def nginx_uri_length_bounds(vars_dict):
        """URI length must be 1-8192."""
        ul = vars_dict.get('uri_len')
        if ul is None:
            return None
        return z3.Or(ul < 1, ul > 8192)

    @staticmethod
    def nginx_header_count_bounds(vars_dict):
        """Header count must be 0-100."""
        hc = vars_dict.get('header_count')
        if hc is None:
            return None
        return z3.Or(hc < 0, hc > 100)

    @staticmethod
    def nginx_http_minor_version_bounds(vars_dict):
        """HTTP minor version must be 0-9."""
        minor = vars_dict.get('http_minor')
        if minor is None:
            return None
        return z3.Or(minor < 0, minor > 9)

    @staticmethod
    def nginx_http_major_version_bounds(vars_dict):
        """HTTP major version must be 0-9."""
        major = vars_dict.get('http_major')
        if major is None:
            return None
        return z3.Or(major < 0, major > 9)

    @staticmethod
    def nginx_header_name_length_bounds(vars_dict):
        """Single HTTP header name length must be 1-1024."""
        hnl = vars_dict.get('header_name_len')
        if hnl is None:
            return None
        return z3.Or(hnl < 1, hnl > 1024)

    # ── libxml2 additional constraints ──

    @staticmethod
    def libxml2_attr_count_bounds(vars_dict):
        """Attribute count per element must be 0-10000."""
        nb = vars_dict.get('nb_attributes')
        if nb is None:
            return None
        return z3.Or(nb < 0, nb > 10000)

    @staticmethod
    def libxml2_name_length_bounds(vars_dict):
        """Element/attribute name length must be 1-50000."""
        nl = vars_dict.get('name_len')
        if nl is None:
            return None
        return z3.Or(nl < 1, nl > 50000)

    @staticmethod
    def libxml2_namespace_uri_length_bounds(vars_dict):
        """Namespace URI length must be 1-8192 to prevent memory exhaustion."""
        uri_len = vars_dict.get('ns_uri_len')
        if uri_len is None:
            return None
        return z3.Or(uri_len < 1, uri_len > 8192)

    @staticmethod
    def libxml2_encoding_decl_length_bounds(vars_dict):
        """Encoding declaration length must be 1-40 to prevent buffer overread."""
        enc_len = vars_dict.get('encoding_decl_len')
        if enc_len is None:
            return None
        return z3.Or(enc_len < 1, enc_len > 40)

    # ── libpng additional constraints ──

    @staticmethod
    def png_height_bounds(vars_dict):
        """PNG IHDR height must be positive and within INT_MAX."""
        h = vars_dict.get('height')
        if h is None:
            return None
        return z3.Or(h < 1, h > 2147483647)

    @staticmethod
    def png_bit_depth_bounds(vars_dict):
        """PNG bit depth must be 1-16."""
        bd = vars_dict.get('bit_depth')
        if bd is None:
            return None
        return z3.Or(bd < 1, bd > 16)

    @staticmethod
    def png_chunk_length_bounds(vars_dict):
        """PNG chunk length must be non-negative and within INT_MAX."""
        cl = vars_dict.get('chunk_length')
        if cl is None:
            return None
        return z3.Or(cl < 0, cl > 2147483647)

    # ── mbedtls additional constraints ──

    @staticmethod
    def mbedtls_ciphertext_len_bounds(vars_dict):
        """Ciphertext length must be 0-16384."""
        ct = vars_dict.get('ct_len')
        if ct is None:
            return None
        return z3.Or(ct < 0, ct > 16384)

    @staticmethod
    def mbedtls_major_version_bounds(vars_dict):
        """TLS major version must be exactly 3."""
        mv = vars_dict.get('tls_major')
        if mv is None:
            return None
        return z3.Or(mv < 3, mv > 3)

    @staticmethod
    def mbedtls_minor_version_bounds(vars_dict):
        """TLS minor version must be 0-4."""
        mv = vars_dict.get('tls_minor')
        if mv is None:
            return None
        return z3.Or(mv < 0, mv > 4)

    @staticmethod
    def mbedtls_content_type_bounds(vars_dict):
        """TLS record content type must be between 20 and 24."""
        ct = vars_dict.get('tls_content_type')
        if ct is None:
            return None
        return z3.Or(ct < 20, ct > 24)

    @staticmethod
    def mbedtls_record_header_len_bounds(vars_dict):
        """TLS record header length must be exactly 5 bytes."""
        header_len = vars_dict.get('record_header_len')
        if header_len is None:
            return None
        return z3.Or(header_len < 5, header_len > 5)

    @staticmethod
    def mbedtls_handshake_msg_len_bounds(vars_dict):
        """TLS handshake message length (uint24) must be 0..16777215."""
        msg_len = vars_dict.get('handshake_msg_len')
        if msg_len is None:
            return None
        return z3.Or(msg_len < 0, msg_len > 16777215)

    # ── openssh additional constraints ──

    @staticmethod
    def openssh_channel_id_bounds(vars_dict):
        """Channel ID must be 0-65535."""
        cid = vars_dict.get('channel_id')
        if cid is None:
            return None
        return z3.Or(cid < 0, cid > 65535)

    @staticmethod
    def openssh_packet_len_bounds(vars_dict):
        """SSH packet length must be 5-262144."""
        pl = vars_dict.get('packet_len')
        if pl is None:
            return None
        return z3.Or(pl < 5, pl > 262144)

    @staticmethod
    def openssh_key_bits_bounds(vars_dict):
        """SSH key bit length must be 1024-16384."""
        key_bits = vars_dict.get('key_bits')
        if key_bits is None:
            return None
        return z3.Or(key_bits < 1024, key_bits > 16384)

    @staticmethod
    def openssh_padding_len_bounds(vars_dict):
        """SSH packet padding must be 4-255 bytes (RFC 4253 §6)."""
        padding_len = vars_dict.get('padding_len')
        if padding_len is None:
            return None
        return z3.Or(padding_len < 4, padding_len > 255)

    @staticmethod
    def openssh_kex_proposal_len_bounds(vars_dict):
        """KEX proposal string length must be 1-32768 bytes to prevent memory exhaustion."""
        kex_len = vars_dict.get('kex_proposal_len')
        if kex_len is None:
            return None
        return z3.Or(kex_len < 1, kex_len > 32768)

    # ── sudo additional constraints ──

    @staticmethod
    def sudo_gid_bounds(vars_dict):
        """GID must be 0-65534."""
        gid = vars_dict.get('gid')
        if gid is None:
            return None
        return z3.Or(gid < 0, gid > 65534)

    @staticmethod
    def sudo_env_count_bounds(vars_dict):
        """Environment variable count must be 0-1024."""
        ec = vars_dict.get('env_count')
        if ec is None:
            return None
        return z3.Or(ec < 0, ec > 1024)

    @staticmethod
    def sudo_argv_count_bounds(vars_dict):
        """Argument count must be 1-4096."""
        ac = vars_dict.get('argc')
        if ac is None:
            return None
        return z3.Or(ac < 1, ac > 4096)

    # ── git additional constraints ──

    @staticmethod
    def git_pkt_line_len_bounds(vars_dict):
        """pkt-line length must be 0-65520."""
        pl = vars_dict.get('pkt_len')
        if pl is None:
            return None
        return z3.Or(pl < 0, pl > 65520)

    @staticmethod
    def git_hash_rawsz_allowed_set(vars_dict):
        """Hash raw size must be an exact supported digest width (SHA-1 or SHA-256)."""
        hr = vars_dict.get('hash_rawsz')
        if hr is None:
            return None
        return z3.Not(z3.Or(hr == 20, hr == 32))

    @staticmethod
    def git_tree_depth_bounds(vars_dict):
        """Tree traversal depth must be 0-4096."""
        td = vars_dict.get('tree_depth')
        if td is None:
            return None
        return z3.Or(td < 0, td > 4096)

    @staticmethod
    def git_path_len_bounds(vars_dict):
        """Pathname length must be 1-4096."""
        pl = vars_dict.get('path_len')
        if pl is None:
            return None
        return z3.Or(pl < 1, pl > 4096)

    @staticmethod
    def git_object_type_bounds(vars_dict):
        """Object type must be 1-7 (OBJ_COMMIT..OBJ_REF_DELTA)."""
        ot = vars_dict.get('obj_type')
        if ot is None:
            return None
        return z3.Or(ot < 1, ot > 7)

    @staticmethod
    def git_object_type_allowed_set(vars_dict):
        """Object type must be one of Git's defined on-disk types: 1,2,3,4,6,7 (5 is reserved/invalid)."""
        ot = vars_dict.get('obj_type')
        if ot is None:
            return None
        return z3.Not(z3.Or(ot == 1, ot == 2, ot == 3, ot == 4, ot == 6, ot == 7))

    @staticmethod
    def git_symref_depth_bounds(vars_dict):
        """Symbolic ref depth must be 0-5 (SYMREF_MAXDEPTH)."""
        sd = vars_dict.get('symref_depth')
        if sd is None:
            return None
        return z3.Or(sd < 0, sd > 5)

    @staticmethod
    def git_hash_algo_bounds(vars_dict):
        """Hash algorithm ID must be 1 (SHA1) or 2 (SHA256)."""
        ha = vars_dict.get('hash_algo')
        if ha is None:
            return None
        return z3.Or(ha < 1, ha > 2)

    @staticmethod
    def git_hash_algo_rawsz_coupling(vars_dict):
        """Hash algorithm and digest width must match exactly (SHA1=20, SHA256=32)."""
        ha = vars_dict.get('hash_algo')
        hr = vars_dict.get('hash_rawsz')
        if ha is None or hr is None:
            return None
        return z3.Not(z3.Or(
            z3.And(ha == 1, hr == 20),
            z3.And(ha == 2, hr == 32),
        ))

    @staticmethod
    def git_pack_obj_header_len_bounds(vars_dict):
        """Pack object header length must be 1-10."""
        hl = vars_dict.get('header_len')
        if hl is None:
            return None
        return z3.Or(hl < 1, hl > 10)

    @staticmethod
    def git_hash_rawsz_bounds(vars_dict):
        """Hash raw size must be 20 (SHA1) to 32 (SHA256)."""
        hr = vars_dict.get('hash_rawsz')
        if hr is None:
            return None
        return z3.Or(hr < 20, hr > 32)

    @staticmethod
    def git_hash_bits_bounds(vars_dict):
        """Hash digest bit-length must remain within 160-256 bits."""
        hr = vars_dict.get('hash_rawsz')
        if hr is None:
            return None
        return z3.Or((hr * 8) < 160, (hr * 8) > 256)
