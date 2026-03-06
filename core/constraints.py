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
