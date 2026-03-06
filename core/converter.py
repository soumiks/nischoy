import z3

class SMTConverter:
    """
    Generic AST-to-Z3 converter.
    Translates the intermediate representation from the parser into Z3 expressions.
    Reusable across any C project — the converter doesn't know about curl specifically.
    """
    def __init__(self):
        self.solver = z3.Solver()
        self.vars = {}

    def convert(self, ast):
        """Convert a parsed AST into Z3 solver constraints and variable bindings."""
        # Declare variables based on AST
        for var in ast.get('variables', []):
            if var['type'] == 'int':
                self.vars[var['name']] = z3.Int(var['name'])
            elif var['type'] == 'string':
                self.vars[var['name']] = z3.String(var['name'])

        # Translate operations into Z3 constraints (models the code's actual behavior)
        for op in ast.get('operations', []):
            if op['op'] == 'check_bound':
                var_sym = self.vars[op['variable']]
                max_val = op['max_val']
                self.solver.add(var_sym <= max_val)
                self.solver.add(var_sym >= 0)

            elif op['op'] == 'assign':
                target_name = op['target']
                source_sym = self.vars[op['source']]
                self.vars[target_name] = z3.Int(target_name)
                if op.get('cast') == 'unsigned short':
                    self.solver.add(self.vars[target_name] == source_sym % 65536)
                else:
                    self.solver.add(self.vars[target_name] == source_sym)

            elif op['op'] == 'check_brackets':
                var_sym = self.vars[op['variable']]
                start_char = z3.StringVal(op['start'])
                end_char = z3.StringVal(op['end'])
                starts = z3.SubString(var_sym, 0, 1) == start_char
                ends = z3.SubString(var_sym, z3.Length(var_sym) - 1, 1) == end_char
                self.solver.add(z3.Implies(starts, ends))

            elif op['op'] == 'reject_chars':
                var_sym = self.vars[op['variable']]
                for ch in op['chars']:
                    self.solver.add(z3.Not(z3.Contains(var_sym, z3.StringVal(ch))))

            elif op['op'] == 'junkscan':
                var_sym = self.vars[op['variable']]
                max_control = op.get('max_control', 31)
                for code in range(0, max_control + 1):
                    self.solver.add(z3.Not(z3.Contains(var_sym, z3.StringVal(chr(code)))))
                self.solver.add(z3.Not(z3.Contains(var_sym, z3.StringVal(chr(127)))))

        return self.solver, self.vars
