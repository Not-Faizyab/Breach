import socket
from lexer import lexer 

class Parser:
    def __init__(self, tokens):
        # Load token stream
        self.tokens = tokens
        self.pos = 0          
        # Initialize system RAM
        self.memory = {} 

    def peek(self):
        # Inspect current token without consuming it
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def match(self, expected_type):
        # Enforce strict syntax. Match expected type or kill the process.
        token = self.peek()
        if token and token[0] == expected_type:
            self.pos += 1 
            return token
        raise SyntaxError(f"Code Red: Expected '{expected_type}', found '{token}'")

    def parse(self):
        # Main execution loop
        while self.pos < len(self.tokens):
            token = self.peek()
            
            if token[0] == 'KEYWORD' and token[1] == 'set':
                self.parse_assignment()
            elif token[0] == 'KEYWORD' and token[1] == 'log':
                self.parse_log()
            elif token[0] == 'KEYWORD' and token[1] == 'scan':
                self.parse_scan()
            else:
                self.pos += 1 

    # --- MATH & LOGIC ENGINE PIPELINE ---

    def parse_assignment(self):
        # Handle syntax: set [var] = [expression];
        self.match('KEYWORD')               
        var_name = self.match('ID')[1]      
        self.match('ASSIGN')                
        
        # Route through the logic engine first. If no logic exists, it falls through to math.
        final_value = self.parse_condition()
        self.memory[var_name] = final_value
            
        self.match('DELIM')                 
        print(f"[Memory] {var_name} = {self.memory[var_name]}")

    def parse_condition(self):
        # TIER 0: Boolean Logic (<, >, ==, !=)
        # Evaluate standard math expressions first to establish base values
        left_side = self.parse_expression()

        token = self.peek()
        if token and token[0] == 'COMP':
            op = self.match('COMP')[1]
            right_side = self.parse_expression()

            # Execute Python native comparison
            if op == '<':
                return left_side < right_side
            elif op == '>':
                return left_side > right_side
            elif op == '==':
                return left_side == right_side
            elif op == '!=':
                return left_side != right_side
            elif op == '<=':
                return left_side <= right_side
            elif op == '>=':
                return left_side >= right_side

        # If no comparison operator exists, just return the math result
        return left_side

    def parse_expression(self):
        # TIER 1: Addition and Subtraction
        # Process terms (multiplication/division) first to enforce PEMDAS
        result = self.parse_term()
        
        # Chain addition/subtraction operations
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['+', '-']:
            op = self.match('OP')[1]
            right_side = self.parse_term()
            
            if op == '+':
                result = result + right_side
            elif op == '-':
                result = result - right_side
                
        return result

    def parse_term(self):
        # TIER 2: Multiplication and Division
        # Extract raw factors first
        result = self.parse_factor()
        
        # Execute multiplication/division immediately
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['*', '/']:
            op = self.match('OP')[1]
            right_side = self.parse_factor()
            
            if op == '*':
                result = result * right_side
            elif op == '/':
                result = result / right_side
                
        return result

    def parse_factor(self):
        # TIER 3: Raw Materials (Numbers, Strings, IPs, Variables, Booleans)
        token = self.peek()
        
        if token[0] == 'NUMBER':
            self.match('NUMBER')
            # Convert string token to Python float/int for computation
            return float(token[1]) if '.' in token[1] else int(token[1])
            
        elif token[0] == 'ID':
            self.match('ID')
            var_name = token[1]
            # Pull variable value from RAM
            if var_name in self.memory:
                return self.memory[var_name]
            raise RuntimeError(f"Fatal: Variable '{var_name}' does not exist in memory.")
                
        elif token[0] in ['TYPE_IP', 'STRING']:
            # Bypass math evaluation for raw strings and IP addresses
            self.match(token[0])
            return token[1]
            
        raise SyntaxError(f"Syntax Error: Expected a valid data type, found '{token}'")

    # --- SYSTEM COMMANDS ---

    def parse_log(self):
        self.match('KEYWORD')   
        
        # Support printing both raw strings and active memory variables
        token = self.peek()
        if token[0] == 'STRING':
            message = self.match('STRING')[1].strip('"')
            print(f"> {message}")
        elif token[0] == 'ID':
            var_name = self.match('ID')[1]
            print(f"> {self.memory.get(var_name, 'UNDEFINED')}")
            
        self.match('DELIM')                 

    def parse_scan(self):
        # ... (Skipping scan/if logic printout to save space, keep your existing one!)
        pass


if __name__ == "__main__":
    # Stress test for Boolean Logic
    script = """
    set current_port = 80;
    set max_port = 100;
    
    set is_valid_target = current_port < max_port;
    set is_complete = current_port == 100;
    
    log "Is target valid for scanning?";
    log is_valid_target;
    
    log "Is sweep complete?";
    log is_complete;
    """

    parser = Parser(lexer(script))
    parser.parse()