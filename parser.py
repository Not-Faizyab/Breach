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

    # --- MATH ENGINE PIPELINE ---

    def parse_assignment(self):
        # Handle syntax: set [var] = [math_expression];
        self.match('KEYWORD')               
        var_name = self.match('ID')[1]      
        self.match('ASSIGN')                
        
        # Evaluate full mathematical expression before assigning to memory
        final_value = self.parse_expression()
        self.memory[var_name] = final_value
            
        self.match('DELIM')                 
        print(f"[Memory] {var_name} = {self.memory[var_name]}")

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
        # TIER 3: Raw Materials (Numbers, Strings, IPs, Variables)
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
        self.match('KEYWORD')               
        target_var = self.match('ID')[1]    
        self.match('PUNCT')                 
        
        # Fetch target IP from RAM
        ip_to_scan = self.memory.get(target_var)
        if not ip_to_scan:
            raise RuntimeError(f"Fatal: No IP assigned to '{target_var}'")

        print(f"\n[*] Sweeping {ip_to_scan} (Port 80)...")
        
        # Execute native socket connection to test real-world port status
        is_open = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) 
            if s.connect_ex((ip_to_scan, 80)) == 0:
                is_open = True
            s.close()
        except Exception:
            pass

        # Parse internal block until 'end' keyword is detected
        while self.peek() and self.peek()[1] != 'end':
            token = self.peek()
            if token[0] == 'KEYWORD' and token[1] == 'if':
                self.parse_if(is_open) 
            else:
                self.pos += 1 

        self.match('KEYWORD') 

    def parse_if(self, condition):
        self.match('KEYWORD')   
        self.match('ID')        
        self.match('PUNCT')     
        
        # Execute block if condition resolves to True; otherwise, skip tokens
        while self.peek() and self.peek()[1] != 'end':
            if condition:
                token = self.peek()
                if token[0] == 'KEYWORD' and token[1] == 'log':
                    self.parse_log()
                elif token[0] == 'KEYWORD' and token[1] == 'set':
                    self.parse_assignment()
                else:
                    self.pos += 1
            else:
                self.pos += 1
                
        self.match('KEYWORD') 


if __name__ == "__main__":
    # Stress test for mathematical expression parsing
    script = """
    set base_port = 80;
    set offset = 5 * 2;
    set target_port = base_port + offset;
    
    log "Calculated target port:";
    log target_port;
    """

    parser = Parser(lexer(script))
    parser.parse()