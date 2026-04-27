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
            elif token[0] == 'KEYWORD' and token[1] == 'while':
                self.parse_while()
            else:
                self.pos += 1 

    # --- MATH & LOGIC ENGINE PIPELINE ---
    # (Kept exactly the same as your flawless run)

    def parse_assignment(self):
        self.match('KEYWORD')               
        var_name = self.match('ID')[1]      
        self.match('ASSIGN')                
        
        final_value = self.parse_condition()
        self.memory[var_name] = final_value
            
        self.match('DELIM')                 
        print(f"[Memory] {var_name} = {self.memory[var_name]}")

    def parse_condition(self):
        left_side = self.parse_expression()

        token = self.peek()
        if token and token[0] == 'COMP':
            op = self.match('COMP')[1]
            right_side = self.parse_expression()

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

        return left_side

    def parse_expression(self):
        result = self.parse_term()
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['+', '-']:
            op = self.match('OP')[1]
            right_side = self.parse_term()
            if op == '+':
                result = result + right_side
            elif op == '-':
                result = result - right_side
        return result

    def parse_term(self):
        result = self.parse_factor()
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['*', '/']:
            op = self.match('OP')[1]
            right_side = self.parse_factor()
            if op == '*':
                result = result * right_side
            elif op == '/':
                result = result / right_side
        return result

    def parse_factor(self):
        token = self.peek()
        if token[0] == 'NUMBER':
            self.match('NUMBER')
            return float(token[1]) if '.' in token[1] else int(token[1])
        elif token[0] == 'ID':
            self.match('ID')
            var_name = token[1]
            if var_name in self.memory:
                return self.memory[var_name]
            raise RuntimeError(f"Fatal: Variable '{var_name}' does not exist in memory.")
        elif token[0] in ['TYPE_IP', 'STRING']:
            self.match(token[0])
            return token[1]
        raise SyntaxError(f"Syntax Error: Expected a valid data type, found '{token}'")


    # --- SYSTEM COMMANDS ---

    def parse_log(self):
        self.match('KEYWORD')   
        token = self.peek()
        if token[0] == 'STRING':
            message = self.match('STRING')[1].strip('"')
            print(f"> {message}")
        elif token[0] == 'ID':
            var_name = self.match('ID')[1]
            print(f"> {self.memory.get(var_name, 'UNDEFINED')}")
        self.match('DELIM')                 

    def parse_scan(self):
        # We upgraded this so it can scan dynamically assigned ports!
        self.match('KEYWORD')               
        target_var = self.match('ID')[1]    
        self.match('PUNCT')                 
        
        ip_to_scan = self.memory.get(target_var)
        target_port = int(self.memory.get('port', 80)) # Default to 80 if 'port' isn't set
        
        print(f"[*] Sweeping {ip_to_scan} on Port {target_port}...")
        
        is_open = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2) # Faster timeout for sweeps
            if s.connect_ex((ip_to_scan, target_port)) == 0:
                is_open = True
            s.close()
        except Exception:
            pass

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

    # --- THE TIME MACHINE ---

    def parse_while(self):
        # Handle syntax: while [condition]: [block] end
        self.match('KEYWORD')   
        
        # Mark timeline coordinates before evaluating reality
        condition_start_pos = self.pos 
        
        while True:
            # Always reset timeline to start before evaluating condition
            self.pos = condition_start_pos
            condition_is_true = self.parse_condition()
            self.match('PUNCT')     
            
            if condition_is_true:
                # Execute payload inside the loop
                while self.peek() and self.peek()[1] != 'end':
                    token = self.peek()
                    if token[0] == 'KEYWORD' and token[1] == 'set':
                        self.parse_assignment()
                    elif token[0] == 'KEYWORD' and token[1] == 'log':
                        self.parse_log()
                    elif token[0] == 'KEYWORD' and token[1] == 'scan':
                        self.parse_scan()
                    else:
                        self.pos += 1
                
                # We hit 'end'. Do NOT consume it, let Python restart the while loop to rewind time.
            else:
                # Reality is False. Fast-forward through tokens until block ends.
                while self.peek() and self.peek()[1] != 'end':
                    self.pos += 1
                    
                # Consume 'end' to break the loop and continue execution
                self.match('KEYWORD') 
                break


if __name__ == "__main__":
    # THE ULTIMATE TEST: A Full Subnet/Port Sweep
    script = """
    set target_ip = 1.1.1.1;
    set port = 80;
    set max_port = 83;
    
    log "Commencing Port Sweep...";
    
    while port < max_port:
        log "Scanning:";
        log port;
        
        scan target_ip:
            if open:
                log "CRITICAL: Port is vulnerable!";
            end
        end
        
        set port = port + 1;
    end
    
    log "Sweep terminated.";
    """

    print("\n[!] INITIATING BREACH ENGINE")
    parser = Parser(lexer(script))
    parser.parse()
    print("[!] ENGINE SHUTDOWN\n")