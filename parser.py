import socket
from lexer import lexer 

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0          
        self.memory = {} 

    def peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def match(self, expected_type):
        token = self.peek()
        if token and token[0] == expected_type:
            self.pos += 1 
            return token
        raise SyntaxError(f"Syntax Error: Expected '{expected_type}', found '{token}'")

    def parse(self):
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

    def parse_assignment(self):
        self.match('KEYWORD')               
        var_name = self.match('ID')[1]      
        self.match('ASSIGN')                
        
        val = self.peek()
        if val[0] in ['TYPE_IP', 'NUMBER', 'STRING']:
            self.memory[var_name] = val[1] 
            self.match(val[0])               
            
        self.match('DELIM')                 
        print(f"[Memory] {var_name} = {self.memory[var_name]}")

    def parse_log(self):
        self.match('KEYWORD')               
        message = self.match('STRING')[1]   
        self.match('DELIM')                 
        print(f"> {message.strip('\"')}")

    def parse_scan(self):
        self.match('KEYWORD')               # Match 'scan'
        target_var = self.match('ID')[1]    # Match 'target_ip'
        self.match('PUNCT')                 # Match ':'
        
        # Pull the actual IP address from the language's memory
        ip_to_scan = self.memory.get(target_var)
        if not ip_to_scan:
            raise RuntimeError(f"Fatal Error: Variable '{target_var}' has no IP assigned!")

        print(f"\n[*] Initiating network sweep on {ip_to_scan} (Port 80)...")
        
        # Pinging the port using Python's socket
        is_open = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # Don't hang forever
            if s.connect_ex((ip_to_scan, 80)) == 0:
                is_open = True
            s.close()
        except Exception:
            pass

        # Parse the code inside the scan block until 'end' is hit
        while self.peek() and self.peek()[1] != 'end':
            token = self.peek()
            if token[0] == 'KEYWORD' and token[1] == 'if':
                self.parse_if(is_open) # Pass the real network result into the 'if' statement
            else:
                self.pos += 1 

        self.match('KEYWORD') # Match the 'end' that closes the scan block

    def parse_if(self, condition):
        self.match('KEYWORD')   # Match 'if'
        self.match('ID')        # Match 'open' (we are hardcoding 'open' as the condition for now)
        self.match('PUNCT')     # Match ':'
        
        # If the port was actually open, execute the code inside
        # If it was closed, just skip the tokens until the block ends
        while self.peek() and self.peek()[1] != 'end':
            if condition:
                token = self.peek()
                if token[0] == 'KEYWORD' and token[1] == 'log':
                    self.parse_log()
                else:
                    self.pos += 1
            else:
                self.pos += 1
                
        self.match('KEYWORD') # Match the 'end' that closes the if block


if __name__ == "__main__":
    script = """
    set target_ip = 1.1.1.1;
    set timeout = 50;
    
    scan target_ip:
        if open:
            log "Breach point found on Port 80!";
        end
    end
    """

    parser = Parser(lexer(script))
    parser.parse()