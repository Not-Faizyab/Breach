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
        # Hex-style Syntax Error
        raise SyntaxError(f"[ERR_SYNTAX_0x01] Unexpected token '{token}'. Expected type: <{expected_type}>.")

    def parse(self):
        while self.pos < len(self.tokens):
            token = self.peek()
            if token[0] == 'KEYWORD' and token[1] == 'set': self.parse_assignment()
            elif token[0] == 'KEYWORD' and token[1] == 'log': self.parse_log()
            elif token[0] == 'KEYWORD' and token[1] == 'scan': self.parse_scan()
            elif token[0] == 'KEYWORD' and token[1] == 'while': self.parse_while()
            elif token[0] == 'KEYWORD' and token[1] == 'for': self.parse_for()
            elif token[0] == 'KEYWORD' and token[1] == 'payload': self.parse_payload()
            else: self.pos += 1 

    # --- LOGIC & MATH ENGINE ---
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
            if op == '<': return left_side < right_side
            elif op == '>': return left_side > right_side
            elif op == '==': return left_side == right_side
            elif op == '!=': return left_side != right_side
            elif op == '<=': return left_side <= right_side
            elif op == '>=': return left_side >= right_side
        return left_side

    def parse_expression(self):
        result = self.parse_term()
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['+', '-']:
            op = self.match('OP')[1]
            right_side = self.parse_term()
            if op == '+': result = result + right_side
            elif op == '-': result = result - right_side
        return result

    def parse_term(self):
        result = self.parse_factor()
        while self.peek() and self.peek()[0] == 'OP' and self.peek()[1] in ['*', '/']:
            op = self.match('OP')[1]
            right_side = self.parse_factor()
            if op == '*': result = result * right_side
            elif op == '/': result = result / right_side
        return result

    def parse_factor(self):
        token = self.peek()
        if token[0] == 'NUMBER':
            self.match('NUMBER')
            return float(token[1]) if '.' in token[1] else int(token[1])
        elif token[0] == 'ID':
            self.match('ID')
            var_name = token[1]
            if var_name in self.memory: return self.memory[var_name]
            # Hex-style Memory Error
            raise MemoryError(f"[ERR_MEM_NULL_0x02] Pointer reference failed. '{var_name}' is unallocated.")
        elif token[0] in ['TYPE_IP', 'STRING']:
            self.match(token[0])
            return token[1]
        raise SyntaxError(f"[ERR_TYPE_INVALID_0x04] Expected valid data type, caught: '{token}'")

    # --- SYSTEM COMMANDS ---
    def parse_log(self):
        self.match('KEYWORD')   
        token = self.peek()
        if token[0] == 'STRING':
            message = self.match('STRING')[1].strip('"')
            print(f"> {message.encode().decode('unicode_escape')}")
        elif token[0] == 'ID':
            var_name = self.match('ID')[1]
            print(f"> {self.memory.get(var_name, 'UNDEFINED')}")
        self.match('DELIM')                 

    def parse_scan(self):
        self.match('KEYWORD')               
        target_var = self.match('ID')[1]    
        self.match('PUNCT')                 
        
        ip_to_scan = self.memory.get(target_var)
        if not ip_to_scan:
            raise MemoryError(f"[ERR_MEM_NULL_0x02] Target '{target_var}' has no IP assigned.")
            
        target_port = int(self.memory.get('port', 80)) 
        
        is_open = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2) 
            if s.connect_ex((ip_to_scan, target_port)) == 0:
                is_open = True
            s.close()
        except Exception:
            pass

        while self.peek() and self.peek()[1] != 'end':
            token = self.peek()
            if token[0] == 'KEYWORD' and token[1] == 'if': self.parse_if(is_open) 
            else: self.pos += 1 
        self.match('KEYWORD') 

    def parse_if(self, condition):
        self.match('KEYWORD')   
        self.match('ID')        
        self.match('PUNCT')     
        while self.peek() and self.peek()[1] != 'end':
            if condition:
                token = self.peek()
                if token[0] == 'KEYWORD' and token[1] == 'log': self.parse_log()
                elif token[0] == 'KEYWORD' and token[1] == 'set': self.parse_assignment()
                elif token[0] == 'KEYWORD' and token[1] == 'payload': self.parse_payload()
                else: self.pos += 1
            else:
                self.pos += 1
        self.match('KEYWORD') 

    def parse_while(self):
        self.match('KEYWORD')   
        condition_start_pos = self.pos 
        while True:
            self.pos = condition_start_pos
            condition_is_true = self.parse_condition()
            self.match('PUNCT')     
            if condition_is_true:
                while self.peek() and self.peek()[1] != 'end':
                    token = self.peek()
                    if token[0] == 'KEYWORD' and token[1] == 'set': self.parse_assignment()
                    elif token[0] == 'KEYWORD' and token[1] == 'log': self.parse_log()
                    elif token[0] == 'KEYWORD' and token[1] == 'scan': self.parse_scan()
                    else: self.pos += 1
            else:
                while self.peek() and self.peek()[1] != 'end':
                    self.pos += 1
                self.match('KEYWORD') 
                break

    # --- THE FILE ITERATOR ---
    def parse_for(self):
        # Syntax: for [var] in "[filepath]":
        self.match('KEYWORD')   
        iterator_var = self.match('ID')[1]
        self.match('KEYWORD')   
        
        file_path = self.match('STRING')[1].strip('"')
        self.match('PUNCT')     
        
        # Reach into the OS and rip the lines from the file
        try:
            with open(file_path, 'r') as f:
                # Read lines and strip out blank spaces/newlines
                lines = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            raise MemoryError(f"[ERR_FILE_NULL_0x05] File target '{file_path}' not found on disk.")

        # Mark timeline coordinates
        block_start_pos = self.pos 
        
        # If file is completely empty, bypass the block like
        if not lines:
            while self.peek() and self.peek()[1] != 'end':
                self.pos += 1
            self.match('KEYWORD')
            return

        # Execute the time machine for every line in the file
        for current_line in lines:
            # Inject current line from file directly into RAM
            self.memory[iterator_var] = current_line
            # Rewind timeline
            self.pos = block_start_pos
            
            while self.peek() and self.peek()[1] != 'end':
                token = self.peek()
                if token[0] == 'KEYWORD' and token[1] == 'set': self.parse_assignment()
                elif token[0] == 'KEYWORD' and token[1] == 'log': self.parse_log()
                elif token[0] == 'KEYWORD' and token[1] == 'scan': self.parse_scan()
                elif token[0] == 'KEYWORD' and token[1] == 'while': self.parse_while()
                elif token[0] == 'KEYWORD' and token[1] == 'payload': self.parse_payload()
                else: self.pos += 1
                
        # Fast-forward timeline to break out of the block once the file is exhausted
        self.pos = block_start_pos
        while self.peek() and self.peek()[1] != 'end':
            self.pos += 1
        self.match('KEYWORD')

    # --- OFFENSIVE ARSENAL ---
    def parse_payload(self):
        self.match('KEYWORD')
        target_var = self.match('ID')[1]
        port_var = self.match('ID')[1]
        
        raw_string = self.match('STRING')[1].strip('"')
        payload_data = raw_string.encode().decode('unicode_escape')
        self.match('DELIM')
        
        ip = self.memory.get(target_var)
        port = int(self.memory.get(port_var))
        
        print(f"\n[!] FIRING PAYLOAD AT {ip}:{port}...")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            s.sendall(payload_data.encode()) 
            
            response = s.recv(4096) 
            print(f">>> SERVER RESPONSE CAUGHT:\n{response.decode(errors='ignore')}\n")
            s.close()
        except Exception:
            # Hex-style Network Drop Error
            print(f"[ERR_NET_TIMEOUT_0x03] Target actively refused connection or payload dropped.\n")


if __name__ == "__main__":
    # THE ULTIMATE TEST: File Iteration
    script = r"""
    log "Loading wordlist from disk...";
    
    for endpoint in "paths.txt":
        log "Attempting directory:";
        log endpoint;
    end
    
    log "Wordlist exhausted.";
    """

    print("\n[!] INITIATING BREACH ENGINE")
    parser = Parser(lexer(script))
    parser.parse()
    print("[!] ENGINE SHUTDOWN\n")