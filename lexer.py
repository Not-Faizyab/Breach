import re

def lexer(code_string):
    # Define rules of the universe (Order matters!)
    token_specification = [
        ('TYPE_IP',  r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),              
        ('NUMBER',   r'\d+(\.\d*)?'),                              
        ('KEYWORD',  r'\b(?:set|scan|strike|payload|if|while|end|log)\b'), 
        ('ID',       r'[a-zA-Z_][a-zA-Z0-9_]*'),                   
        ('COMP',     r'==|!=|<=|>=|<|>'),                        
        ('ASSIGN',   r'='),                                        
        ('OP',       r'[+\-*/]'),                                  
        ('STRING',   r'".*?"'),                                    
        ('DELIM',    r';'),                                        
        ('PUNCT',    r'[{}:,]'),                                   
        ('NEWLINE',  r'\n'),                                       
        ('SKIP',     r'[ \t]+'),                                   
        ('MISMATCH', r'.'),                                        
    ]
    
    # 2. Mash all these rules into one giant Regex machine
    tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
    
    line_num = 1
    tokens = []
    
    # 3. Scan through the code and match the patterns
    for mo in re.finditer(tok_regex, code_string):
        kind = mo.lastgroup
        value = mo.group()
        
        if kind == 'NEWLINE':
            line_num += 1
            continue
        elif kind == 'SKIP':
            continue
        elif kind == 'MISMATCH':
            raise RuntimeError(f"Bro, what is this? Syntax error on line {line_num}: {value}")
            
        tokens.append((kind, value))
        
    return tokens


# Prevents the test code from running when imported into parser.py
if __name__ == '__main__':
    sample_code = """
    set target_ip = 192.168.1.1;
    set timeout = 50;

    scan target_ip:
        if open:
            log "Breach point found";
        end
    end
    """

    my_tokens = lexer(sample_code)

    for t in my_tokens:
        print(t)