import re

def lexer(code_string):
    # 1. Define the rules of our universe (Order matters!)
    token_specification = [
        ('TYPE_IP',  r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),              # Matches IPs like 192.168.1.1
        ('NUMBER',   r'\d+(\.\d*)?'),                              # Standard numbers
        ('KEYWORD',  r'\b(?:set|scan|strike|payload|if|end|log)\b'), # Custom hacker arsenal
        ('ID',       r'[a-zA-Z_][a-zA-Z0-9_]*'),                   # Variable names
        ('ASSIGN',   r'='),                                        # The equals sign
        ('OP',       r'[+\-*/]'),                                  # Math operators
        ('STRING',   r'".*?"'),                                    # Text wrapped in quotes (e.g. "Breach point found")
        ('DELIM',    r';'),                                        # Semicolons to end lines
        ('PUNCT',    r'[{}:,]'),                                   # Braces, colons, and commas
        ('NEWLINE',  r'\n'),                                       # Line endings
        ('SKIP',     r'[ \t]+'),                                   # Skip spaces
        ('MISMATCH', r'.'),                                        # Syntax Error catcher
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