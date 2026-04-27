import re

def lexer(code):
    # The absolute rules of the Breach universe
    token_specification = [
        ('TYPE_IP',  r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),              
        ('NUMBER',   r'\d+(\.\d*)?'),                              
        ('KEYWORD',  r'\b(?:set|scan|strike|payload|if|while|for|in|end|log)\b'), 
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
    
    tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
    tokens = []
    
    for mo in re.finditer(tok_regex, code):
        kind = mo.lastgroup
        value = mo.group()
        
        if kind == 'NEWLINE' or kind == 'SKIP':
            continue
        elif kind == 'MISMATCH':
            # Hex-style fatal error for illegal characters
            raise SyntaxError(f"[ERR_LEX_UNKNOWN_CHAR_0x00] Unrecognized byte sequence '{value}' at index {mo.start()}.")
        else:
            tokens.append((kind, value))
            
    return tokens

if __name__ == '__main__':
    # Engine shield: Keeps the lexer silent when imported by the parser
    pass