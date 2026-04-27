use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// --- THE DNA ---
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Keyword(String),
    Identifier(String),
    Number(f64),
    IpAddress(String),
    StringLiteral(String),
    Compare(String),
    Assign,
    Operator(String),
    Delimiter,
    Punctuation(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Num(f64),
    Str(String),
    Bool(bool),
}

// --- THE LEXER ---
fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    
    // Exact same Regex rules as your Python prototype
    let token_rules = vec![
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        ("KEYWORD", r"\b(set|scan|payload|if|while|for|in|end|log)\b"),
        ("ID", r"[a-zA-Z_][a-zA-Z0-9_]*"),
        ("COMP", r"==|!=|<=|>=|<|>"),
        ("ASSIGN", r"="),
        ("OP", r"[+\-*/]"),
        ("STRING", r#""[^"]*""#),
        ("DELIM", r";"),
        ("PUNCT", r"[{}:,]"),
        ("SKIP", r"[ \t\n\r]+"),
    ];

    let combined_regex = token_rules
        .iter()
        .map(|(name, pattern)| format!("(?P<{}>{})", name, pattern))
        .collect::<Vec<String>>()
        .join("|");

    let re = Regex::new(&combined_regex).unwrap();

    let mut last_end = 0;
    for caps in re.captures_iter(code) {
        let m = caps.get(0).unwrap();
        
        if m.start() > last_end {
            let illegal = &code[last_end..m.start()];
            panic!("[ERR_LEX_UNKNOWN_CHAR_0x00] Unrecognized byte sequence '{}' at index {}.", illegal, last_end);
        }
        last_end = m.end();

        let val = m.as_str().to_string();

        if caps.name("SKIP").is_some() { continue; }
        else if caps.name("KEYWORD").is_some() { tokens.push(Token::Keyword(val)); }
        else if caps.name("TYPE_IP").is_some() { tokens.push(Token::IpAddress(val)); }
        else if caps.name("NUMBER").is_some() { tokens.push(Token::Number(val.parse().unwrap())); }
        else if caps.name("ID").is_some() { tokens.push(Token::Identifier(val)); }
        else if caps.name("COMP").is_some() { tokens.push(Token::Compare(val)); }
        else if caps.name("ASSIGN").is_some() { tokens.push(Token::Assign); }
        else if caps.name("OP").is_some() { tokens.push(Token::Operator(val)); }
        else if caps.name("STRING").is_some() { tokens.push(Token::StringLiteral(val.trim_matches('"').to_string())); }
        else if caps.name("DELIM").is_some() { tokens.push(Token::Delimiter); }
        else if caps.name("PUNCT").is_some() { tokens.push(Token::Punctuation(val)); }
    }
    tokens
}

// --- THE ENGINE ---
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    memory: HashMap<String, Value>,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0, memory: HashMap::new() }
    }

    fn peek(&self) -> Option<Token> {
        if self.pos < self.tokens.len() { Some(self.tokens[self.pos].clone()) } else { None }
    }

    fn next(&mut self) { self.pos += 1; }

    fn expect_keyword(&mut self, kw: &str) {
        match self.peek() {
            Some(Token::Keyword(k)) if k == kw => self.next(),
            token => panic!("[ERR_SYNTAX_0x01] Expected keyword '{}', found {:?}", kw, token),
        }
    }

    fn parse(&mut self) {
        while self.pos < self.tokens.len() {
            match self.peek() {
                Some(Token::Keyword(k)) => match k.as_str() {
                    "set" => self.parse_assignment(),
                    "log" => self.parse_log(),
                    "scan" => self.parse_scan(),
                    "while" => self.parse_while(),
                    "for" => self.parse_for(),
                    "payload" => self.parse_payload(),
                    _ => self.next(),
                },
                _ => self.next(),
            }
        }
    }

    // --- LOGIC & MATH ---
    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let var_name = match self.peek() {
            Some(Token::Identifier(id)) => { self.next(); id }
            _ => panic!("[ERR_SYNTAX_0x01] Expected Identifier after 'set'."),
        };

        if let Some(Token::Assign) = self.peek() { self.next(); } 
        else { panic!("[ERR_SYNTAX_0x01] Expected '='."); }

        let val = self.parse_condition();
        
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        else { panic!("[ERR_SYNTAX_0x01] Expected ';'."); }

        println!("[Memory] {} = {:?}", var_name, val);
        self.memory.insert(var_name, val);
    }

    fn parse_condition(&mut self) -> Value {
        let left = self.parse_expression();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next();
            let right = self.parse_expression();
            if let (Value::Num(l), Value::Num(r)) = (&left, &right) {
                let result = match op.as_str() {
                    "<" => l < r, ">" => l > r, "==" => l == r, "!=" => l != r,
                    "<=" => l <= r, ">=" => l >= r,
                    _ => false,
                };
                return Value::Bool(result);
            }
        }
        left
    }

    fn parse_expression(&mut self) -> Value {
        let mut result = self.parse_term();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "+" || op == "-" {
                self.next();
                let right = self.parse_term();
                if let (Value::Num(l), Value::Num(r)) = (&result, &right) {
                    result = if op == "+" { Value::Num(l + r) } else { Value::Num(l - r) };
                }
            } else { break; }
        }
        result
    }

    fn parse_term(&mut self) -> Value {
        let mut result = self.parse_factor();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "*" || op == "/" {
                self.next();
                let right = self.parse_factor();
                if let (Value::Num(l), Value::Num(r)) = (&result, &right) {
                    result = if op == "*" { Value::Num(l * r) } else { Value::Num(l / r) };
                }
            } else { break; }
        }
        result
    }

    fn parse_factor(&mut self) -> Value {
        let token = self.peek().expect("[ERR_SYNTAX_0x01] Unexpected EOF.");
        self.next();
        match token {
            Token::Number(n) => Value::Num(n),
            Token::StringLiteral(s) => Value::Str(s),
            Token::IpAddress(ip) => Value::Str(ip),
            Token::Identifier(id) => self.memory.get(&id).cloned().expect(&format!("[ERR_MEM_NULL_0x02] Variable '{}' unallocated.", id)),
            _ => panic!("[ERR_TYPE_INVALID_0x04] Invalid data type caught."),
        }
    }

    // --- SYSTEM COMMANDS ---
    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let token = self.peek();
        self.next();
        match token {
            Some(Token::StringLiteral(s)) => println!("> {}", s.replace("\\r\\n", "\r\n").replace("\\n", "\n")),
            Some(Token::Identifier(id)) => {
                let val = self.memory.get(&id).expect("[ERR_MEM_NULL_0x02]");
                println!("> {:?}", val);
            }
            _ => panic!("[ERR_SYNTAX_0x01] Invalid log target."),
        }
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    // --- TIME MACHINES ---
    fn parse_while(&mut self) {
        self.expect_keyword("while");
        let start_pos = self.pos;

        loop {
            self.pos = start_pos;
            let condition = match self.parse_condition() {
                Value::Bool(b) => b,
                _ => panic!("[ERR_TYPE_INVALID_0x04] While loop condition must be boolean."),
            };

            if let Some(Token::Punctuation(p)) = self.peek() { 
                if p == ":" { self.next(); } 
            }

            if condition {
                while let Some(tok) = self.peek() {
                    if let Token::Keyword(k) = tok {
                        if k == "end" { break; }
                        match k.as_str() {
                            "set" => self.parse_assignment(),
                            "log" => self.parse_log(),
                            "scan" => self.parse_scan(),
                            "payload" => self.parse_payload(),
                            _ => self.next(),
                        }
                    } else { self.next(); }
                }
            } else {
                while let Some(tok) = self.peek() {
                    if let Token::Keyword(k) = tok { if k == "end" { break; } }
                    self.next();
                }
                self.expect_keyword("end");
                break;
            }
        }
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for");
        let iter_var = match self.peek() {
            Some(Token::Identifier(id)) => { self.next(); id },
            _ => panic!("Expected ID"),
        };
        self.expect_keyword("in");
        
        let filepath = match self.peek() {
            Some(Token::StringLiteral(s)) => { self.next(); s },
            _ => panic!("Expected File String"),
        };
        
        if let Some(Token::Punctuation(p)) = self.peek() { 
            if p == ":" { self.next(); } 
        }

        let file_content = fs::read_to_string(&filepath).expect(&format!("[ERR_FILE_NULL_0x05] File '{}' missing.", filepath));
        let lines: Vec<&str> = file_content.lines().filter(|l| !l.trim().is_empty()).collect();
        let block_start = self.pos;

        for line in lines {
            self.memory.insert(iter_var.clone(), Value::Str(line.to_string()));
            self.pos = block_start;

            while let Some(tok) = self.peek() {
                if let Token::Keyword(k) = tok {
                    if k == "end" { break; }
                    match k.as_str() {
                        "set" => self.parse_assignment(),
                        "log" => self.parse_log(),
                        "scan" => self.parse_scan(),
                        "payload" => self.parse_payload(),
                        _ => self.next(),
                    }
                } else { self.next(); }
            }
        }
        self.pos = block_start;
        while let Some(tok) = self.peek() {
            if let Token::Keyword(k) = tok { if k == "end" { break; } }
            self.next();
        }
        self.expect_keyword("end");
    }

    // --- OFFENSIVE ARSENAL ---
    fn parse_scan(&mut self) {
        self.expect_keyword("scan");
        let target = match self.peek() {
            Some(Token::Identifier(id)) => { self.next(); id }
            _ => panic!("Expected target ID"),
        };
        if let Some(Token::Punctuation(p)) = self.peek() { if p == ":" { self.next(); } }

        let ip = match self.memory.get(&target) {
            Some(Value::Str(s)) => s.clone(),
            _ => panic!("[ERR_MEM_NULL_0x02] No IP found."),
        };
        
        let port = match self.memory.get("port") {
            Some(Value::Num(p)) => *p as u16,
            _ => 80, // Default fallback
        };

        let address = format!("{}:{}", ip, port);
        let mut is_open = false;
        
        // Native OS-level TCP Socket connection
        if let Ok(addresses) = address.to_socket_addrs() {
            if let Some(addr) = addresses.filter(|a| a.is_ipv4()).next() {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
                    is_open = true;
                }
            }
        }

        while let Some(tok) = self.peek() {
            if let Token::Keyword(k) = tok {
                if k == "end" { break; }
                if k == "if" { self.parse_if(is_open); }
                else { self.next(); }
            } else { self.next(); }
        }
        self.expect_keyword("end");
    }

    fn parse_if(&mut self, condition: bool) {
        self.expect_keyword("if");
        if let Some(Token::Identifier(_)) = self.peek() { self.next(); } // Match "open"
        if let Some(Token::Punctuation(_)) = self.peek() { self.next(); }

        while let Some(tok) = self.peek() {
            if let Token::Keyword(k) = tok.clone() {
                if k == "end" { break; }
                if condition {
                    match k.as_str() {
                        "set" => self.parse_assignment(),
                        "log" => self.parse_log(),
                        "payload" => self.parse_payload(),
                        _ => self.next(),
                    }
                } else { self.next(); }
            } else { self.next(); }
        }
        self.expect_keyword("end");
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let target_var = match self.peek() { Some(Token::Identifier(id)) => { self.next(); id }, _ => panic!() };
        let port_var = match self.peek() { Some(Token::Identifier(id)) => { self.next(); id }, _ => panic!() };
        
        let raw_payload = match self.peek() { 
            Some(Token::StringLiteral(s)) => { self.next(); s }, 
            _ => panic!() 
        };
        
        if let Some(Token::Delimiter) = self.peek() { self.next(); }

        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s, _ => panic!() };
        let port = match self.memory.get(&port_var) { Some(Value::Num(n)) => *n as u16, _ => panic!() };
        let formatted_payload = raw_payload.replace("\\r\\n", "\r\n").replace("\\n", "\n");

        // ... (keep the top of parse_payload exactly the same)
        println!("\n[!] FIRING RAW BYTES AT {}:{}...", ip, port);
        let address = format!("{}:{}", ip, port);

        if let Ok(mut stream) = TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(2)) {
            // 1. Slap a strict 2-second timeout on reading so the engine never hangs
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            
            // 2. Fire the payload
            let _ = stream.write_all(formatted_payload.as_bytes());
            
            // 3. Create a raw 4KB memory buffer (Exactly like Python's recv(4096))
            let mut buffer = [0; 4096];
            
            // 4. Read whatever is immediately available into the buffer and run
            if let Ok(bytes_read) = stream.read(&mut buffer) {
                // Convert the raw bytes back into human-readable text
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                println!(">>> SERVER RESPONSE CAUGHT:\n{}\n", response);
            }
        } else {
            println!("[ERR_NET_TIMEOUT_0x03] Target actively refused connection.\n");
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("[!] FATAL: No payload provided.");
        println!("[?] Usage: cargo run <script.breach>");
        std::process::exit(1);
    }

    let target_file = &args[1];
    if !target_file.ends_with(".breach") {
        println!("[ERR_SYS_INVALID_EXT_0x06] File '{}' rejected. Require '.breach' extension.", target_file);
        std::process::exit(1);
    }

    let code = fs::read_to_string(target_file).unwrap_or_else(|_| {
        println!("[ERR_FILE_NULL_0x05] Target script not found on disk.");
        std::process::exit(1);
    });

    println!("\n[!] INITIATING BREACH V2 (RUST BARE-METAL)");
    println!("[*] Compiling payload: {}\n", target_file);

    let tokens = lexer(&code);
    let mut parser = Parser::new(tokens);
    parser.parse();
    
    println!("\n[!] ENGINE SHUTDOWN: CLEAN EXIT");
}