use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write as StdWrite};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- CORE DATA ARCHITECTURE ---

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

// --- LEXICAL ANALYSIS ---

fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let token_rules = vec![
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        ("KEYWORD", r"\b(set|scan|payload|if|while|for|in|end|log|swarm|ports|to)\b"),
        ("ID", r"[a-zA-Z_][a-zA-Z0-9_]*"),
        ("COMP", r"==|!=|<=|>=|<|>"),
        ("ASSIGN", r"="),
        ("OP", r"[+\-*/]"),
        ("STRING", r#""[^"]*""#),
        ("DELIM", r";"),
        ("PUNCT", r"[{}:,]"),
        ("SKIP", r"[ \t\n\r]+"),
    ];

    let combined_regex = token_rules.iter().map(|(n, p)| format!("(?P<{}>{})", n, p)).collect::<Vec<_>>().join("|");
    let re = Regex::new(&combined_regex).unwrap();

    let mut last_end = 0;
    for caps in re.captures_iter(code) {
        let m = caps.get(0).unwrap();
        if m.start() > last_end { panic!("[INTERPRETER_FATAL] Unexpected token at offset {}.", last_end); }
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

// --- POLYMORPHIC PRE-PROCESSOR ---

fn get_entropy_seed() -> usize {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as usize
}

fn mutate_token_stream(tokens: Vec<Token>) -> Vec<Token> {
    let mut mutated = Vec::new();
    let mut count = 0;

    for token in tokens {
        mutated.push(token.clone());
        if let Token::Delimiter = token {
            let seed = get_entropy_seed();
            if seed % 10 < 3 {
                let id = format!("_internal_{}", seed % 1000);
                mutated.push(Token::Keyword("set".to_string()));
                mutated.push(Token::Identifier(id));
                mutated.push(Token::Assign);
                mutated.push(Token::Number((seed % 100) as f64));
                mutated.push(Token::Operator("+".to_string()));
                mutated.push(Token::Number(1.0));
                mutated.push(Token::Delimiter);
                count += 1;
            }
        }
    }
    if count > 0 { println!("[SYSTEM_STATUS] Applied {} polymorphic mutations to execution context.", count); }
    mutated
}

// --- COMPILER ENGINE ---

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    memory: HashMap<String, Value>,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self { Parser { tokens, pos: 0, memory: HashMap::new() } }
    fn peek(&self) -> Option<Token> { self.tokens.get(self.pos).cloned() }
    fn next(&mut self) { self.pos += 1; }

    fn expect_keyword(&mut self, kw: &str) {
        if let Some(Token::Keyword(k)) = self.peek() {
            if k == kw { self.next(); return; }
        }
        panic!("[RUNTIME_ERROR] Expected keyword '{}' at token {}.", kw, self.pos);
    }

    fn parse(&mut self) {
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(k)) = self.peek() {
                match k.as_str() {
                    "set" => self.parse_assignment(),
                    "log" => self.parse_log(),
                    "scan" => self.parse_scan(),
                    "swarm" => self.parse_swarm(),
                    "while" => self.parse_while(),
                    "for" => self.parse_for(),
                    "payload" => self.parse_payload(),
                    _ => self.next(),
                }
            } else { self.next(); }
        }
    }

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!("ID expected"); };
        self.next(); // Consume '='
        let val = self.parse_expression();
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        self.memory.insert(name, val);
    }

    fn parse_expression(&mut self) -> Value {
        let mut res = self.parse_term();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "+" || op == "-" {
                self.next();
                let right = self.parse_term();
                if let (Value::Num(l), Value::Num(r)) = (&res, &right) {
                    res = if op == "+" { Value::Num(l + r) } else { Value::Num(l - r) };
                }
            } else { break; }
        }
        res
    }

    fn parse_term(&mut self) -> Value {
        let mut res = self.parse_factor();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "*" || op == "/" {
                self.next();
                let right = self.parse_factor();
                if let (Value::Num(l), Value::Num(r)) = (&res, &right) {
                    res = if op == "*" { Value::Num(l * r) } else { Value::Num(l / r) };
                }
            } else { break; }
        }
        res
    }

    fn parse_factor(&mut self) -> Value {
        let tok = self.peek().expect("Unexpected EOF");
        self.next();
        match tok {
            Token::Number(n) => Value::Num(n),
            Token::StringLiteral(s) | Token::IpAddress(s) => Value::Str(s),
            Token::Identifier(id) => self.memory.get(&id).cloned().unwrap_or(Value::Num(0.0)),
            _ => panic!("Type error"),
        }
    }

    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let val = match self.peek() {
            Some(Token::StringLiteral(s)) => { self.next(); s },
            Some(Token::Identifier(id)) => {
                self.next();
                match self.memory.get(&id) {
                    Some(Value::Num(n)) => n.to_string(),
                    Some(Value::Str(s)) => s.clone(),
                    _ => "null".to_string(),
                }
            },
            _ => panic!("Log target invalid"),
        };
        println!("[STDOUT] {}", val);
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    fn parse_scan(&mut self) {
        self.expect_keyword("scan");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }

        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let port = match self.memory.get("port") { Some(Value::Num(p)) => *p as u16, _ => 80 };
        
        let addr = format!("{}:{}", ip, port);
        let status = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok();
        
        self.parse_if(status);
    }

    fn parse_swarm(&mut self) {
        self.expect_keyword("swarm");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("ports");
        let start = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        self.expect_keyword("to");
        let end = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }

        let mut sub_tokens = Vec::new();
        let mut depth = 1;
        while let Some(tok) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = tok {
                if ["if", "for", "while", "swarm", "scan"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            sub_tokens.push(tok);
        }

        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let mem_snap = self.memory.clone();
        
        println!("[TASK_INIT] Spawning asynchronous pool for range {}-{}...", start, end);
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut tasks = vec![];
            for port in start..=end {
                let ip_clone = ip.clone();
                let tokens_clone = sub_tokens.clone();
                let mut local_mem = mem_snap.clone();
                
                tasks.push(tokio::task::spawn_blocking(move || {
                    let addr = format!("{}:{}", ip_clone, port);
                    let status = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(400)).is_ok();
                    local_mem.insert("port".to_string(), Value::Num(port as f64));
                    let mut engine = Parser::new(tokens_clone);
                    engine.memory = local_mem;
                    
                    while engine.pos < engine.tokens.len() {
                        if let Some(Token::Keyword(k)) = engine.peek() {
                            if k == "if" { engine.parse_if(status); }
                            else { engine.parse(); }
                        } else { engine.next(); }
                    }
                }));
            }
            for t in tasks { let _ = t.await; }
        });
    }

    fn parse_if(&mut self, condition: bool) {
        self.expect_keyword("if");
        self.next(); // Consume "open" or identifier
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        if condition {
            while let Some(tok) = self.peek() {
                if let Token::Keyword(ref k) = tok { if k == "end" { break; } }
                self.parse();
            }
            self.expect_keyword("end");
        } else {
            let mut d = 1;
            while d > 0 {
                self.next();
                if let Some(Token::Keyword(ref k)) = self.peek() {
                    if ["if", "swarm", "scan", "while", "for"].contains(&k.as_str()) { d += 1; }
                    if k == "end" { d -= 1; }
                }
            }
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
        }
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let target_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let port_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { 
            if let Some(Token::Number(n)) = self.peek() { self.next(); n.to_string() } else { panic!(); }
        };
        let data = if let Some(Token::StringLiteral(s)) = self.peek() { self.next(); s } else { panic!(); };

        let ip = match self.memory.get(&target_id) { Some(Value::Str(s)) => s, _ => &target_id };
        let port = match self.memory.get(&port_id) { Some(Value::Num(n)) => *n as u16, _ => port_id.parse().unwrap_or(80) };

        let addr = format!("{}:{}", ip, port);
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(1)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(data.replace("\\n", "\n").replace("\\r", "\r").as_bytes());
            let mut buf = [0; 4096];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 { println!("[NET_INGRESS] Result from {}:\n{}", addr, String::from_utf8_lossy(&buf[..n]).trim()); }
            }
        }
    }

    fn parse_while(&mut self) { 
        self.expect_keyword("while");
        // Simplified for this version to keep logic clean
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for");
        // Simplified for this version
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { println!("Usage: breach <file.breach>"); return; }

    let raw_code = fs::read_to_string(&args[1]).expect("IO_ERROR: Failed to read source.");
    println!("[PROCESS_START] Initializing Breach v2.1 (Rust Runtime)...");

    let tokens = lexer(&raw_code);
    let mutated_tokens = mutate_token_stream(tokens);
    
    let mut engine = Parser::new(mutated_tokens);
    engine.parse();
    
    println!("[PROCESS_END] Execution sequence finalized.");
}