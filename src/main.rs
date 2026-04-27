use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write as StdWrite};
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// =====================================================================
// --- CORE DATA ARCHITECTURE ---
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
    List(Vec<Value>) 
}

// =====================================================================
// --- LEXICAL ANALYSIS ENGINE ---
// =====================================================================

fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    
    let token_rules = vec![
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        // ADDED: transmit
        ("KEYWORD", r"\b(set|scan|payload|if|while|for|in|end|log|swarm|ports|to|write|append|wait|list|push|pop|rand|op|call|resolve|input|transmit)\b"),
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
        .collect::<Vec<_>>()
        .join("|");
        
    let re = Regex::new(&combined_regex).unwrap();
    let mut last_end = 0;

    for caps in re.captures_iter(code) {
        let m = caps.get(0).unwrap();
        
        if m.start() > last_end { 
            panic!("[FATAL] Lexer failure at offset {}. Invalid syntax.", last_end); 
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

// =====================================================================
// --- POLYMORPHIC PRE-PROCESSOR (STEALTH) ---
// =====================================================================

fn mutate_token_stream(tokens: Vec<Token>) -> Vec<Token> {
    let mut mutated_stream = Vec::new();
    
    for token in tokens {
        mutated_stream.push(token.clone());
        
        if let Token::Delimiter = token {
            let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as usize;
            
            if seed % 10 < 2 {
                let junk_id = format!("_v_{}", seed % 100);
                mutated_stream.push(Token::Keyword("set".to_string()));
                mutated_stream.push(Token::Identifier(junk_id));
                mutated_stream.push(Token::Assign);
                mutated_stream.push(Token::Number(1.0));
                mutated_stream.push(Token::Delimiter);
            }
        }
    }
    mutated_stream
}

fn format_address(ip: &str, port: u16) -> String {
    if ip.contains(':') { 
        format!("[{}]:{}", ip, port) 
    } else { 
        format!("{}:{}", ip, port)   
    }
}

// =====================================================================
// --- MASTER PARSER & EXECUTION ENGINE ---
// =====================================================================

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    memory: HashMap<String, Value>,
    functions: HashMap<String, Vec<Token>>, 
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self { 
        Parser { 
            tokens, 
            pos: 0, 
            memory: HashMap::new(), 
            functions: HashMap::new() 
        } 
    }
    
    fn peek(&self) -> Option<Token> { self.tokens.get(self.pos).cloned() }
    fn next(&mut self) { self.pos += 1; }
    
    fn expect_keyword(&mut self, kw: &str) {
        if let Some(Token::Keyword(k)) = self.peek() { 
            if k == kw { 
                self.next(); 
                return; 
            } 
        }
        panic!("[RUNTIME_ERROR] Expected keyword '{}' at position {}.", kw, self.pos);
    }

    fn parse(&mut self) { 
        while self.pos < self.tokens.len() { 
            self.parse_statement(); 
        } 
    }

    fn parse_statement(&mut self) {
        if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "set" => self.parse_assignment(),
                "log" => self.parse_log(),
                "scan" => self.parse_scan(),
                "swarm" => self.parse_swarm(),
                "payload" => self.parse_payload(),
                "transmit" => self.parse_transmit(), // ROUTED
                "while" => self.parse_while(),
                "for" => self.parse_for(),
                "if" => self.parse_if(true),
                "wait" => self.parse_wait(),
                "write" => self.parse_file_operation(false),
                "append" => self.parse_file_operation(true),
                "push" => self.parse_list_push(),
                "pop" => self.parse_list_pop(),
                "op" => self.parse_op_definition(),
                "call" => self.parse_op_call(),
                "end" => self.next(),
                _ => self.next(),
            }
        } else { 
            self.next(); 
        }
    }

    // --- LOGIC & ASSIGNMENTS ---

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        
        let var_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Assign) = self.peek() { self.next(); }
        
        let value = if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "list" => { self.next(); Value::List(Vec::new()) },
                "rand" => self.parse_rand(),
                "resolve" => self.parse_resolve(),
                "input" => self.parse_input(),
                _ => self.parse_condition(),
            }
        } else { 
            self.parse_condition() 
        };
        
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        self.memory.insert(var_name, value);
    }

    // --- SYSTEM UTILITIES ---

    fn parse_resolve(&mut self) -> Value {
        self.expect_keyword("resolve");
        let host = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); };
        
        if let Ok(mut addrs) = format!("{}:80", host).to_socket_addrs() {
            if let Some(resolved_addr) = addrs.next() { 
                return Value::Str(resolved_addr.ip().to_string()); 
            }
        }
        Value::Str("0.0.0.0".to_string())
    }

    fn parse_input(&mut self) -> Value {
        self.expect_keyword("input");
        let prompt_text = if let Value::Str(s) = self.parse_factor() { s } else { "".to_string() };
        
        print!("{}", prompt_text); 
        let _ = io::stdout().flush();
        
        let mut user_input = String::new(); 
        let _ = io::stdin().read_line(&mut user_input);
        
        Value::Str(user_input.trim().to_string())
    }

    fn parse_rand(&mut self) -> Value {
        self.expect_keyword("rand");
        let start_range = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 0 };
        
        self.expect_keyword("to");
        let end_range = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 100 };
        
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;
        let random_result = start_range + (seed % (end_range - start_range + 1).max(1));
        
        Value::Num(random_result as f64)
    }

    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let log_value = match self.parse_condition() {
            Value::Num(n) => n.to_string(), 
            Value::Str(s) => s,
            Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l),
        };
        println!("{}", log_value);
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    // --- MATH & EXPRESSION EVALUATOR ---

    fn parse_condition(&mut self) -> Value {
        let left_side = self.parse_expression();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next();
            let right_side = self.parse_expression();
            if let (Value::Num(l), Value::Num(r)) = (&left_side, &right_side) {
                let result = match op.as_str() {
                    "==" => l == r, "!=" => l != r, ">" => l > r, "<" => l < r, ">=" => l >= r, "<=" => l <= r, _ => false
                };
                return Value::Bool(result);
            }
        }
        left_side
    }

    fn parse_expression(&mut self) -> Value {
        let mut result = self.parse_term();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "+" || op == "-" {
                self.next();
                let right_side = self.parse_term();
                result = match (result, right_side) {
                    (Value::Num(l), Value::Num(r)) => if op == "+" { Value::Num(l + r) } else { Value::Num(l - r) },
                    (Value::Str(l), Value::Str(r)) => if op == "+" { Value::Str(l + &r) } else { panic!() },
                    (Value::Str(l), Value::Num(r)) => if op == "+" { Value::Str(l + &r.to_string()) } else { panic!() },
                    (Value::Num(l), Value::Str(r)) => if op == "+" { Value::Str(l.to_string() + &r) } else { panic!() },
                    _ => panic!("Type error in expression"),
                };
            } else { break; }
        }
        result
    }

    fn parse_term(&mut self) -> Value {
        let mut result = self.parse_factor();
        while let Some(Token::Operator(op)) = self.peek() {
            if op == "*" || op == "/" {
                self.next();
                let right_side = self.parse_factor();
                if let (Value::Num(l), Value::Num(r)) = (&result, &right_side) {
                    result = if op == "*" { Value::Num(l * r) } else { Value::Num(l / r) };
                }
            } else { break; }
        }
        result
    }

    fn parse_factor(&mut self) -> Value {
        let token = self.peek().expect("Unexpected End of File"); 
        self.next();
        match token {
            Token::Number(n) => Value::Num(n),
            Token::StringLiteral(s) | Token::IpAddress(s) => Value::Str(s),
            Token::Identifier(id) => self.memory.get(&id).cloned().unwrap_or(Value::Num(0.0)),
            _ => panic!("Invalid factor type"),
        }
    }

    // --- MODULAR OPERATIONS (OP) ---

    fn parse_op_definition(&mut self) {
        self.expect_keyword("op");
        let op_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        let mut op_body = Vec::new(); 
        let mut block_depth = 1;
        
        while let Some(token) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = token {
                if ["if", "for", "while", "swarm", "scan", "op"].contains(&k.as_str()) { block_depth += 1; }
                if k == "end" { block_depth -= 1; if block_depth == 0 { break; } }
            }
            op_body.push(token);
        }
        self.functions.insert(op_name, op_body);
    }

    fn parse_op_call(&mut self) {
        self.expect_keyword("call");
        let op_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        
        if let Some(function_body) = self.functions.get(&op_name).cloned() {
            let mut sub_parser = Parser::new(function_body); 
            sub_parser.memory = self.memory.clone();
            sub_parser.functions = self.functions.clone(); 
            sub_parser.parse(); 
            self.memory = sub_parser.memory; 
        }
    }

    // --- OFFENSIVE NETWORKING ---

    fn parse_scan(&mut self) {
        self.expect_keyword("scan");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let port = match self.memory.get("port") { Some(Value::Num(p)) => *p as u16, _ => 80 };
        let address = format_address(&ip, port);
        
        let is_open = if let Ok(mut resolved_addrs) = address.to_socket_addrs() {
            if let Some(final_addr) = resolved_addrs.next() {
                TcpStream::connect_timeout(&final_addr, Duration::from_millis(500)).is_ok()
            } else { false }
        } else { false };
        
        self.parse_if(is_open);
    }

    fn parse_swarm(&mut self) {
        self.expect_keyword("swarm");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("ports");
        let start_port = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        self.expect_keyword("to");
        let end_port = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        
        let mut swarm_body = Vec::new(); 
        let mut block_depth = 1;
        while let Some(token) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = token {
                if ["if", "for", "while", "swarm", "scan", "op"].contains(&k.as_str()) { block_depth += 1; }
                if k == "end" { block_depth -= 1; if block_depth == 0 { break; } }
            }
            swarm_body.push(token);
        }
        
        let ip_target = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let memory_snapshot = self.memory.clone();
        let functions_snapshot = self.functions.clone();
        
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut thread_handles = vec![];
            for port in start_port..=end_port {
                let current_ip = ip_target.clone();
                let inner_code = swarm_body.clone();
                let mut local_memory = memory_snapshot.clone();
                let local_functions = functions_snapshot.clone();
                
                thread_handles.push(tokio::task::spawn_blocking(move || {
                    let formatted_address = format_address(&current_ip, port);
                    let is_port_open = if let Ok(mut resolved) = formatted_address.to_socket_addrs() {
                        if let Some(addr) = resolved.next() {
                            TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
                        } else { false }
                    } else { false };
                    
                    local_memory.insert("port".to_string(), Value::Num(port as f64));
                    let mut isolated_parser = Parser::new(inner_code); 
                    isolated_parser.memory = local_memory; 
                    isolated_parser.functions = local_functions;
                    isolated_parser.execute_swarm_block(is_port_open);
                }));
            }
            for handle in thread_handles { let _ = handle.await; }
        });
    }

    fn execute_swarm_block(&mut self, is_open: bool) {
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if k == "if" { self.parse_if(is_open); } else { self.parse_statement(); }
            } else { self.next(); }
        }
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let port_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else if let Some(Token::Number(n)) = self.peek() { self.next(); n.to_string() } else { panic!(); };
        let raw_payload = if let Some(Token::StringLiteral(s)) = self.peek() { self.next(); s } else { panic!(); };
        
        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => target_var };
        let port = match self.memory.get(&port_var) { Some(Value::Num(n)) => *n as u16, _ => port_var.parse().unwrap_or(80) };
        let address = format_address(&ip, port);
        
        if let Ok(mut resolved_addrs) = address.to_socket_addrs() {
            if let Some(final_addr) = resolved_addrs.next() {
                if let Ok(mut stream) = TcpStream::connect_timeout(&final_addr, Duration::from_secs(1)) {
                    let formatted_data = raw_payload.replace("\\n", "\n").replace("\\r", "\r");
                    let _ = stream.write_all(formatted_data.as_bytes());
                    
                    let mut buffer = [0; 4096];
                    if let Ok(bytes_read) = stream.read(&mut buffer) { 
                        if bytes_read > 0 { println!("{}", String::from_utf8_lossy(&buffer[..bytes_read]).trim()); } 
                    }
                }
            }
        }
    }

    // --- NEW: CLOUD EXFILTRATION (TRANSMIT) ---

    fn parse_transmit(&mut self) {
        self.expect_keyword("transmit");
        
        let target_var = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let port_var = if let Some(Token::Identifier(id)) = self.peek() { 
            self.next(); id 
        } else if let Some(Token::Number(n)) = self.peek() { 
            self.next(); n.to_string() 
        } else { panic!(); };
        
        let data_to_send = match self.parse_factor() {
            Value::Num(n) => n.to_string(),
            Value::Str(s) => s,
            Value::Bool(b) => b.to_string(),
            Value::List(l) => format!("{:?}", l),
        };
        
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        
        let ip = match self.memory.get(&target_var) { Some(Value::Str(s)) => s.clone(), _ => target_var.clone() };
        let port = match self.memory.get(&port_var) { Some(Value::Num(n)) => *n as u16, _ => port_var.parse().unwrap_or(80) };
        let address = format_address(&ip, port);
        
        // Fire-and-forget HTTP POST exfiltration
        if let Ok(mut resolved_addrs) = address.to_socket_addrs() {
            if let Some(final_addr) = resolved_addrs.next() {
                // Short timeout. We send the data and vanish.
                if let Ok(mut stream) = TcpStream::connect_timeout(&final_addr, Duration::from_millis(300)) {
                    let post_request = format!(
                        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", 
                        ip, data_to_send.len(), data_to_send
                    );
                    let _ = stream.write_all(post_request.as_bytes());
                }
            }
        }
    }

    // --- CONTROL FLOW & FILES (LOOPS / IF) ---

    fn parse_if(&mut self, condition_met: bool) {
        self.expect_keyword("if"); self.next(); 
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        if condition_met {
            while let Some(token) = self.peek() {
                if let Token::Keyword(ref k) = token { if k == "end" { break; } }
                self.parse_statement();
            }
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
        } else { self.skip_logic_block(); }
    }

    fn skip_logic_block(&mut self) {
        let mut block_depth = 1;
        while block_depth > 0 {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if ["if", "swarm", "scan", "while", "for", "op"].contains(&k.as_str()) { block_depth += 1; }
                if k == "end" { block_depth -= 1; }
            }
            if block_depth == 0 { break; } 
            self.next();
        }
        self.next(); 
    }

    fn parse_while(&mut self) {
        self.expect_keyword("while"); 
        let condition_start_pos = self.pos;
        loop {
            self.pos = condition_start_pos;
            if let Value::Bool(condition_is_true) = self.parse_condition() {
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                if !condition_is_true { self.skip_logic_block(); break; }
                while let Some(token) = self.peek() { 
                    if let Token::Keyword(ref k) = token { if k == "end" { break; } } 
                    self.parse_statement(); 
                }
            } else { break; }
        }
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for"); 
        let iter_variable = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("in"); 
        
        let mut iteration_items = Vec::new();
        match self.peek() {
            Some(Token::StringLiteral(filename)) => { 
                self.next(); 
                let content = fs::read_to_string(filename).unwrap_or_default();
                iteration_items = content.lines().map(|line| Value::Str(line.to_string())).collect(); 
            },
            Some(Token::Identifier(list_name)) => { 
                self.next(); 
                if let Some(Value::List(l)) = self.memory.get(&list_name) { iteration_items = l.clone(); } 
            },
            _ => panic!("Invalid iteration source"),
        }
        
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let loop_body_start_pos = self.pos;
        
        for item_value in iteration_items {
            self.memory.insert(iter_variable.clone(), item_value); 
            self.pos = loop_body_start_pos;
            while let Some(token) = self.peek() { 
                if let Token::Keyword(ref k) = token { if k == "end" { break; } } 
                self.parse_statement(); 
            }
        }
        self.pos = loop_body_start_pos; 
        self.skip_logic_block();
    }

    fn parse_wait(&mut self) { 
        self.expect_keyword("wait"); 
        let ms_delay = if let Value::Num(n) = self.parse_factor() { n as u64 } else { 0 }; 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        thread::sleep(Duration::from_millis(ms_delay)); 
    }

    fn parse_file_operation(&mut self, is_append: bool) { 
        self.next(); 
        let filepath = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); }; 
        let content_to_write = match self.parse_factor() { 
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), Value::List(l) => format!("{:?}", l), 
        }; 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        let mut file_options = OpenOptions::new(); 
        file_options.write(true).create(true); 
        if is_append { file_options.append(true); } else { file_options.truncate(true); } 
        if let Ok(mut file) = file_options.open(filepath) { let _ = writeln!(file, "{}", content_to_write); } 
    }

    fn parse_list_push(&mut self) { 
        self.expect_keyword("push"); 
        let list_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; 
        let value_to_add = self.parse_factor(); 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        if let Some(Value::List(internal_list)) = self.memory.get_mut(&list_name) { internal_list.push(value_to_add); } 
    }

    fn parse_list_pop(&mut self) { 
        self.expect_keyword("pop"); 
        let list_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        if let Some(Value::List(internal_list)) = self.memory.get_mut(&list_name) { internal_list.pop(); } 
    }
}

// =====================================================================
// --- SYSTEM ENTRY POINT ---
// =====================================================================

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { 
        println!("[!] Error: No breach payload provided.");
        return; 
    }
    
    let raw_code = fs::read_to_string(&args[1]).unwrap_or_else(|_| {
        println!("[!] Error: Failed to read file {}", args[1]);
        std::process::exit(1);
    });
    
    let raw_tokens = lexer(&raw_code);
    let mutated_tokens = mutate_token_stream(raw_tokens);
    let mut execution_engine = Parser::new(mutated_tokens);
    execution_engine.parse();
}