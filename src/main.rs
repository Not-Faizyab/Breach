use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write as StdWrite};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- CORE DATA ARCHITECTURE ---

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Keyword(String), Identifier(String), Number(f64), IpAddress(String),
    StringLiteral(String), Compare(String), Assign, Operator(String),
    Delimiter, Punctuation(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Value { 
    Num(f64), 
    Str(String), 
    Bool(bool), 
    List(Vec<Value>) 
}

// --- LEXICAL ANALYSIS ---

fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let token_rules = vec![
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        ("KEYWORD", r"\b(set|scan|payload|if|while|for|in|end|log|swarm|ports|to|write|append|wait|list|push|pop|rand)\b"),
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
        if m.start() > last_end { panic!("[FATAL] Lexer failure at offset {}.", last_end); }
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

fn mutate_token_stream(tokens: Vec<Token>) -> Vec<Token> {
    let mut mutated = Vec::new();
    for token in tokens {
        mutated.push(token.clone());
        if let Token::Delimiter = token {
            let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as usize;
            if seed % 10 < 3 {
                let id = format!("_v_{}", seed % 1000);
                mutated.push(Token::Keyword("set".to_string()));
                mutated.push(Token::Identifier(id));
                mutated.push(Token::Assign);
                mutated.push(Token::Number((seed % 100) as f64));
                mutated.push(Token::Operator("+".to_string()));
                mutated.push(Token::Number(1.0));
                mutated.push(Token::Delimiter);
            }
        }
    }
    mutated
}

// --- EXECUTION ENGINE ---

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
        panic!("[RUNTIME_ERROR] Expected keyword '{}' at pos {}.", kw, self.pos);
    }

    fn parse(&mut self) {
        while self.pos < self.tokens.len() {
            self.parse_next_stmt();
        }
    }

    fn parse_next_stmt(&mut self) {
        if let Some(tok) = self.peek() {
            match tok {
                Token::Keyword(k) => match k.as_str() {
                    "set" => self.parse_assignment(),
                    "log" => self.parse_log(),
                    "scan" => self.parse_scan(),
                    "swarm" => self.parse_swarm(),
                    "payload" => self.parse_payload(),
                    "while" => self.parse_while(),
                    "for" => self.parse_for(),
                    "if" => { self.parse_if(true); },
                    "wait" => self.parse_wait(),
                    "write" => self.parse_file_op(false),
                    "append" => self.parse_file_op(true),
                    "push" => self.parse_list_push(),
                    "pop" => self.parse_list_pop(),
                    "end" => { self.next(); },
                    _ => self.next(),
                },
                _ => self.next(),
            }
        }
    }

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Assign) = self.peek() { self.next(); }
        
        let val = if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "list" => { self.next(); Value::List(Vec::new()) },
                "rand" => self.parse_rand(),
                _ => self.parse_condition(),
            }
        } else { self.parse_condition() };

        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        self.memory.insert(name, val);
    }

    fn parse_rand(&mut self) -> Value {
        self.expect_keyword("rand");
        let start = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 0 };
        self.expect_keyword("to");
        let end = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 100 };
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;
        let result = start + (seed % (end - start + 1).max(1));
        Value::Num(result as f64)
    }

    fn parse_list_push(&mut self) {
        self.expect_keyword("push");
        let list_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let val = self.parse_factor();
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        if let Some(Value::List(list)) = self.memory.get_mut(&list_name) {
            list.push(val);
        }
    }

    fn parse_list_pop(&mut self) {
        self.expect_keyword("pop");
        let list_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        if let Some(Value::List(list)) = self.memory.get_mut(&list_name) {
            list.pop();
        }
    }

    fn parse_file_op(&mut self, is_append: bool) {
        self.next(); // Consume keyword
        let path = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); };
        let val_to_write = match self.parse_factor() {
            Value::Num(n) => n.to_string(),
            Value::Str(s) => s,
            Value::Bool(b) => b.to_string(),
            Value::List(l) => format!("{:?}", l),
        };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        let mut options = OpenOptions::new();
        options.write(true).create(true);
        if is_append { options.append(true); } else { options.truncate(true); }
        if let Ok(mut f) = options.open(path) { let _ = writeln!(f, "{}", val_to_write); }
    }

    fn parse_wait(&mut self) {
        self.expect_keyword("wait");
        let ms = if let Value::Num(n) = self.parse_factor() { n as u64 } else { 0 };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        thread::sleep(Duration::from_millis(ms));
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
                    Some(Value::Bool(b)) => b.to_string(),
                    Some(Value::List(l)) => format!("{:?}", l),
                    None => "null".to_string(),
                }
            },
            Some(Token::Number(n)) => { self.next(); n.to_string() },
            _ => panic!("Log target invalid"),
        };
        println!("{}", val);
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    fn parse_condition(&mut self) -> Value {
        let left = self.parse_expression();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next();
            let right = self.parse_expression();
            if let (Value::Num(l), Value::Num(r)) = (&left, &right) {
                let res = match op.as_str() {
                    "==" => l == r, "!=" => l != r, ">" => l > r, "<" => l < r, ">=" => l >= r, "<=" => l <= r, _ => false
                };
                return Value::Bool(res);
            }
        }
        left
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
        let tok = self.peek().expect("EOF");
        self.next();
        match tok {
            Token::Number(n) => Value::Num(n),
            Token::StringLiteral(s) | Token::IpAddress(s) => Value::Str(s),
            Token::Identifier(id) => self.memory.get(&id).cloned().unwrap_or(Value::Num(0.0)),
            _ => panic!("Factor error"),
        }
    }

    fn parse_while(&mut self) {
        self.expect_keyword("while");
        let start = self.pos;
        loop {
            self.pos = start;
            if let Value::Bool(b) = self.parse_condition() {
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                if !b { self.skip_block(); break; }
                while let Some(tok) = self.peek() {
                    if let Token::Keyword(ref k) = tok { if k == "end" { break; } }
                    self.parse_next_stmt();
                }
            } else { break; }
        }
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for");
        let it = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("in");
        
        let mut items = Vec::new();
        match self.peek() {
            Some(Token::StringLiteral(s)) => { // File iteration
                self.next();
                let content = fs::read_to_string(s).unwrap_or_default();
                items = content.lines().map(|l| Value::Str(l.to_string())).collect();
            },
            Some(Token::Identifier(id)) => { // List iteration
                self.next();
                if let Some(Value::List(l)) = self.memory.get(&id) { items = l.clone(); }
            },
            _ => panic!("For loop source invalid"),
        }

        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let block_start = self.pos;
        for val in items {
            self.memory.insert(it.clone(), val);
            self.pos = block_start;
            while let Some(tok) = self.peek() {
                if let Token::Keyword(ref k) = tok { if k == "end" { break; } }
                self.parse_next_stmt();
            }
        }
        self.pos = block_start;
        self.skip_block();
    }

    fn skip_block(&mut self) {
        let mut d = 1;
        while d > 0 {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if ["if", "swarm", "scan", "while", "for"].contains(&k.as_str()) { d += 1; }
                if k == "end" { d -= 1; }
            }
            if d == 0 { break; }
            self.next();
        }
        self.next();
    }

    fn parse_scan(&mut self) {
        self.expect_keyword("scan");
        let t = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let ip = match self.memory.get(&t) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let port = match self.memory.get("port") { Some(Value::Num(p)) => *p as u16, _ => 80 };
        let status = TcpStream::connect_timeout(&format!("{}:{}", ip, port).parse().unwrap(), Duration::from_millis(500)).is_ok();
        self.parse_if(status);
    }

    fn parse_swarm(&mut self) {
        self.expect_keyword("swarm");
        let t = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("ports");
        let start = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        self.expect_keyword("to");
        let end = if let Value::Num(n) = self.parse_factor() { n as u16 } else { 0 };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let mut sub = Vec::new();
        let mut d = 1;
        while let Some(tok) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = tok {
                if ["if", "for", "while", "swarm", "scan"].contains(&k.as_str()) { d += 1; }
                if k == "end" { d -= 1; if d == 0 { break; } }
            }
            sub.push(tok);
        }
        let ip = match self.memory.get(&t) { Some(Value::Str(s)) => s.clone(), _ => panic!() };
        let mem = self.memory.clone();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ts = vec![];
            for port in start..=end {
                let (ip_c, sub_c, mut mem_c) = (ip.clone(), sub.clone(), mem.clone());
                ts.push(tokio::task::spawn_blocking(move || {
                    let open = TcpStream::connect_timeout(&format!("{}:{}", ip_c, port).parse().unwrap(), Duration::from_millis(400)).is_ok();
                    mem_c.insert("port".to_string(), Value::Num(port as f64));
                    let mut p = Parser::new(sub_c); p.memory = mem_c;
                    p.run_swarm_inner(open);
                }));
            }
            for t in ts { let _ = t.await; }
        });
    }

    fn run_swarm_inner(&mut self, open: bool) {
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if k == "if" { self.parse_if(open); } else { self.parse_next_stmt(); }
            } else { self.next(); }
        }
    }

    fn parse_if(&mut self, cond: bool) {
        self.expect_keyword("if");
        self.next();
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        if cond {
            while let Some(tok) = self.peek() {
                if let Token::Keyword(ref k) = tok { if k == "end" { break; } }
                self.parse_next_stmt();
            }
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
        } else { self.skip_block(); }
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let t_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let p_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { if let Some(Token::Number(n)) = self.peek() { self.next(); n.to_string() } else { panic!(); } };
        let data = if let Some(Token::StringLiteral(s)) = self.peek() { self.next(); s } else { panic!(); };
        let ip = match self.memory.get(&t_id) { Some(Value::Str(s)) => s.clone(), _ => t_id };
        let port = match self.memory.get(&p_id) { Some(Value::Num(n)) => *n as u16, _ => p_id.parse().unwrap_or(80) };
        if let Ok(mut s) = TcpStream::connect_timeout(&format!("{}:{}", ip, port).parse().unwrap(), Duration::from_secs(1)) {
            let _ = s.write_all(data.replace("\\n", "\n").replace("\\r", "\r").as_bytes());
            let mut b = [0; 4096];
            if let Ok(n) = s.read(&mut b) { if n > 0 { println!("{}", String::from_utf8_lossy(&b[..n]).trim()); } }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { return; }
    let code = fs::read_to_string(&args[1]).unwrap_or_default();
    let mutated = mutate_token_stream(lexer(&code));
    let mut parser = Parser::new(mutated);
    parser.parse();
}