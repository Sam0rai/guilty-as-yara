use std::fs::File;
use std::io::Write;
use std::process;
use std::collections::HashSet;

// Simple PE header structures (minimal implementation)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DOSHeader {
    pub magic: u16,        // "MZ"
    pub cblp: u16,
    pub cp: u16,
    pub crlc: u16,
    pub cparhdr: u16,
    pub minalloc: u16,
    pub maxalloc: u16,
    pub ss: u16,
    pub sp: u16,
    pub csum: u16,
    pub ip: u16,
    pub cs: u16,
    pub lfarlc: u16,
    pub ovno: u16,
    pub res: [u16; 4],
    pub oemid: u16,
    pub oeminfo: u16,
    pub res2: [u16; 10],
    pub lfanew: u32,       // Offset to PE header
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PEHeader {
    pub signature: u32,    // "PE\0\0"
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PEOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

struct YaraRuleParser;

impl YaraRuleParser {
        fn parse_rules(file_path: &str) -> Result<Vec<YaraRule>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file_path)?;
        let mut rules = Vec::new();
        let mut current_rule: Option<YaraRule> = None;
        let mut in_strings_section = false;
        let mut current_hex_pattern: Option<(String, String)> = None;
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("rule ") {
                // Finish any pending hex pattern
                if let Some((var, pattern)) = current_hex_pattern.take() {
                    if let Some(rule) = &mut current_rule {
                        rule.strings.push((var, pattern));
                    }
                }
                
                if let Some(rule) = current_rule.take() {
                    rules.push(rule);
                }
                let name = line.split_whitespace().nth(1).unwrap_or("").trim_matches('{').trim().to_string();
                current_rule = Some(YaraRule {
                    name,
                    strings: Vec::new(),
                    condition: String::new(),
                });
                in_strings_section = false;
            } else if line == "strings:" {
                in_strings_section = true;
            } else if line.starts_with("$") && in_strings_section && current_hex_pattern.is_none() {
                // Start of a new string definition
                if let Some(rule) = &mut current_rule {
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let var = parts[0].trim().to_string();
                        let value = parts[1].trim();
                        
                        if value.starts_with('{') {
                            // Start of a multi-line hex pattern
                            if value.ends_with('}') {
                                // Single-line hex pattern
                                rule.strings.push((var, value.to_string()));
                            } else {
                                // Multi-line hex pattern - start collecting
                                current_hex_pattern = Some((var, value.to_string()));
                            }
                        } else {
                            // Regular string literal
                            rule.strings.push((var, value.to_string()));
                        }
                    }
                }
            } else if in_strings_section && current_hex_pattern.is_some() {
                // We're in the middle of a multi-line hex pattern
                if let Some((ref var, ref mut pattern)) = current_hex_pattern {
                    if line.ends_with('}') {
                        // End of the hex pattern
                        *pattern += " ";
                        *pattern += line;
                        if let Some(rule) = &mut current_rule {
                            rule.strings.push((var.clone(), pattern.clone()));
                        }
                        current_hex_pattern = None;
                    } else {
                        // Continue collecting hex pattern lines
                        *pattern += " ";
                        *pattern += line;
                    }
                }
            } else if line.starts_with("condition:") {
                // Finish any pending hex pattern before leaving strings section
                if let Some((var, pattern)) = current_hex_pattern.take() {
                    if let Some(rule) = &mut current_rule {
                        rule.strings.push((var, pattern));
                    }
                }
                
                if let Some(rule) = &mut current_rule {
                    rule.condition = line.replace("condition:", "").trim().to_string();
                }
                in_strings_section = false;
            } else if line == "}" {
                // Finish any pending hex pattern before ending rule
                if let Some((var, pattern)) = current_hex_pattern.take() {
                    if let Some(rule) = &mut current_rule {
                        rule.strings.push((var, pattern));
                    }
                }
                
                if let Some(rule) = current_rule.take() {
                    rules.push(rule);
                }
                in_strings_section = false;
            }
        }
        
        // Handle any remaining rule
        if let Some(rule) = current_rule.take() {
            rules.push(rule);
        }
        
        Ok(rules)
    }
}

#[derive(Debug)]
struct YaraRule {
    name: String,
    strings: Vec<(String, String)>,
    condition: String,
}

#[derive(Debug, Clone)]
struct HexPattern {
    bytes: Vec<Option<u8>>, // Some(byte) for fixed bytes, None for wildcards
    original_pattern: String,
}

impl HexPattern {
    fn parse(pattern: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let cleaned = pattern
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        
        let mut bytes = Vec::new();
        let mut parts = cleaned.split_whitespace().peekable();
        
        while let Some(part) = parts.next() {
            if part == "??" {
                // Single wildcard byte
                bytes.push(None);
            } else if part.starts_with('[') && part.ends_with(']') {
                // Handle [N] syntax for multiple wildcards
                if let Ok(count) = part.trim_matches('[').trim_matches(']').parse::<usize>() {
                    for _ in 0..count {
                        bytes.push(None);
                    }
                } else {
                    return Err(format!("Invalid wildcard count: '{}'", part).into());
                }
            } else if part.len() == 2 {
                // Regular hex byte
                if let Ok(byte) = u8::from_str_radix(part, 16) {
                    bytes.push(Some(byte));
                } else {
                    return Err(format!("Invalid hex byte: '{}'", part).into());
                }
            } else {
                return Err(format!("Invalid pattern part: '{}'", part).into());
            }
        }
        
        Ok(HexPattern {
            bytes,
            original_pattern: pattern.to_string(),
        })
    }
    
    fn generate_safe_bytes(&self) -> Vec<u8> {
        self.bytes.iter().map(|b| match b {
            Some(byte) => *byte,
            None => 0x90, // Always use NOP for wildcards (safe rule of thumb)
        }).collect()
    }
    
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

struct PEFileBuilder {
    data_section_content: Vec<u8>,
    code_section_content: Vec<u8>,
    hex_patterns: Vec<HexPattern>,
    unique_strings: HashSet<String>
}

impl PEFileBuilder {
    fn new() -> Self {
        Self {
            data_section_content: Vec::new(),
            code_section_content: Vec::new(),
            hex_patterns: Vec::new(),
            unique_strings: HashSet::new(),
        }
    }

    fn create_dos_stub(&self) -> Vec<u8> {
        let mut stub = Vec::new();
        // Minimal DOS program that just exits
        stub.extend_from_slice(&[
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
            0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
            0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
            0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        stub
    }

    fn add_yara_strings(&mut self, rules: &[YaraRule]) {
        for rule in rules {
            println!("Processing rule: {}", rule.name);
            
            for (var_name, pattern) in &rule.strings {
                println!("  Pattern {}: {}", var_name, pattern);
                
                if pattern.starts_with('{') && pattern.ends_with('}') {
                    // Hex byte sequence
                    match HexPattern::parse(pattern) {
                        Ok(hex_pattern) => {
                            println!("    Parsed hex pattern with {} bytes ({} fixed, {} wildcards)", 
                                hex_pattern.len(),
                                hex_pattern.bytes.iter().filter(|b| b.is_some()).count(),
                                hex_pattern.bytes.iter().filter(|b| b.is_none()).count());
                            
                            self.hex_patterns.push(hex_pattern);
                        }
                        Err(e) => {
                            eprintln!("    Failed to parse hex pattern: {}", e);
                        }
                    }
                } else {
                    // String literal
                    let clean_string = pattern.trim_matches('"');
                    if self.unique_strings.insert(clean_string.to_string()) {
                        let bytes = clean_string.as_bytes();
                        self.data_section_content.extend_from_slice(bytes);
                        self.data_section_content.push(0); // null terminator
                        
                        // Also add as wide string
                        let wide: Vec<u16> = clean_string.encode_utf16().collect();
                        unsafe {
                            let wide_bytes = std::slice::from_raw_parts(
                                wide.as_ptr() as *const u8,
                                wide.len() * 2,
                            );
                            self.data_section_content.extend_from_slice(wide_bytes);
                            self.data_section_content.extend_from_slice(&[0, 0]);
                        }
                        println!("    Added string: '{}'", clean_string);
                    }
                }
            }
        }
    }

    fn create_safe_function_with_pattern(&self, pattern: &HexPattern) -> Vec<u8> {
        let mut code = Vec::new();
        let safe_pattern = pattern.generate_safe_bytes();
        
        // Function that will never be called
        // Use an "always-false" condition
        code.extend_from_slice(&[
            0x48, 0x83, 0xEC, 0x08,                         // sub rsp, 8
            0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
            0x48, 0x83, 0x3C, 0x24, 0x01,                   // cmp qword [rsp], 1
            0x74, 0x02,                                     // je +2 (skip if equal - which never happens)
        ]);
        
        // Add the safe pattern
        code.extend_from_slice(&safe_pattern);
        
        // Function epilogue
        code.extend_from_slice(&[
            0x48, 0x83, 0xC4, 0x08,     // add rsp, 8
            0xC3,                       // ret
        ]);
        
        code
    }

    fn build_pe_file(&self, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(output_path)?;
        
        // DOS Header
        let dos_header = DOSHeader {
            magic: 0x5A4D, // "MZ"
            cblp: 0x0090,
            cp: 0x0003,
            crlc: 0x0000,
            cparhdr: 0x0004,
            minalloc: 0x0000,
            maxalloc: 0xFFFF,
            ss: 0x0000,
            sp: 0x00B8,
            csum: 0x0000,
            ip: 0x0000,
            cs: 0x0000,
            lfarlc: 0x0040,
            ovno: 0x0000,
            res: [0; 4],
            oemid: 0x0000,
            oeminfo: 0x0000,
            res2: [0; 10],
            lfanew: 0x00000080,
        };

        // Write DOS header
        unsafe {
            let header_slice = std::slice::from_raw_parts(
                &dos_header as *const _ as *const u8,
                std::mem::size_of::<DOSHeader>(),
            );
            file.write_all(header_slice)?;
        }

        // Write DOS stub
        let dos_stub = self.create_dos_stub();
        file.write_all(&dos_stub)?;

        // Pad to PE header
        let current_pos = 0x80;
        if current_pos < 0x80 {
            file.write_all(&vec![0; 0x80 - current_pos])?;
        }

        // PE Header
        let pe_header = PEHeader {
            signature: 0x00004550, // "PE\0\0"
            machine: 0x014C, // i386
            number_of_sections: 0x0002,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00E0,
            characteristics: 0x010F,
        };

        unsafe {
            let header_slice = std::slice::from_raw_parts(
                &pe_header as *const _ as *const u8,
                std::mem::size_of::<PEHeader>(),
            );
            file.write_all(header_slice)?;
        }

        // Optional Header
        let opt_header = PEOptionalHeader {
            magic: 0x010B,
            major_linker_version: 0x06,
            minor_linker_version: 0x00,
            size_of_code: 0x00000200,
            size_of_initialized_data: 0x00000200,
            size_of_uninitialized_data: 0x00000000,
            address_of_entry_point: 0x00001000,
            base_of_code: 0x00001000,
            base_of_data: 0x00002000,
            image_base: 0x00400000,
            section_alignment: 0x00001000,
            file_alignment: 0x00000200,
            major_operating_system_version: 0x0004,
            minor_operating_system_version: 0x0000,
            major_image_version: 0x0000,
            minor_image_version: 0x0000,
            major_subsystem_version: 0x0004,
            minor_subsystem_version: 0x0000,
            win32_version_value: 0x00000000,
            size_of_image: 0x00003000,
            size_of_headers: 0x00000200,
            check_sum: 0x00000000,
            subsystem: 0x0003, // Windows CUI
            dll_characteristics: 0x0000,
            size_of_stack_reserve: 0x00100000,
            size_of_stack_commit: 0x00001000,
            size_of_heap_reserve: 0x00100000,
            size_of_heap_commit: 0x00001000,
            loader_flags: 0x00000000,
            number_of_rva_and_sizes: 0x00000010,
        };

        unsafe {
            let header_slice = std::slice::from_raw_parts(
                &opt_header as *const _ as *const u8,
                std::mem::size_of::<PEOptionalHeader>(),
            );
            file.write_all(header_slice)?;
        }

        // Write zeroed data directories
        file.write_all(&vec![0; 0x80])?;

        // .text section
        let text_header = SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0x00000200,
            virtual_address: 0x00001000,
            size_of_raw_data: 0x00000200,
            pointer_to_raw_data: 0x00000200,
            pointer_to_relocations: 0x00000000,
            pointer_to_linenumbers: 0x00000000,
            number_of_relocations: 0x0000,
            number_of_linenumbers: 0x0000,
            characteristics: 0x60000020,
        };

        unsafe {
            let header_slice = std::slice::from_raw_parts(
                &text_header as *const _ as *const u8,
                std::mem::size_of::<SectionHeader>(),
            );
            file.write_all(header_slice)?;
        }

        // .data section
        let data_header = SectionHeader {
            name: *b".data\0\0\0",
            virtual_size: 0x00000200,
            virtual_address: 0x00002000,
            size_of_raw_data: 0x00000200,
            pointer_to_raw_data: 0x00000400,
            pointer_to_relocations: 0x00000000,
            pointer_to_linenumbers: 0x00000000,
            number_of_relocations: 0x0000,
            number_of_linenumbers: 0x0000,
            characteristics: 0xC0000040,
        };

        unsafe {
            let header_slice = std::slice::from_raw_parts(
                &data_header as *const _ as *const u8,
                std::mem::size_of::<SectionHeader>(),
            );
            file.write_all(header_slice)?;
        }

        // Pad to end of headers
        file.write_all(&vec![0; 0x200 - 0x1C0])?;

         // Write .text section with hex patterns and code
        file.write_all(&self.code_section_content)?;
        let text_padding = 0x400 - (self.code_section_content.len() % 0x400);
        file.write_all(&vec![0; text_padding])?;

        // Write .data section with strings
        file.write_all(&self.data_section_content)?;
        let data_padding = 0x200 - (self.data_section_content.len() % 0x200);
        file.write_all(&vec![0; data_padding])?;

        Ok(())
    }

    fn generate_safe_hex_pattern_bytes(&mut self) {
        // Add main function that does nothing and exits safely
        self.add_safe_main_function();

        // Add the hex patterns in never-called functions
        for pattern in &self.hex_patterns {
            println!("Generating safe bytes for pattern: {}", pattern.original_pattern);
            
            // Option 1: Safe bytes in never-called function
            let safe_function = self.create_safe_function_with_pattern(pattern);
            self.code_section_content.extend_from_slice(&safe_function);
            
            // Option 2: Also place in data section as raw bytes
            let safe_bytes = pattern.generate_safe_bytes();
            self.data_section_content.extend_from_slice(&safe_bytes);
            
            println!("    Added safe pattern ({} bytes)", safe_bytes.len());
        }        
    }

    fn add_safe_main_function(&mut self) {
        let mut main_code = Vec::new();
        
        // Safe main function that just exits cleanly
        main_code.extend_from_slice(&[
            // Function prologue
            0x55,                           // push rbp
            0x48, 0x89, 0xE5,               // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20,         // sub rsp, 0x20
            
            // Call ExitProcess(0)
            0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ExitProcess address
            0xFF, 0xD0,                    // call rax
            
            // Should never reach here, but just in case
            0x48, 0x83, 0xC4, 0x20,        // add rsp, 0x20
            0x5D,                          // pop rbp
            0xC3,                          // ret
        ]);
        
        // Insert at beginning of code section
        self.code_section_content.splice(0..0, main_code);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <yara_rule_file> <output_pe_file>", args[0]);
        process::exit(1);
    }

    let yara_file = &args[1];
    let output_file = &args[2];

    println!("Parsing YARA rules from: {}", yara_file);
    let rules = YaraRuleParser::parse_rules(yara_file)?;

    println!("Found {} rules", rules.len());
    
    let mut builder = PEFileBuilder::new();
    builder.add_yara_strings(&rules);
    
    builder.generate_safe_hex_pattern_bytes();

    println!("Building PE file: {}", output_file);
    builder.build_pe_file(output_file)?;

    println!("Successfully created SAFE test PE file");
    println!("- Embedded {} unique strings", builder.unique_strings.len());
    println!("- Processed {} hex patterns", builder.hex_patterns.len());
    println!("- Generated {} bytes of safe code", builder.code_section_content.len());
    println!("- Generated {} bytes of data", builder.data_section_content.len());
    println!("- Executable will exit immediately when run");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_parsing() {
        let test_rules = r#"
rule TestRule1 {
    strings:
        $s1 = "malicious_string"
        $s2 = "evil_domain.com"
    condition:
        any of them
}

rule TestRule2 {
    strings:
        $s3 = "suspicious_pattern"
    condition:
        $s3
}"#;

        std::fs::write("test_rules.yar", test_rules).unwrap();
        let rules = YaraRuleParser::parse_rules("test_rules.yar").unwrap();
        
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "TestRule1");
        assert_eq!(rules[0].strings.len(), 2);
        assert_eq!(rules[1].name, "TestRule2");
        assert_eq!(rules[1].strings.len(), 1);
        
        std::fs::remove_file("test_rules.yar").unwrap();
    }

    #[test]
    fn test_wildcard_syntax() {
        let pattern = "{E3 A0 00 0B E5 9F 11 EB [3] E3 A0 00 0D E5 9F 11 EB}";
        let hex_pattern = HexPattern::parse(pattern).unwrap();
        
        println!("Original pattern: {}", pattern);
        println!("Parsed bytes count: {}", hex_pattern.bytes.len());
        println!("Fixed bytes: {}", hex_pattern.bytes.iter().filter(|b| b.is_some()).count());
        println!("Wildcard bytes: {}", hex_pattern.bytes.iter().filter(|b| b.is_none()).count());
        
        let safe_bytes = hex_pattern.generate_safe_bytes();
        println!("Generated safe bytes: {:02X?}", safe_bytes);
        
        // Verify the structure:
        // Should have: 8 fixed bytes + 3 wildcards + 8 fixed bytes = 19 total bytes
        assert_eq!(hex_pattern.bytes.len(), 19);
        assert_eq!(hex_pattern.bytes.iter().filter(|b| b.is_some()).count(), 16);
        assert_eq!(hex_pattern.bytes.iter().filter(|b| b.is_none()).count(), 3);
        
        // Verify the positions of wildcards (should be at indices 8, 9, 10)
        assert!(hex_pattern.bytes[8].is_none());
        assert!(hex_pattern.bytes[9].is_none());
        assert!(hex_pattern.bytes[10].is_none());
    }
}