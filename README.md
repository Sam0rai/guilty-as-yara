# Guilty-As-Yara
💡In a nutshell: Think about it as an EICAR creating tool - only for Yara rules!

A Rust-based tool that generates Windows PE executables containing data patterns designed to trigger YARA rule matches. This is invaluable for validating YARA rules and ensuring your malware detection signatures work as expected.



## 🎯 Purpose

When developing YARA rules for malware detection, or when performing Threat Hunting based on YARA rules, you need to verify that your rules correctly identify target patterns, or that your scanning works correctly. This tool automates the creation of **test PE files** that contain the exact strings and byte sequences your YARA rules are searching for, providing a reliable way to:

- Validate YARA rule effectiveness
- Test hex pattern matching
- Create safe test files for CI/CD pipelines


## 🚀 Features

- **YARA Rule Parsing**: Extracts both string literals and hex byte sequences from YARA rule files
- **Multi-line Hex Pattern Support**: Handles complex hex patterns spanning multiple lines
- **Safe PE Generation**: Creates Windows executables that are safe to run (immediately exit)
- **Smart Pattern Placement**: Embeds patterns in both executable and data sections while maintaining safety
- **Wildcard Handling**: Properly processes `??` wildcards in hex patterns with safe byte substitution (0x90)


## 🛠️ Installation

Clone the repo and build with Cargo:

```bash
git clone https://github.com/Sam0rai/guilty-as-yara.git
cd my-rust-project
cargo build --release
```


## 📖 Usage
### Basic Usage
```bash
# Generate a test PE from YARA rules
cargo run -- rules.yar test_output.exe

# Or use the built binary
C:\Temp\guilty_as_yara.exe rules.yar test_output.exe
```

### Verify with YARA
```bash
yara rules.yar test_output.exe
```

### Example YARA Rule File
```yara
rule ExampleMalware {
    strings:
        $malicious_string = "evil_domain.com"
        $hex_pattern = {
            48 8B 0C 17
            41 8A 04 00
            80 E9 04
            75 ??
        }
    condition:
        any of them
}
```

## 🔧 Key Technical Components
1. **YARA Rule Parser (YaraRuleParser)**<br>
* Multi-line hex pattern handling: Correctly parses hex sequences spanning multiple lines.
* State machine parsing: Tracks rule sections (strings [ASCII and Wide], condition) and nested patterns.
* Robust error handling: Continues parsing even with minor syntax variations.
<br><br>
   
2. **Hex Pattern Processor (HexPattern)**<br>
```rust
impl HexPattern {
    fn parse(pattern: &str) -> Result<Self, Error>  // Parses { 48 8B ?? 17 } syntax
    fn generate_safe_bytes(&self) -> Vec<u8>        // Uses NOP (0x90) for wildcards
}
```
3. **Safe PE Builder (PEFileBuilder)**
* Structured PE headers: Generates valid DOS, PE, and section headers.
* Memory layout management: Proper RVA calculations and section alignment.
* Safe execution guarantee: Entry point directs to immediate clean exit.<br><br>

4. **Safe Code Generation**
```rust
fn add_safe_main_function(&mut self) {
    // Generates: push rbp, mov rbp, rsp, call ExitProcess(0)
}
fn create_safe_function_with_pattern(&self, pattern: &HexPattern) -> Vec<u8> {
    // Wraps patterns in never-executed conditional blocks
}
```