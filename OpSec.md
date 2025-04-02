# Quantum Scanner - Operational Security Guide

This document outlines the operational security (OpSec) improvements made to Quantum Scanner and best practices for red team operations.

## Enhanced Security Features

### 1. Build Process Security
- Binary is stripped to remove debug symbols that could reveal information
- UPX compression reduces binary size and obfuscates code patterns
- Secure clean-up of build artifacts to prevent forensic recovery

### 2. Runtime Security
- DNS requests routed through Tor when available
- Randomized packet timing to evade pattern recognition
- Automatic enabling of evasion techniques
- Secure temporary logging to memory-backed locations
- Automatic secure deletion of logs

### 3. Evasion Techniques
- OS fingerprint randomization via TTL manipulation
- Spoofed source IP capabilities 
- Realistic browser user-agent generation
- Traffic pattern randomization
- Protocol mimicry

### 4. Anti-Forensics
- Secure deletion of scan artifacts
- Automatic cleaning of shell history
- Optional memory-only operation mode (via --memory-only flag)
- Configurable logging options

## Usage for Red Team Operations

### Recommended Usage Pattern

1. **Preparation**
   ```
   # Build with enhanced security
   ./build.sh
   ```

2. **Execution**
   ```
   # Run through security-enhanced wrapper
   sudo ./run_scanner.sh [OPTIONS] <TARGET>
   ```

3. **Clean-up**
   ```
   # Remove all traces
   ./clean_traces.sh
   ```

### Enhanced Scan Profiles

#### Quick Common Port Discovery
Ideal for rapid enumeration of common services:
```
sudo ./run_scanner.sh --top-100 --enhanced-evasion TARGET
```

#### Low and Slow Reconnaissance
Ideal for initial target discovery without alerting security systems:
```
sudo ./run_scanner.sh -s fin,null -p 22,80,443,3389,8080 --rate 10 -e --memory-only TARGET
```

#### Comprehensive Coverage
For thorough enumeration once initial access is established:
```
sudo ./run_scanner.sh -s syn,ssl,udp -p 1-10000 -e --timeout 5 TARGET
```

#### Evasive Scanning
For high-security environments with advanced monitoring:
```
sudo ./run_scanner.sh -s frag,mimic -p 80,443,8080,8443 -e --memory-only --use-tor TARGET
```

## Operational Considerations

### Pre-Scan Checklist
- [ ] Verify you have authorization to scan the target
- [ ] Ensure proper network isolation (VPN/Tor)
- [ ] Check for host-based security systems
- [ ] Verify your source IP anonymization

### During Scan
- Limit scan duration and intensity
- Use progressive scan techniques (start slow, increase as needed)
- Monitor for detection/blocking responses
- Maintain operational awareness

### Post-Scan
- Verify all logs are securely deleted
- Clear shell history of scan commands
- Ensure all temporary files are removed
- Document findings securely

## Security Improvements

The following core improvements have been added to the Quantum Scanner codebase:

1. **Source IP Manipulation**
   - Realistic address generation based on common network patterns
   - Mimics legitimate client, router, or server addresses

2. **TTL Randomization**
   - Randomized Time-To-Live values in IP headers
   - Mimics common operating systems to blend with normal traffic
   - Helps evade network security systems that analyze packet TTL values

3. **Browser Emulation**
   - Realistic user agent randomization
   - Protocol-correct header formatting
   - Timing patterns matching real browser behavior

4. **Build Process Security**
   - Securely compiles and packages the scanner
   - Adds anti-forensic capabilities
   - Manages operational traces

5. **Environment Variable Control**
   - `QUANTUM_ALLOW_PRIVATE` - Enables scanning of private networks (disabled by default)

## Technical Details

### Network Behavior Randomization

The scanner can now mimic common network traffic patterns by:

1. Randomizing packet timing with realistic distributions
2. Using appropriate TTL values based on the OS being mimicked
3. Generating appropriate header values and flags
4. Implementing client-like behavior in connections

### Source Address Selection

Enhanced source address selection logic:

```rust
match network_class {
    Some("router") => {
        // Common router-like addresses (e.g., x.x.x.1, x.x.x.254)
        let first = rng.gen_range(1..223);
        let second = rng.gen_range(0..255);
        let third = rng.gen_range(0..255);
        let last = if rng.gen_bool(0.7) { 1 } else { 254 };
        
        IpAddr::V4(Ipv4Addr::new(first, second, third, last))
    },
    Some("client") => {
        // Addresses that look like typical client machines
        let first = match rng.gen_range(0..3) {
            0 => 10,                           // RFC1918 private (10.0.0.0/8)
            1 => 192,                          // RFC1918 private (192.168.0.0/16)
            _ => rng.gen_range(1..223),        // Random public
        };
        
        let second = if first == 192 { 168 } else { rng.gen_range(0..255) };
        let third = rng.gen_range(0..255);
        let last = rng.gen_range(2..254);      // Avoid .0, .1, and .255
        
        IpAddr::V4(Ipv4Addr::new(first, second, third, last))
    },
    // Additional patterns...
}
```

## Legal Notice

**IMPORTANT**: This scanner and its enhanced evasion techniques are intended for authorized security testing only. Unauthorized scanning may violate computer crime laws in most jurisdictions.

Always ensure you have explicit authorization before scanning any targets.

---

*Note: The techniques described in this document are for educational purposes and authorized security testing only. Always adhere to legal requirements and obtain proper authorization before security testing.* 