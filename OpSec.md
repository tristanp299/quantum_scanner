# Quantum Scanner - Operational Security Guide

This document outlines the operational security (OpSec) improvements made to Quantum Scanner and best practices for red team operations.

## Enhanced Security Features

### 1. Build Process Security
- Binary is stripped to remove debug symbols that could reveal information
- Ultra-minimal UPX compression enabled by default to produce the smallest possible binary size and obfuscate code patterns
- Secure clean-up of build artifacts to prevent forensic recovery
- Cross-compilation support to build on different platforms than deployment targets

### 2. Runtime Security
- DNS requests routed through Tor when available
- Randomized packet timing to evade pattern recognition
- Automatic enabling of evasion techniques
- Secure temporary logging to memory-backed locations
- Automatic secure deletion of logs
- Configurable packet TTL values to mimic legitimate traffic
- Protocol-specific mimicry to blend with normal service traffic
- Fragmentation techniques to bypass deep packet inspection

## Recommended Operational Security Practices

### Network-Level OpSec
1. **IP Masking**
   - Always use `--use-tor` when available for critical operations
   - Consider deploying on multiple throw-away VPS instances for distributed scanning
   - Utilize `--mimic-os` to match the target environment or traffic patterns

2. **Timing Considerations**
   - Use `--random-delay` with higher `--max-delay` values for stealthy operations
   - Set lower `--rate` limits to avoid detection by traffic volume analysis
   - Schedule scans during periods of high network activity to blend in

3. **Payload Security**
   - Use `--mimic-protocol` to match expected traffic types on the target network
   - Employ `--enhanced-evasion` for high-security environments
   - Consider `--dns-tunnel` or `--icmp-tunnel` in highly restricted environments

### System-Level OpSec
1. **Filesystem Security**
   - Always enable `--memory-only` mode for sensitive operations
   - Use `--use-ramdisk` for temporary storage when disk writes are necessary
   - Enable `--secure-delete` with multiple `--delete-passes` for critical operations
   - Never store results on the scanning system; use encrypted outputs

2. **Process Behavior**
   - Run in a containerized environment when possible
   - Disable core dumps and other debug features in your environment
   - Sandbox the scanner to prevent unintended system calls
   - Consider running as an unprivileged user when raw socket operations aren't needed

3. **Output Management**
   - Use `--encrypt-logs` with a strong, unique password
   - Collect results via secure channels with end-to-end encryption
   - Consider redirecting output to an encrypted volume that can be quickly detached

## Advanced Evasion Techniques

### Network Evasion
- Use `ScanType::Fin`, `ScanType::Null`, and `ScanType::Xmas` scans for bypassing simple firewalls
- Employ `ScanType::Frag` for bypassing signature-based intrusion detection systems
- Set appropriate timeouts to avoid leaving half-open connections that might trigger alerts
- Use the `-E/--enhanced-evasion` flag to enable all advanced evasion techniques

### Signature Evasion
- Customize `--mimic-protocol` with `--protocol-variant` to match expected client versions
- Use `--ttl-jitter` with values between 1-3 to randomize TTL values while maintaining realism
- Avoid scanning well-known honeypot port ranges (e.g., 22, 23, 25, 80, 443) in sequence
- Distribute scan operations across multiple source systems for critical targets

### Temporal Evasion
- Use random scan ordering with non-sequential port selection
- Implement extended delays between scan attempts to specific critical services
- Schedule scanning during business hours when legitimate traffic is higher
- Break scanning into multiple sessions across different days for long-term operations

## Post-Scan Security
- Securely wipe all temporary files and logs if used
- Destroy any RAM disks created during operation
- Consider using ephemeral systems that can be completely destroyed
- Never keep a record of the target IP addresses on the same system as the scanner results
- Encrypt all findings before transmission to analysis systems

## Legal and Ethical Considerations
- Always ensure you have proper authorization before scanning any systems
- Document your authorization and scope to prevent misunderstandings
- Respect the scan boundaries defined in your engagement rules
- Immediately stop scanning if you detect critical systems not in scope
- Report any accidental access to out-of-scope systems to your engagement contacts 