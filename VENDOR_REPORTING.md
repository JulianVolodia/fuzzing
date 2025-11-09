# Security Vulnerability Reporting Guide

This comprehensive guide explains how to report security vulnerabilities to major vendors including Apple, Microsoft, Google, and others.

## 🎯 General Principles

### Before You Report

1. **Verify the vulnerability is real**
   - Can you reproduce it consistently?
   - Does it work on the latest version?
   - Is it actually a security issue?

2. **Minimize the test case**
   ```bash
   # Use libFuzzer's minimization
   ./fuzzer -minimize_crash=1 -runs=10000 crash-xxxxx
   ```

3. **Assess the impact**
   - Remote vs. local exploitation
   - User interaction required?
   - Sandbox escape? Kernel access?
   - Data exposure?

4. **Check if it's already known**
   - Search CVE databases
   - Check vendor security advisories
   - Look at recent patches

### Report Quality Checklist

✅ Clear vulnerability description
✅ Affected versions identified
✅ Minimized proof-of-concept
✅ Step-by-step reproduction
✅ Impact assessment
✅ Suggested fix (optional but appreciated)
✅ Your contact information

## 🍎 Apple Security Reporting

### Contact Information

- **Apple Security Bounty**: https://security.apple.com/
- **Email**: product-security@apple.com
- **PGP Key**: Available at https://support.apple.com/en-us/HT201220

### Scope

**In Scope:**
- macOS, iOS, iPadOS, watchOS, tvOS
- Safari and WebKit
- iCloud services
- Apple hardware (including Secure Enclave)
- First-party applications

**Out of Scope:**
- Third-party apps on App Store
- Physical access required
- Social engineering
- Denial of service (unless severe)

### Bounty Amounts

| Category | Amount (USD) |
|----------|--------------|
| Zero-click kernel code execution | $2,000,000 |
| Zero-click kernel code execution w/ persistence | $2,000,000 |
| Network attack w/o user interaction | Up to $1,000,000 |
| Zero-click user data extraction | $1,000,000 |
| Physical attack requiring expensive hardware | Up to $1,000,000 |
| One-click kernel code execution | $500,000 |
| User code execution kernel bypass | $500,000 |
| Sandboxed code execution | $250,000 |
| Authentication bypass | $250,000 |
| User data access without authentication | $100,000 |

**Bonus Multipliers:**
- Fuzzing kernel extensions without code execution: 1.5x
- Highly valuable reports: Up to 2x

### Report Template for Apple

```markdown
# [Component] [Vulnerability Type] in [Affected Product]

## Summary
Brief description of the vulnerability in 2-3 sentences.

## Affected Versions
- macOS: [Version, Build Number]
- iOS: [Version, Build Number]
- Component: [Framework/Library name and version]

## Vulnerability Details
Detailed technical description of the vulnerability.

### Type
- [ ] Memory Corruption (Buffer Overflow, Use-After-Free, etc.)
- [ ] Logic Error
- [ ] Authentication Bypass
- [ ] Information Disclosure
- [ ] Other: ___________

### Impact
- [ ] Remote Code Execution
- [ ] Privilege Escalation
- [ ] Sandbox Escape
- [ ] Information Disclosure
- [ ] Denial of Service

## Reproduction Steps

1. Build the proof-of-concept:
   ```bash
   clang++ -fsanitize=address poc.cc -framework CoreGraphics -o poc
   ```

2. Run the proof-of-concept:
   ```bash
   ./poc crash_file.png
   ```

3. Observe crash with AddressSanitizer output:
   ```
   ==12345==ERROR: AddressSanitizer: heap-buffer-overflow
   ...
   ```

## Proof of Concept

Attached files:
- poc.cc - Source code to reproduce
- crash_file.png - Minimized crashing input
- crash_log.txt - Full crash log with symbols

## Suggested Fix

Optional: Describe potential mitigation or fix.

## Timeline

- Discovery date: YYYY-MM-DD
- Initial report date: YYYY-MM-DD

## Credit

Name: [Your Name]
Affiliation: [Optional]
```

### What Apple Looks For

✅ **Good Reports:**
- Clear, reproducible steps
- Minimized test cases
- Detailed impact analysis
- Works on latest OS version

❌ **Poor Reports:**
- Vague descriptions
- Large/complex test cases
- Already patched vulnerabilities
- Low/no security impact

## 🪟 Microsoft Security Reporting

### Contact Information

- **MSRC Portal**: https://msrc.microsoft.com/report
- **Email**: secure@microsoft.com
- **Bounty Programs**: https://www.microsoft.com/en-us/msrc/bounty

### Scope

**In Scope:**
- Windows OS (all supported versions)
- Microsoft Edge
- Office 365
- Azure cloud services
- Visual Studio
- .NET Framework
- Xbox

**Out of Scope:**
- Unsupported Windows versions (e.g., Windows 7, XP)
- Denial of service (unless critical)
- Deprecated products

### Bounty Amounts

#### Windows Bounty Program
| Category | Amount (USD) |
|----------|--------------|
| Hyper-V Remote Code Execution | $250,000 |
| Windows Remote Code Execution | $20,000 - $100,000 |
| Windows Elevation of Privilege | $10,000 - $30,000 |
| Windows Information Disclosure | $3,000 - $10,000 |
| Windows Defense in Depth | $500 - $5,000 |

#### Microsoft Edge Bounty
| Category | Amount (USD) |
|----------|--------------|
| Critical RCE | $30,000 - $100,000 |
| Important RCE | $15,000 - $50,000 |
| EoP/ASLR/Sandbox Bypass | $10,000 - $40,000 |
| Information Disclosure | $3,000 - $10,000 |

### Report Template for Microsoft

```markdown
Title: [Component] [Vulnerability Type] leading to [Impact]

## Executive Summary
Brief non-technical description for triage.

## Technical Details

### Affected Products
- Product: Windows 11 / Windows Server 2022
- Versions: [Specific versions tested]
- Component: GDI+, DirectWrite, etc.
- Architecture: x64 / x86 / ARM64

### Vulnerability Class
- CWE-###: [CWE Name]
- Vulnerability Type: Use-After-Free, Buffer Overflow, etc.

### Attack Scenario
Describe how an attacker would exploit this:
1. Attacker sends malicious [file type]
2. Victim opens in [application]
3. Vulnerability triggers
4. Attacker achieves [impact]

### Impact Assessment
- Confidentiality: [None/Low/Medium/High]
- Integrity: [None/Low/Medium/High]
- Availability: [None/Low/Medium/High]
- Attack Complexity: [High/Medium/Low]
- User Interaction: [Required/Not Required]

## Proof of Concept

### Build Instructions
```powershell
clang++ -fsanitize=address poc.cc -lgdiplus -o poc.exe
```

### Execution
```powershell
.\poc.exe malicious_image.png
```

### Expected Result
Application crashes with memory corruption.

### Actual Result
```
(c8c.1234): Access violation - code c0000005 (first chance)
rax=0000000000000000 rbx=00007ff800000000 rcx=0000000041414141
...
```

## Remediation Suggestions
Optional: Suggest how Microsoft could fix this.

## Disclosure Timeline
Microsoft has 90 days from report acknowledgment for coordinated disclosure.

## Additional Information
- Affected file: gdiplus.dll version 10.0.22000.1
- Call stack, crash dump analysis, etc.
```

### Microsoft's Response Timeline

1. **Initial Response**: 24-48 hours (acknowledgment)
2. **Case Assignment**: 1-3 days
3. **Triage**: 1-2 weeks
4. **Bounty Decision**: 2-4 weeks after triage
5. **Fix Development**: Varies (usually next Patch Tuesday)
6. **Public Disclosure**: Coordinated with security bulletin

## 🔍 Google Security Reporting

### Contact Information

- **Google VRP**: https://bughunters.google.com/
- **Chrome Bugs**: https://bugs.chromium.org/p/chromium/issues/entry?template=Security+Bug
- **Android**: https://source.android.com/security/overview/updates-resources#report-issues

### Scope

**Chrome/Chromium:**
- Renderer exploits
- Browser process exploits
- Sandbox escapes
- Extension vulnerabilities
- Site isolation bypasses

**Android:**
- Framework vulnerabilities
- Kernel vulnerabilities
- OEM/Chipset vulnerabilities
- Bootloader vulnerabilities

**Google Cloud:**
- GCP infrastructure
- App Engine
- Compute Engine
- Cloud Storage

### Bounty Amounts

#### Chrome Vulnerability Rewards
| Category | Baseline | High Quality |
|----------|----------|--------------|
| Critical RCE | $15,000 | $45,000+ |
| High Severity | $7,500 | $22,500 |
| Medium Severity | $3,000 | $9,000 |
| Low Severity | $1,000 | $3,000 |

**Multipliers:**
- High quality: 1.5x
- Exceptional quality: 3x+
- Exploitable bugs: Higher rewards

#### Android Security Rewards
| Category | Amount (USD) |
|----------|--------------|
| Kernel RCE | $30,000 - $250,000 |
| Remote exploit chain | $10,000 - $150,000 |
| Lockscreen bypass | $2,000 - $30,000 |
| TrustZone/TEE | $10,000 - $200,000 |

### Report Template for Google

```markdown
# [Component] [Vulnerability] in [Product]

## Description
One paragraph summary of the issue.

## Reproduction Case

### Version
- Chrome Version: 120.0.6099.109 (Official Build) (64-bit)
- Operating System: Windows 11 / macOS 14.1 / Ubuntu 22.04
- Tested on: [Date]

### Test Case
Attached: test_case.html (minimized)

### Steps to Reproduce
1. Open Chrome with --disable-web-security for testing
2. Navigate to test_case.html
3. Click "Trigger Bug"
4. Observe crash in renderer process

### Expected Behavior
Page should display error message.

### Actual Behavior
Renderer crashes with heap corruption:
```
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x614000000240
READ of size 8 at 0x614000000240 thread T0
    #0 0x7f3a1b in blink::Node::ownerDocument() third_party/blink/renderer/core/dom/node.cc:123
```

## Impact

### Severity Assessment
- Security Impact: High
- Exploitability: Medium
- User Interaction: Click link

### Attack Scenario
1. Attacker hosts malicious page
2. Victim visits page
3. Renderer exploited
4. Sandbox escape required for full RCE

## Additional Information

### Crash Type
Heap use-after-free in Blink rendering engine

### Root Cause
Object lifetime management issue in DOM manipulation

### Affected Components
- Blink: third_party/blink/renderer/core/
- Component: Blink>DOM

### Potential Fix
Add ref-counting to affected object

## Attachments
- test_case.html (minimized)
- crash_log.txt
- poc_explanation.md (detailed write-up)
```

### What Google Rewards

✅ **High Quality Reports Include:**
- Minimized test cases
- Root cause analysis
- Potential security impact explained
- Suggested fixes
- Works on stable channel

🏆 **Exceptional Reports Also Have:**
- Full exploit chain
- Bypass demonstrations
- Novel attack techniques
- Multiple bugs chained

## 🌐 Other Vendors

### Mozilla (Firefox)

- **Bugzilla**: https://bugzilla.mozilla.org/
- **Security**: https://www.mozilla.org/security/bug-bounty/
- **Bounty Range**: $500 - $10,000

### Adobe

- **PSIRT**: https://helpx.adobe.com/security/report-vulnerability.html
- **Bug Bounty**: Via HackerOne and Bugcrowd
- **Bounty Range**: $500 - $10,000+

### Oracle

- **Critical Patch Update**: Via email to secalert_us@oracle.com
- **Bounty**: Via bug bounty program
- **Disclosure**: Quarterly patches

### Linux Distributions

- **Ubuntu**: security@ubuntu.com
- **Red Hat**: security@redhat.com
- **Debian**: security@debian.org
- **Kernel**: security@kernel.org

## 📋 General Reporting Best Practices

### Do's ✅

1. **Be Professional**
   - Use clear, technical language
   - Be respectful and patient
   - Follow up if no response after 1 week

2. **Provide Complete Information**
   - Reproducible steps
   - Version information
   - Minimized test cases
   - System configuration

3. **Assess Impact Accurately**
   - Don't overstate severity
   - Explain actual risk
   - Consider attack scenarios

4. **Follow Disclosure Timelines**
   - Typically 90 days
   - Respect vendor requests for extensions
   - Coordinate public disclosure

5. **Keep It Confidential**
   - Don't share details publicly before patch
   - Don't sell vulnerabilities
   - Don't discuss on social media

### Don'ts ❌

1. **Don't Rush**
   - Take time to minimize test case
   - Verify on multiple versions
   - Write clear reproduction steps

2. **Don't Spam**
   - One report per vulnerability
   - Don't submit duplicates
   - Don't flood vendor with minor issues

3. **Don't Threaten**
   - No ransom demands
   - No disclosure deadlines in first email
   - No threats of exploitation

4. **Don't Exploit**
   - Never attack production systems
   - Don't weaponize vulnerabilities
   - Don't test on users' data

## 💰 Maximizing Bounty Awards

### Quality Over Quantity

One high-quality critical vulnerability report can earn more than 100 low-quality medium reports.

### What Makes a Report "High Quality"?

1. **Minimized Test Case**
   - Small file size (< 1 KB ideal)
   - No unnecessary complexity
   - Fast to reproduce

2. **Root Cause Analysis**
   - Explain the bug
   - Show the vulnerable code (if possible)
   - Explain why it happens

3. **Impact Demonstration**
   - Show real-world attack scenario
   - Demonstrate exploitability
   - Chain bugs if applicable

4. **Clear Documentation**
   - Step-by-step reproduction
   - Screenshots/videos
   - Debugger output

5. **Suggested Fix**
   - Show understanding of codebase
   - Propose concrete solution
   - Consider performance impact

### Timing Matters

- Report to vendors during business days (Tuesday-Thursday)
- Avoid holidays and weekends
- Check vendor's patch cycle (e.g., Microsoft Patch Tuesday)

## 🎓 Learning From Others

### Public Vulnerability Databases

- **CVE**: https://cve.mitre.org/
- **NVD**: https://nvd.nist.gov/
- **Google Project Zero**: https://googleprojectzero.blogspot.com/
- **Talos Intelligence**: https://talosintelligence.com/vulnerability_reports

### Bug Bounty Disclosure Blogs

Many researchers blog about their findings after disclosure:
- https://googleprojectzero.blogspot.com/
- https://securit yresearch.google/
- Individual researcher blogs (search for "[vendor] CVE blog")

## 📞 Vendor Contact Quick Reference

| Vendor | Primary Contact | Bug Bounty | Response Time |
|--------|----------------|------------|---------------|
| Apple | product-security@apple.com | Yes, up to $2M | 1-7 days |
| Microsoft | msrc.microsoft.com/report | Yes, up to $250K | 1-3 days |
| Google | bughunters.google.com | Yes, up to $250K+ | 1-2 days |
| Mozilla | bugzilla.mozilla.org | Yes, up to $10K | 1-3 days |
| Adobe | HackerOne/Bugcrowd | Yes, varies | 1-7 days |
| Linux | vendor-specific | Varies | Varies |

## ⚖️ Legal Considerations

### Safe Harbor

Most vendors provide "safe harbor" for security research:
- No legal action if you follow responsible disclosure
- Must not access user data
- Must not cause damage
- Must report findings privately

### Always Check Terms

Before testing, review:
- Vendor bug bounty terms
- Responsible disclosure policy
- Scope and rules of engagement
- Legal protection offered

## 🎯 Final Checklist Before Submitting

Before hitting "Submit", verify:

- [ ] Vulnerability is reproducible
- [ ] Test case is minimized
- [ ] Works on latest version
- [ ] Not already reported/patched
- [ ] Clear security impact
- [ ] Professional report format
- [ ] All required information included
- [ ] Appropriate vendor selected
- [ ] Your contact info correct

## 🏆 Success Stories

Remember: Every major vendor has paid millions in bounties to researchers who followed these practices. Your fuzzing work can contribute to making software more secure for everyone while earning substantial rewards.

**Good luck and responsible disclosure!** 🐛🔒💰
