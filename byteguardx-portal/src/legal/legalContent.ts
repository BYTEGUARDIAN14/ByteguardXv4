export interface LegalContent {
  title: string;
  content: string;
}

export interface LegalContentMap {
  privacy: LegalContent;
  terms: LegalContent;
  security: LegalContent;
  license: LegalContent;
}

export const legalContent: LegalContentMap = {
  privacy: {
    title: "Privacy Policy",
    content: `# Privacy Policy

**Last updated: ${new Date().toLocaleDateString()}**

## Introduction

ByteGuardX ("we," "our," or "us") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our AI-powered vulnerability scanning platform.

## Information We Collect

### Information You Provide
- Account registration details (email, username)
- Scan configurations and preferences
- Support communications
- Feedback and survey responses

### Automatically Collected Information
- Usage analytics and performance metrics
- Device and browser information
- IP addresses and location data
- Scan results and vulnerability reports

### Code Analysis Data
- Source code patterns (processed locally)
- Vulnerability findings and classifications
- Dependency information
- Security metrics and trends

## How We Use Your Information

We use collected information to:
- Provide and maintain our scanning services
- Improve AI detection algorithms
- Generate security reports and analytics
- Provide customer support
- Send important service notifications
- Comply with legal obligations

## Data Security

We implement industry-standard security measures:
- AES-256 encryption for data at rest
- TLS 1.3 for data in transit
- Regular security audits and penetration testing
- Access controls and authentication
- Secure data centers and infrastructure

## Data Retention

- Scan results: Retained for 90 days unless deleted
- Account data: Retained while account is active
- Analytics data: Aggregated and anonymized after 12 months
- Support communications: Retained for 3 years

## Your Rights

You have the right to:
- Access your personal data
- Correct inaccurate information
- Delete your account and data
- Export your data
- Opt-out of marketing communications

## Third-Party Services

We may use third-party services for:
- Analytics and performance monitoring
- Payment processing
- Email communications
- Cloud infrastructure

## International Transfers

Your data may be transferred to and processed in countries other than your own. We ensure appropriate safeguards are in place.

## Children's Privacy

Our service is not intended for users under 13 years of age. We do not knowingly collect personal information from children.

## Changes to This Policy

We may update this Privacy Policy periodically. We will notify you of any material changes via email or through our service.

## Contact Us

For privacy-related questions or concerns:
- Email: privacy@byteguardx.com
- Address: ByteGuardX Privacy Team, [Address]
- Phone: [Phone Number]

By using ByteGuardX, you acknowledge that you have read and understood this Privacy Policy.`
  },

  terms: {
    title: "Terms of Service",
    content: `# Terms of Service

**Last updated: ${new Date().toLocaleDateString()}**

## Acceptance of Terms

By accessing or using ByteGuardX ("Service"), you agree to be bound by these Terms of Service ("Terms"). If you disagree with any part of these terms, you may not access the Service.

## Description of Service

ByteGuardX is an AI-powered security vulnerability scanner that:
- Analyzes source code for security vulnerabilities
- Detects secrets, dependencies, and AI-generated patterns
- Provides fix suggestions and security reports
- Operates in offline-first mode for privacy

## User Accounts

### Registration
- You must provide accurate and complete information
- You are responsible for maintaining account security
- One account per user or organization
- You must be at least 13 years old to use the Service

### Account Responsibilities
- Keep your login credentials secure
- Notify us immediately of any unauthorized access
- You are responsible for all activities under your account
- Do not share your account with others

## Acceptable Use

### Permitted Uses
- Scan your own code or code you have permission to analyze
- Use the Service for legitimate security testing
- Generate reports for internal security purposes
- Integrate with your development workflow

### Prohibited Uses
- Scan code without proper authorization
- Attempt to reverse engineer our AI models
- Use the Service for illegal activities
- Violate any applicable laws or regulations
- Interfere with or disrupt the Service

## Intellectual Property

### Your Content
- You retain ownership of your source code
- You grant us limited rights to process your code for scanning
- We do not claim ownership of your scan results
- You may delete your data at any time

### Our Content
- ByteGuardX owns all rights to the Service and technology
- Our AI models and algorithms are proprietary
- You may not copy, modify, or distribute our software
- All trademarks and logos are our property

## Privacy and Data Protection

- Your privacy is important to us
- We process data according to our Privacy Policy
- Scans are performed locally when possible
- We implement strong security measures
- You control your data retention settings

## Service Availability

### Uptime
- We strive for 99.9% uptime
- Scheduled maintenance will be announced
- We are not liable for service interruptions
- Offline functionality remains available

### Support
- Documentation and guides are provided
- Email support for paid users
- Community forums for all users
- Response times vary by plan level

## Subscription and Billing

### Free Tier
- Limited scans per month
- Basic vulnerability detection
- Standard reporting features
- Community support

### Paid Plans
- Unlimited scans
- Advanced AI detection
- Priority support
- Enterprise features

### Billing Terms
- Subscriptions are billed monthly or annually
- Prices are subject to change with notice
- Refunds are provided according to our refund policy
- Taxes may apply based on your location

## Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW:
- WE PROVIDE THE SERVICE "AS IS" WITHOUT WARRANTIES
- WE ARE NOT LIABLE FOR INDIRECT OR CONSEQUENTIAL DAMAGES
- OUR LIABILITY IS LIMITED TO THE AMOUNT YOU PAID
- SOME JURISDICTIONS DO NOT ALLOW THESE LIMITATIONS

## Indemnification

You agree to indemnify and hold us harmless from any claims, damages, or expenses arising from:
- Your use of the Service
- Your violation of these Terms
- Your violation of any third-party rights
- Your code or content

## Termination

### By You
- You may terminate your account at any time
- Cancellation takes effect at the end of your billing period
- You may export your data before termination

### By Us
- We may terminate accounts for Terms violations
- We may suspend Service for non-payment
- We will provide reasonable notice when possible

## Changes to Terms

- We may modify these Terms at any time
- Material changes will be communicated via email
- Continued use constitutes acceptance of new Terms
- You may terminate if you disagree with changes

## Governing Law

These Terms are governed by the laws of [Jurisdiction], without regard to conflict of law principles.

## Contact Information

For questions about these Terms:
- Email: legal@byteguardx.com
- Address: ByteGuardX Legal Team, [Address]

By using ByteGuardX, you acknowledge that you have read, understood, and agree to be bound by these Terms of Service.`
  },

  security: {
    title: "Security Policy",
    content: `# Security Policy

**Last updated: ${new Date().toLocaleDateString()}**

## Our Commitment to Security

ByteGuardX takes security seriously. As a security-focused platform, we implement comprehensive measures to protect your data and ensure the integrity of our services.

## Security Architecture

### Offline-First Design
- Core scanning operates locally on your machine
- Minimal data transmission to our servers
- Your source code never leaves your environment
- AI models run locally when possible

### Data Encryption
- **At Rest**: AES-256 encryption for all stored data
- **In Transit**: TLS 1.3 for all communications
- **Database**: Encrypted database storage
- **Backups**: Encrypted backup systems

### Authentication & Authorization
- Multi-factor authentication (MFA) support
- JWT tokens with secure expiration
- Role-based access control (RBAC)
- Session management and timeout controls

## Infrastructure Security

### Cloud Security
- SOC 2 Type II compliant infrastructure
- Regular penetration testing
- 24/7 security monitoring
- Automated threat detection

### Network Security
- Web Application Firewall (WAF)
- DDoS protection and mitigation
- Network segmentation
- Intrusion detection systems

### Application Security
- Secure coding practices
- Regular security code reviews
- Automated vulnerability scanning
- Dependency security monitoring

## Data Protection

### Data Minimization
- We collect only necessary data
- Automatic data purging policies
- User-controlled data retention
- Anonymization of analytics data

### Data Processing
- Local processing prioritized
- Secure multi-tenant architecture
- Data isolation between users
- Audit logging for all access

### Compliance
- GDPR compliance for EU users
- CCPA compliance for California residents
- SOC 2 Type II certification
- Regular compliance audits

## Vulnerability Management

### Our Security Process
1. **Detection**: Automated and manual security testing
2. **Assessment**: Risk evaluation and prioritization
3. **Remediation**: Rapid patching and fixes
4. **Verification**: Testing and validation
5. **Communication**: Transparent disclosure

### Security Updates
- Critical patches deployed within 24 hours
- Regular security updates and improvements
- Automated dependency updates
- Security advisory notifications

## Incident Response

### Response Team
- 24/7 security incident response
- Dedicated security operations center
- Escalation procedures and protocols
- Communication and notification systems

### Incident Handling
1. **Detection & Analysis**: Rapid identification and assessment
2. **Containment**: Immediate threat isolation
3. **Eradication**: Root cause elimination
4. **Recovery**: Service restoration
5. **Lessons Learned**: Process improvement

## Responsible Disclosure

### Security Research
We welcome security researchers and encourage responsible disclosure of security vulnerabilities.

### Reporting Process
1. **Email**: security@byteguardx.com
2. **PGP Key**: Available on our website
3. **Response Time**: Within 24 hours
4. **Resolution**: Coordinated disclosure timeline

### Bug Bounty Program
- Rewards for valid security findings
- Scope includes web application and APIs
- Responsible disclosure requirements
- Recognition for security researchers

## Contact Information

### Security Team
- **Email**: security@byteguardx.com
- **PGP Key**: [PGP Key Fingerprint]
- **Response Time**: 24 hours maximum

### Emergency Contact
- **Critical Issues**: security-emergency@byteguardx.com
- **Phone**: [Emergency Phone Number]
- **Available**: 24/7 for critical security issues

---

*This Security Policy is reviewed and updated regularly to reflect our current security practices and industry standards.*`
  },

  license: {
    title: "License",
    content: `# ByteGuardX License

**Version 1.0 - ${new Date().toLocaleDateString()}**

## MIT License

Copyright (c) ${new Date().getFullYear()} ByteGuardX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Additional Terms

### Commercial Use
- Commercial use is permitted under this license
- Enterprise features may require separate licensing
- Contact us for enterprise licensing options

### Attribution
- Attribution is appreciated but not required
- Include copyright notice in redistributions
- Link back to ByteGuardX project if possible

### Contributions
- Contributions are welcome and encouraged
- Contributors retain copyright to their contributions
- Contributions are licensed under the same terms

### Third-Party Components
This software includes third-party components with their own licenses:
- React (MIT License)
- Flask (BSD License)
- TensorFlow (Apache 2.0 License)
- Various npm and pip packages (see package files)

### AI Models and Data
- AI models are proprietary and not covered by this license
- Training data and algorithms remain ByteGuardX property
- Model outputs are not restricted by this license

### Trademark
- "ByteGuardX" is a trademark of ByteGuardX
- Logo and branding elements are not covered by this license
- Permission required for trademark use

## Support and Warranty

### No Warranty
This software is provided "as is" without warranty of any kind. Use at your own risk.

### Support
- Community support available through GitHub
- Paid support available for enterprise users
- Documentation and guides provided

### Liability
The authors and contributors are not liable for any damages arising from the use of this software.

## Contact

For licensing questions or commercial inquiries:
- Email: licensing@byteguardx.com
- Website: https://byteguardx.com
- GitHub: https://github.com/byteguardx/byteguardx

---

*This license applies to the ByteGuardX open-source components. Enterprise features and services may have additional terms.*`
  }
};
