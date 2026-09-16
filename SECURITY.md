# Security Policy

## About This Project

NetSentinel is a smart network monitoring and security system designed to
detect suspicious network activities and provide response capabilities.

The project currently focuses on network monitoring, attack detection,
alert generation, and response/blocking mechanisms.

## Supported Security Monitoring

NetSentinel currently monitors and detects activities such as:

- Port Scanning
- Host Sweep
- Host Discovery Probes
- SYN Flood
- Failed Connection Attempts

## Responsible Use

NetSentinel is intended for:

- Authorized networks
- Security research
- Educational purposes
- Controlled laboratory environments
- Network monitoring where the user has permission

Do not use this project to monitor or interfere with networks without
proper authorization.

## Reporting a Security Issue

If you discover a security vulnerability in this project, please report it
privately to the repository maintainer instead of publicly disclosing the
issue.

When reporting an issue, include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Affected file or component
- Potential security impact
- Any suggested mitigation

## Security Considerations

Because this project can monitor network traffic and includes response
capabilities, it should be deployed carefully.

Before using the system on a production network:

1. Test the detection rules in a controlled environment.
2. Verify blocking and response actions.
3. Configure trusted IP and MAC addresses where required.
4. Review generated alerts before enabling automated response actions.
5. Run the application with only the privileges required for its operation.

## Project Status

NetSentinel is an actively developed project. Detection rules,
response mechanisms, and security features may change as the project evolves.
