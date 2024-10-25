# DNS Client

A lightweight DNS client implementation that performs domain name to IP address translation by directly communicating with DNS servers using the DNS protocol.

## Features

- Custom DNS query message construction
- UDP-based communication with DNS servers
- Support for Google's public DNS (8.8.8.8)
- Timeout-based retry mechanism
- Detailed response parsing and display
- Resource Record (RR) processing

## Installation

```bash
git clone [your-repository-url]
cd dns-client
```

## Usage

```bash
python main.py <hostname>
```

Example:
```bash
python main.py example.com
```

The client will display detailed information about the DNS resolution process, including:
- Query ID
- Response flags
- Question section details
- Answer section with resolved IP addresses
- Additional resource records (if any)

## Technical Details

### DNS Message Format
The implementation follows the standard DNS protocol specification (RFC 1035) with:
- Header section with query identification and flags
- Question section containing the domain name query
- Answer section in responses with resolved addresses

### Retry Mechanism
- 5 second timeout for each query attempt
- Maximum 3 retry attempts
- Error reporting if no response is received

### Supported Record Types
- Currently focuses on A records (IPv4 addresses)
- Future support planned for NS, MX, and CNAME records

## Dependencies

- Python 3.6+
- No external libraries required (uses standard library only)

## Debugging

For debugging purposes, you can use Wireshark to capture and analyze the DNS packets:
1. Start Wireshark and filter for DNS packets (filter: `dns`)
2. Run your query
3. Examine the packet structure and fields

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Your chosen license]

## Acknowledgments

- Based on DNS protocol specifications from RFC 1035
- Uses Google's Public DNS service