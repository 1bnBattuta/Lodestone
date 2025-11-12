# Contributing to Lodestone

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## Table of Contents

- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)


## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
````bash
   git clone https://github.com/[your-username]/Lodestone.git
   cd Lodestone
````
3. **Add upstream remote**:
````bash
   git remote add upstream https://github.com/1bnBattuta/Lodestone.git
````
4. **Create a branch** for your changes:
````bash
   git checkout -b feature/your-feature-name
````

## How to Contribute

### Types of Contributions

We welcome many types of contributions:

- **Bug fixes**: Fix issues in existing code
- **New features**: Add new functionality
- **Documentation**: Improve or add documentation
- **Performance improvements**: Optimize existing code
- **Protocol support**: Add support for new protocols
- **Tests**: Add or improve test coverage
- **Examples**: Add usage examples

### Areas Needing Help

- [ ] Support for more protocols (SCTP, GRE, VXLAN, etc.)
- [ ] Windows/macOS support
- [ ] Better IPv6 flow tracking
- [ ] ML-based anomaly detection
- [ ] Performance benchmarking suite
- [ ] Docker containerization
- [ ] CI/CD pipeline

## Development Setup

### Prerequisites

- **Linux** (kernel 2.6.27+)
- **GCC** 7.0 or higher
- **libpcap-dev**
- **make**
- **git**

### Installing Dependencies

**Debian/Ubuntu:**
````bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev git
````

**Fedora/RHEL/CentOS:**
````bash
sudo dnf install gcc make libpcap-devel git
````

**Arch Linux:**
````bash
sudo pacman -S base-devel libpcap git
````

### Building the Project
````bash
# Standard build
make

# Debug build (with symbols and no optimization)
make debug

# Build with checksum validation
make checksums

# Clean build artifacts
make clean
````

### Running Tests
````bash
# Build and run basic tests
make test

# Test with different interfaces
sudo ./bin/Lodestone -i lo -c 10

# Test with filters
sudo ./bin/Lodestone -i eth0 -f "tcp port 80" -c 100
````

## Coding Standards

### C Style Guidelines

We follow a modified version of the Linux kernel coding style:

#### Indentation and Formatting
````c
// Use 4 spaces for indentation (NO TABS)
void example_function(int param) {
    if (condition) {
        // Code here
    }
}

// Braces on same line for functions
int another_function(void) {
    return 0;
}

// Space after keywords
if (condition)
while (condition)
for (i = 0; i < n; i++)

// No space between function name and parenthesis
function_call(arg1, arg2);

// Pointer asterisk attached to variable name
int *ptr;
char *string;
````

#### Naming Conventions
````c
// Functions: lowercase with underscores
int parse_packet(packet_t *pkt);
void display_packet_info(void);

// Structures: lowercase with _t suffix
typedef struct {
    int field;
} my_struct_t;

// Constants and macros: UPPERCASE
#define MAX_PACKET_SIZE 65535
#define SUCCESS 0

// Global variables: g_ prefix (avoid if possible)
static int g_packet_count = 0;

// Static functions: static keyword
static void internal_helper(void) {
    // ...
}
````

#### Comments
````c
// Single-line comments for brief explanations
int count = 0;  // Packet counter

/*
 * Multi-line comments for detailed explanations
 * Use this style for function documentation
 */

/**
 * Function documentation
 * 
 * @param pkt Pointer to packet structure
 * @return SUCCESS on success, ERROR on failure
 */
int process_packet(packet_t *pkt);
````

#### Error Handling
````c
// Always check return values
int ret = function_call();
if (ret != SUCCESS) {
    fprintf(stderr, "Error: function_call failed\n");
    return ERROR;
}

// Check pointers before use
if (!ptr) {
    return ERROR;
}

// Use goto for cleanup when necessary
int function(void) {
    char *buf = malloc(SIZE);
    if (!buf) {
        goto error;
    }
    
    // Do work
    
    free(buf);
    return SUCCESS;

error:
    free(buf);
    return ERROR;
}
````

#### Memory Management
````c
// Always free allocated memory
char *buf = malloc(1024);
if (!buf) {
    return ERROR;
}

// Use memory
// ...

free(buf);

// Set pointers to NULL after freeing
ptr = NULL;

// Use calloc for zero-initialized memory
struct_t *s = calloc(1, sizeof(struct_t));
````

### Header File Guidelines
````c
// Include guards
#ifndef MODULE_NAME_H
#define MODULE_NAME_H

// System includes first
#include <stdio.h>
#include <stdlib.h>

// Project includes second
#include "../utils/common.h"
#include "module.h"

// Declarations
// ...

#endif
````

## Testing Guidelines

### Writing Tests

When adding new features, include tests:

1. **Unit tests**: Test individual functions
2. **Integration tests**: Test module interactions
3. **Performance tests**: Benchmark critical paths

### Test Coverage

- All new functions should have tests
- Bug fixes should include regression tests
- Protocol parsers should have test packets

### Manual Testing Checklist

Before submitting a PR, test:

- [ ] Compiles without warnings (`make`)
- [ ] Compiles in debug mode (`make debug`)
- [ ] Basic capture works (`-i lo -c 10`)
- [ ] Filters work correctly
- [ ] Output files are valid
- [ ] No memory leaks (use `valgrind`)
- [ ] Works with different protocols
````bash
# Check for memory leaks
valgrind --leak-check=full --show-leak-kinds=all \
  sudo ./bin/Lodestone -i lo -c 100
````

## Submitting Changes

### Pull Request Process

1. **Update your fork**:
````bash
   git fetch upstream
   git checkout main
   git merge upstream/main
````

2. **Rebase your branch**:
````bash
   git checkout feature/your-feature
   git rebase main
````

3. **Run tests** and ensure everything works

4. **Commit your changes** with clear messages:
````bash
   git add .
   git commit -m "Add feature: brief description
   
   Detailed explanation of what changed and why.
   Fixes #123"
````

5. **Push to your fork**:
````bash
   git push origin feature/your-feature
````

6. **Create a Pull Request** on GitHub

### Commit Message Guidelines

Follow the conventional commits format:
````
<type>(<scope>): <subject>

<body>

<footer>
````

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes

**Examples:**
````
feat(parser): add support for VLAN tags

Implements IEEE 802.1Q VLAN tag parsing in the Ethernet
parser. Updates packet structure to include VLAN ID.

Closes #45

---

fix(capture): prevent packet drops on high traffic

Increases socket buffer size and adds flow control to
prevent kernel packet drops during high-volume captures.

Fixes #67

---

docs(readme): update installation instructions

Adds instructions for Arch Linux and clarifies
dependency requirements.
````

### Pull Request Description Template
````markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested on Linux kernel X.X
- [ ] No memory leaks (valgrind)
- [ ] Passes all existing tests
- [ ] Added new tests

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex sections
- [ ] Updated documentation
- [ ] No new warnings
- [ ] Added tests for new features

## Related Issues
Fixes #(issue number)

## Screenshots (if applicable)
````

## Reporting Bugs

### Before Submitting a Bug Report

- Check the documentation
- Search existing issues
- Try the latest version
- Collect relevant information

### Bug Report Template
````markdown
**Describe the bug**
Clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Kernel version: [e.g., 5.15.0]
- GCC version: [e.g., 11.3.0]
- libpcap version: [e.g., 1.10.1]
- Packet sniffer version/commit: [e.g., v1.0.0 or commit hash]

**Command used:**
```bash
sudo ./bin/packet-sniffer -i eth0 -f "tcp" -c 100
```

**Error output:**
````
Paste error messages here
````

**Additional context**
Any other relevant information.
````

## Suggesting Features

### Feature Request Template
````markdown
**Is your feature request related to a problem?**
Clear description of the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Use case**
How would this feature be used?

**Additional context**
Any other relevant information, mockups, or examples.
````

## Development Tips

### Useful Commands
````bash
# Find all TODO comments
grep -r "TODO" src/

# Check for memory leaks
valgrind --leak-check=full sudo ./bin/Lodestone -i lo -c 10

# Profile performance
perf record sudo ./bin/Lodestone -i eth0 -c 1000
perf report

# Static analysis
cppcheck --enable=all src/

# Check code style
clang-format -style=file -i src/**/*.c
````

### Debugging Tips
````bash
# Build with debug symbols
make debug

# Run with GDB
sudo gdb ./bin/Lodestone
(gdb) run -i eth0 -c 10
(gdb) bt  # Backtrace on crash

# Enable verbose output
sudo ./bin/Lodestone -i eth0 -v -d detailed
````

### Performance Testing
````bash
# Generate test traffic
sudo hping3 -S -p 80 --flood localhost

# Measure capture performance
sudo ./bin/Lodestone -i lo -m -q -c 100000 -s
````

## Project Structure

Understanding the codebase:
````
Lodestone/
├── src/
│   ├── main.c              # Entry point, CLI handling
│   ├── utils/              # Utility functions
│   │   ├── packet.c        # Packet structure
│   │   ├── buffer.c        # Ring buffer
│   │   ├── checksum.c      # Checksum calculations
│   │   └── hash.c          # Hash table
│   ├── capture/            # Packet capture
│   │   ├── capture.c       # Standard capture
│   │   ├── mmap_capture.c  # Zero-copy capture
│   │   └── filter.c        # BPF filtering
│   ├── parser/             # Protocol parsers
│   │   ├── parser.c        # Main parser
│   │   ├── ethernet.c      # Ethernet
│   │   ├── ip.c            # IPv4
│   │   ├── ipv6.c          # IPv6
│   │   ├── tcp.c           # TCP
│   │   ├── udp.c           # UDP
│   │   └── ...             # Other protocols
│   ├── output/             # Output modules
│   │   ├── display.c       # Terminal display
│   │   ├── pcap_writer.c   # PCAP output
│   │   ├── logger.c        # Various log formats
│   │   └── stats.c         # Statistics
│   └── analysis/           # Analysis features
│       ├── stream.c        # TCP stream reassembly
│       └── detector.c      # Anomaly detection
├── docs/                   # Documentation
├── tests/                  # Test files
└── examples/               # Usage examples
````

## Communication

- **Issues**: For bug reports and feature requests
- **Pull Requests**: For code contributions
- **Discussions**: For questions and ideas
- **Email**: hostilewire@proton.me for privat


