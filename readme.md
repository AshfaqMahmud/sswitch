# SSwitch - Simple Switch Implementation

A lightweight implementation of a switch structure for C++, offering a clean and efficient alternative to traditional switch statements.

## Overview

SSwitch provides a modern approach to handling switch-case scenarios in C++, with the following features:

- Type-safe case matching
- No fall-through behavior
- Support for any comparable types
- Header-only implementation
- Clean and readable syntax

## Usage

```cpp
#include "sswitch.hpp"

// Example usage
auto result = SSwitch(value)
    .Case(1, []() { return "One"; })
    .Case(2, []() { return "Two"; })
    .Default([]() { return "Other"; });
```

## Installation

Simply include the header file in your project:

```cpp
#include "sswitch.hpp"
```

## Requirements

- C++11 or later
- Any standard-compliant C++ compiler

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.