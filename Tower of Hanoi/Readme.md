# Tower of Hanoi Recursive Visualizer

**Version 3.1 — "Deep Recursion (Fixed)"**  
**Author:** Shivani Bhat  

---

## Overview

The **Tower of Hanoi Recursive Visualizer** is a sophisticated, educational Bash script that provides a real-time animated visualization of the classic Tower of Hanoi puzzle. 

It demonstrates the elegance of **recursion**, live call stack behavior, and the divide-and-conquer strategy through an aesthetically pleasing terminal interface with colored discs and interactive controls.

---

## Features

- Real-time recursive animation with colored discs
- Live recursion call stack visualization panel
- Progress bar, move counter, and depth tracking
- Educational annotations explaining each step
- Interactive controls (speed, skip, quit)
- Fully compatible with `set -euo pipefail`
- Supports 1 to 8 discs
- Adaptive terminal rendering

---

## Requirements

- Bash 4.3 or higher (nameref support)
- Terminal with 256-color support
- `tput` or `stty` (for automatic terminal size detection)

---

## Installation

```bash
git clone https://github.com/yourusername/tower-of-hanoi-bash.git
cd tower-of-hanoi-bash
chmod +x tower_of_hanoi.sh
```

---

## Usage

```bash
./tower_of_hanoi.sh [OPTIONS]
```

### Available Options

| Option            | Description                              | Default    |
|-------------------|------------------------------------------|------------|
| `--discs N`       | Number of discs (1–8)                    | 5          |
| `--delay S`       | Delay between moves (seconds)            | 0.30       |
| `--fast`          | Fast mode (0.05s delay)                  | -          |
| `--instant`       | Solve instantly (benchmark mode)         | -          |
| `--no-stack`      | Hide the recursion call stack panel      | -          |
| `--help`          | Show usage information                   | -          |

### Examples

```bash
# Recommended for learning
./tower_of_hanoi.sh --discs 5 --delay 0.2

# Higher complexity
./tower_of_hanoi.sh --discs 7 --fast

# Maximum discs with instant solve
./tower_of_hanoi.sh --discs 8 --instant
```

---

## Controls (During Animation)

| Key       | Action                        |
|-----------|-------------------------------|
| `+` or `=`| Speed up animation            |
| `-`       | Slow down animation           |
| `s`       | Skip to end (instant solve)   |
| `q`       | Quit                          |

---

## Algorithm

The script implements the classic recursive solution:

**To move `n` discs from Source to Destination using Auxiliary:**

1. Recursively move `n-1` discs from Source → Auxiliary  
2. Move disc `n` directly from Source → Destination  
3. Recursively move `n-1` discs from Auxiliary → Destination  

**Base Case:** When `n = 1`, move the single disc directly.

**Mathematical Result:**
- Minimum moves = **2ⁿ − 1**
- Maximum recursion depth = **N**
- Time Complexity = **O(2ⁿ)**
- Space Complexity = **O(N)**

---

## Performance

| Discs | Moves | Max Depth | Approx. Time (0.2s delay) |
|-------|-------|-----------|---------------------------|
| 3     | 7     | 3         | ~2 seconds                |
| 5     | 31    | 5         | ~8 seconds                |
| 6     | 63    | 6         | ~15 seconds               |
| 7     | 127   | 7         | ~30 seconds               |
| 8     | 255   | 8         | ~55 seconds               |

---

## Technical Highlights

- Fixed critical bugs (subshell, `set -e`, unbound variables)
- Uses Bash namerefs for efficient stack operations
- Global `$POPPED` pattern for safe array mutation
- Modular rendering system
- Extensive inline documentation

---

## Educational Purpose

This project is designed to help students and developers deeply understand:
- Recursion and recursive unwinding
- Call stack mechanics
- Divide and Conquer strategy
- Time and space complexity

---

## License

This project is open-sourced under the **MIT License**. You are free to use, modify, and distribute it for educational and personal purposes.

---

**Created by Shivani Bhat**  

---
