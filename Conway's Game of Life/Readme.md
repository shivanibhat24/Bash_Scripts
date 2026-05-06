# Conway's Game of Life — Bash Edition

**Version 4.0 — "Emergent Complexity"**  
**Author:** Shivani Bhat

---

## Overview

A visually rich, high-performance implementation of **Conway's Game of Life** in pure Bash. It demonstrates how simple rules can create infinite complexity, oscillators, spaceships, and even universal computation.

This educational project features real-time animation, multiple famous patterns, interactive controls, and beautiful terminal rendering.

---

## Features

- Real-time simulation with smooth terminal animation
- 12+ built-in classic patterns (Glider, Gosper Gun, Acorn, Pulsar, etc.)
- Live statistics: Population, Births, Deaths, Peak, Stability
- Toroidal (wrapping) and finite boundary modes
- Color and monochrome rendering modes
- Interactive controls
- Optimized neighbour counting using lookup table
- Double-buffered simulation (correct simultaneous updates)

---

## Requirements

- Bash 4.0+
- 256-color terminal
- `tput` (recommended)

---

## Usage

```bash
./conways_game_of_life.sh [OPTIONS]
```

### Options

| Option            | Description                          | Default     |
|-------------------|--------------------------------------|-------------|
| `--pattern NAME`  | Starting pattern                     | random      |
| `--width N`       | Grid width                           | 64          |
| `--height N`      | Grid height                          | 26          |
| `--delay S`       | Seconds per generation               | 0.07        |
| `--density N`     | Random fill %                        | 28          |
| `--no-wrap`       | Disable toroidal wrapping            | -           |
| `--mono`          | Monochrome mode                      | -           |
| `--fast`          | Very fast mode                       | -           |

### Examples

```bash
./conways_game_of_life.sh --pattern gosper
./conways_game_of_life.sh --pattern acorn --fast
./conways_game_of_life.sh --pattern random --density 40 --width 80 --height 35
```

---

## Controls (During Simulation)

| Key       | Action                      |
|-----------|-----------------------------|
| `p`       | Pause / Resume              |
| `r`       | Reset current pattern       |
| `n`       | Next pattern                |
| `+ / =`   | Speed up                    |
| `-`       | Slow down                   |
| `w`       | Toggle wrapping             |
| `c`       | Toggle colors               |
| `q`       | Quit                        |

---

## Famous Patterns Included

- `gosper` — Glider Gun (infinite growth)
- `acorn` — Methuselah (5206 generations)
- `rpentomino` — Classic methuselah
- `pulsar`, `pentadecathlon` — Beautiful oscillators
- `glider`, `lwss`, `hwss` — Spaceships
- `random` — Probabilistic fill

---

## Educational Value

Perfect for understanding:
- Cellular automata
- Emergent behavior
- Optimization techniques in scripting
- Double buffering
- Space-time tradeoffs (precomputed neighbour table)

---


---

Would you like me to send you the **complete fixed script** in one single copyable block now?
