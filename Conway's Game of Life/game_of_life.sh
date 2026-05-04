#!/usr/bin/env bash
# =============================================================================
#
#   ██████╗ ██████╗ ███╗   ██╗██╗    ██╗ █████╗ ██╗   ██╗███████╗
#  ██╔════╝██╔═══██╗████╗  ██║██║    ██║██╔══██╗╚██╗ ██╔╝██╔════╝
#  ██║     ██║   ██║██╔██╗ ██║██║ █╗ ██║███████║ ╚████╔╝ ███████╗
#  ██║     ██║   ██║██║╚██╗██║██║███╗██║██╔══██║  ╚██╔╝  ╚════██║
#  ╚██████╗╚██████╔╝██║ ╚████║╚███╔███╔╝██║  ██║   ██║   ███████║
#   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
#
#   ██████╗  █████╗ ███╗   ███╗███████╗     ██████╗ ███████╗
#  ██╔════╝ ██╔══██╗████╗ ████║██╔════╝    ██╔═══██╗██╔════╝
#  ██║  ███╗███████║██╔████╔██║█████╗      ██║   ██║█████╗
#  ██║   ██║██╔══██║██║╚██╔╝██║██╔══╝      ██║   ██║██╔══╝
#  ╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗    ╚██████╔╝██║
#   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝     ╚═════╝ ╚═╝
#
#  ██╗     ██╗███████╗███████╗
#  ██║     ██║██╔════╝██╔════╝
#  ██║     ██║█████╗  █████╗
#  ██║     ██║██╔══╝  ██╔══╝
#  ███████╗██║██║     ███████╗
#  ╚══════╝╚═╝╚═╝     ╚══════╝
#
# =============================================================================
# AUTHOR   : Shivani Bhat
# VERSION  : 4.0 — "Emergent Complexity"
# REQUIRES : bash >= 4.0, a 256-colour VT100-compatible terminal
#
# PURPOSE  : Conway's Game of Life — a zero-player cellular automaton
#            demonstrating how infinite complexity emerges from four rules.
#
# IN MEMORIAM: John Horton Conway  (1937 - 2020)
# -----------------------------------------------
#   Mathematician. Princeton Professor. Inventor of the Game of Life.
#   He described the Game as his most famous creation — and his most
#   embarrassing, because it was so simple. Yet it inspired entire
#   fields: cellular automata, artificial life, computability theory.
#   Conway's Game of Life is Turing-complete. Any computation that
#   can be described can be performed inside this grid.
#   From four sentences, a universe.
#
# THE FOUR LAWS (applied simultaneously to every cell, every generation)
# -----------------------------------------------------------------------
#
#   [1] UNDERPOPULATION : A live cell with fewer than 2 live neighbours DIES.
#   [2] SURVIVAL        : A live cell with 2 or 3 live neighbours LIVES ON.
#   [3] OVERPOPULATION  : A live cell with more than 3 live neighbours DIES.
#   [4] REPRODUCTION    : A dead cell with exactly 3 live neighbours BECOMES ALIVE.
#
# WHAT EMERGES FROM THESE FOUR RULES
# ------------------------------------
#   Gliders         — small patterns that travel diagonally across the grid.
#   Oscillators     — patterns that cycle through states (period 2, 3, 15...).
#   Still Lifes     — stable patterns that never change (block, beehive, loaf).
#   Spaceships      — larger patterns that translate across the grid.
#   Glider Guns     — stationary patterns that emit an endless stream of gliders.
#   Methuselahs     — small seeds that take thousands of generations to stabilise.
#   Turing Machines — the game is computationally UNIVERSAL.
#
# ALGORITHM: ITERATIVE SIMULATION
# --------------------------------
#   Unlike Tower of Hanoi, Life has NO recursion.
#   It is driven entirely by nested iteration:
#
#     for each generation:
#       for each row y in [0, H):          -- OUTER ITERATION
#         for each column x in [0, W):     -- INNER ITERATION
#           count 8 neighbours             -- NEIGHBOUR ITERATION
#           apply the four rules
#           write result to NEW_GRID
#       swap NEW_GRID -> GRID
#
#   Time per generation: O(W * H)
#   The simultaneous-update constraint (all cells evaluated against the
#   OLD grid before any are updated) is enforced by the double-buffer swap.
#
# OPTIMISATION: NEIGHBOUR COUNTING VIA PRECOMPUTED LOOKUP TABLE
# --------------------------------------------------------------
#   Naively calling a function for each of the 8 neighbours is slow in bash.
#   Instead, we precompute a flat "neighbour index list" for every cell at
#   startup, stored in NBRS[]. Each cell i has exactly 8 entries in NBRS:
#     NBRS[i*8 + 0..7] = flat indices of its 8 neighbours (with wrap).
#   During next_generation(), we look up these pre-baked indices directly —
#   no per-call arithmetic, no subshell, no function call overhead.
#   This reduces neighbour evaluation to 8 direct array reads per cell.
#
# CONTROLS (during simulation)
#   [q]         Quit
#   [p]         Pause / Resume
#   [r]         Reset grid (reseed with current pattern)
#   [n]         Next pattern (cycle through all built-in patterns)
#   [+] / [=]   Speed up (reduce delay)
#   [-]         Slow down (increase delay)
#   [w]         Toggle wrap (toroidal vs finite)
#   [c]         Toggle colour mode
#
# USAGE
#   ./conways_game_of_life.sh [OPTIONS]
# =============================================================================

# =============================================================================
#  STRICT MODE
# =============================================================================
set -euo pipefail

# =============================================================================
#  COLOUR PALETTE
# =============================================================================
RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
ITALIC=$'\033[3m'
REVERSE=$'\033[7m'

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'
MAGENTA=$'\033[35m'
CYAN=$'\033[36m'
WHITE=$'\033[37m'

BR_RED=$'\033[91m'
BR_GREEN=$'\033[92m'
BR_YELLOW=$'\033[93m'
BR_BLUE=$'\033[94m'
BR_MAGENTA=$'\033[95m'
BR_CYAN=$'\033[96m'
BR_WHITE=$'\033[97m'

BG_BLACK=$'\033[40m'
BG_RED=$'\033[41m'
BG_GREEN=$'\033[42m'
BG_BLUE=$'\033[44m'

# =============================================================================
#  CONFIGURATION DEFAULTS
# =============================================================================
GRID_W=64             # Grid width  (cells)
GRID_H=26             # Grid height (cells)
MAX_GENS=0            # 0 = run forever; N = stop after N generations
DELAY=0.07            # Seconds between generations
PATTERN="random"      # Starting pattern name
WRAP=1                # 1 = toroidal edges; 0 = hard boundary (dead outside)
DENSITY=28            # Random fill density percent (1-99)
COLOUR_MODE=1         # 1 = coloured cells; 0 = monochrome

# =============================================================================
#  CELL RENDERING GLYPHS
#  We use full-width Unicode block elements for a smooth, solid look.
# =============================================================================
CELL_ALIVE="##"       # Live cell glyph   (2 chars wide)
CELL_DEAD="  "        # Dead cell glyph   (2 chars wide)
CELL_BORN="++"        # Born this gen
CELL_DIED="--"        # Died this gen

# =============================================================================
#  GLOBAL STATE
# =============================================================================

# The grid is stored as a flat 1-D bash array of integers.
# Index mapping: cell (x, y) lives at GRID[ y * GRID_W + x ]
# 0 = dead, 1 = alive
declare -a GRID
declare -a PREV_GRID      # Snapshot of the previous generation (for diffs)
declare -a NEW_GRID       # Scratch buffer for next_generation()

# NBRS[i*8 .. i*8+7] = flat indices of cell i's 8 Moore neighbours
# This lookup table is built ONCE by build_neighbour_table() and reused
# every generation, saving thousands of modulo operations per tick.
declare -a NBRS

GENERATION=0
POPULATION=0
PREV_POPULATION=0
PEAK_POPULATION=0
BIRTHS=0
DEATHS=0
STABLE_GENS=0         # Consecutive unchanged generations
TOTAL_CELLS=0         # GRID_W * GRID_H

PAUSED=0
RUNNING=1

# Ordered list of patterns for cycling with [n]
PATTERN_LIST=( random glider gosper pulsar pentadecathlon blinker
               rpentomino diehard acorn lwss hwss glider_fleet )
PATTERN_IDX=0         # Current index into PATTERN_LIST

# Terminal dimensions
TERM_COLS=80
TERM_ROWS=24

# =============================================================================
#  TERMINAL UTILITIES
# =============================================================================
cursor_to()   { printf '\033[%d;%dH' "$1" "$2"; }
clear_screen(){ printf '\033[2J\033[H'; }
hide_cursor() { printf '\033[?25l'; }
show_cursor() { printf '\033[?25h'; }

query_term_size() {
    if command -v tput &>/dev/null; then
        TERM_COLS=$(tput cols  2>/dev/null || echo 80)
        TERM_ROWS=$(tput lines 2>/dev/null || echo 24)
    else
        TERM_COLS=80; TERM_ROWS=24
    fi
    # Clamp grid to terminal
    local max_grid_w=$(( (TERM_COLS - 6) / 2 ))
    local max_grid_h=$(( TERM_ROWS - 6 ))
    (( GRID_W > max_grid_w )) && GRID_W=$max_grid_w
    (( GRID_H > max_grid_h )) && GRID_H=$max_grid_h
    TOTAL_CELLS=$(( GRID_W * GRID_H ))
}

# =============================================================================
#  NEIGHBOUR LOOKUP TABLE
#
#  ITERATION: This function iterates over every cell exactly once at startup.
#  For each cell i at position (x, y), it computes the flat indices of the
#  8 Moore-neighbourhood cells (with toroidal or clamped wrapping) and stores
#  them contiguously in NBRS[i*8 .. i*8+7].
#
#  This is a classic space-time trade-off:
#    - Extra memory: 8 * W * H integers (one time).
#    - Saves: 8 * W * H modulo operations PER GENERATION.
#  For a 64x26 grid running at 10 gen/sec, that's ~130,000 saved arithmetic
#  operations per second — critical for bash's slow arithmetic.
# =============================================================================
build_neighbour_table() {
    local i x y nx ny idx

    # OUTER ITERATION: every cell in the grid  ---------------------------------
    for (( y = 0; y < GRID_H; y++ )); do
        for (( x = 0; x < GRID_W; x++ )); do

            i=$(( y * GRID_W + x ))
            local slot=$(( i * 8 ))
            local k=0

            # INNER ITERATION: 8 neighbours in Moore neighbourhood ------------
            # dx in {-1, 0, 1}, dy in {-1, 0, 1}, skip (0,0) = self
            for (( dy = -1; dy <= 1; dy++ )); do
                for (( dx = -1; dx <= 1; dx++ )); do
                    (( dx == 0 && dy == 0 )) && continue

                    nx=$(( x + dx ))
                    ny=$(( y + dy ))

                    if (( WRAP )); then
                        # Toroidal wrap: treat the grid as a torus.
                        # Bash modulo can return negative for negative inputs,
                        # so we add the dimension before taking modulo.
                        nx=$(( (nx + GRID_W) % GRID_W ))
                        ny=$(( (ny + GRID_H) % GRID_H ))
                    else
                        # Hard boundary: clamp to nearest valid cell.
                        # Out-of-bound neighbours become the edge cell itself,
                        # but we zero-check during counting so they stay dead.
                        (( nx < 0 ))       && nx=0
                        (( nx >= GRID_W )) && nx=$(( GRID_W - 1 ))
                        (( ny < 0 ))       && ny=0
                        (( ny >= GRID_H )) && ny=$(( GRID_H - 1 ))
                    fi

                    NBRS[$(( slot + k ))]=$(( ny * GRID_W + nx ))
                    (( k++ ))
                done
            done
            # -----------------------------------------------------------------

        done
    done
}

# =============================================================================
#  GRID HELPERS
# =============================================================================

# set_cell <x> <y> <value>
set_cell() { GRID[$(( $2 * GRID_W + $1 ))]="$3"; }

# zero-fill the entire grid
clear_grid() {
    local i
    for (( i = 0; i < TOTAL_CELLS; i++ )); do
        GRID[$i]=0
    done
}

# =============================================================================
#  NEXT GENERATION — THE CORE ENGINE
#
#  This function advances the simulation by one tick.
#  It applies Conway's four rules simultaneously to every cell.
#
#  KEY DESIGN DECISION: DOUBLE BUFFER
#  -----------------------------------
#  We never modify GRID in-place. Instead:
#    1. Read ALL cells from GRID (current generation).
#    2. Write results into NEW_GRID (scratch buffer).
#    3. After ALL cells are evaluated, copy NEW_GRID -> GRID.
#  Without the double buffer, updating cell (x, y) would corrupt the
#  neighbour counts of (x+1, y), (x, y+1) etc. — breaking the rules.
#
#  OPTIMISATION: PRECOMPUTED NEIGHBOUR TABLE
#  ------------------------------------------
#  Instead of calling a function per neighbour (8 subshell forks per cell),
#  we look up precomputed flat indices from NBRS[].
#  8 direct array reads replace 8 function calls — roughly 10x faster.
#
#  ITERATION STRUCTURE
#  --------------------
#  Level 1 (line 1): for each cell index i in [0, W*H)   -- FLAT ITERATION
#  Level 2 (implicit): unrolled 8-neighbour sum           -- UNROLLED LOOP
#  Per generation cost: O(W * H)
# =============================================================================
next_generation() {
    PREV_GRID=("${GRID[@]}")
    PREV_POPULATION=$POPULATION
    POPULATION=0
    BIRTHS=0
    DEATHS=0
    local changed=0
    local i base n0 n1 n2 n3 n4 n5 n6 n7 nbrs cur nxt

    # =========================================================================
    # MAIN ITERATION: evaluate every cell in the grid in one flat pass.
    #
    # We iterate over flat index i rather than (x,y) pairs — identical
    # semantics, but one loop instead of two means fewer loop-overhead
    # instructions in bash's interpreter. Each cell has a unique index:
    #     i = y * GRID_W + x
    # =========================================================================
    for (( i = 0; i < TOTAL_CELLS; i++ )); do

        cur="${GRID[$i]:-0}"       # current state: 0 = dead, 1 = alive
        base=$(( i * 8 ))          # start of this cell's NBRS slot

        # ── Count live neighbours using precomputed index table ──────────────
        # We unroll the 8-neighbour sum manually (no inner for-loop).
        # Each line reads one neighbour's flat index from NBRS[], then reads
        # that cell's value from GRID[]. Direct array lookups — no arithmetic.
        #
        # This is the innermost "hot path" of the simulation.
        # It runs TOTAL_CELLS times per generation.
        n0="${GRID[${NBRS[$base]}]:-0}"
        n1="${GRID[${NBRS[$(( base+1 ))]}]:-0}"
        n2="${GRID[${NBRS[$(( base+2 ))]}]:-0}"
        n3="${GRID[${NBRS[$(( base+3 ))]}]:-0}"
        n4="${GRID[${NBRS[$(( base+4 ))]}]:-0}"
        n5="${GRID[${NBRS[$(( base+5 ))]}]:-0}"
        n6="${GRID[${NBRS[$(( base+6 ))]}]:-0}"
        n7="${GRID[${NBRS[$(( base+7 ))]}]:-0}"
        nbrs=$(( n0 + n1 + n2 + n3 + n4 + n5 + n6 + n7 ))
        # ─────────────────────────────────────────────────────────────────────

        # ── Apply Conway's four rules ─────────────────────────────────────────
        nxt=0
        if (( cur == 1 )); then
            # Cell is ALIVE: survives if it has 2 or 3 neighbours.
            # Otherwise it dies — from underpopulation (< 2) or
            # overpopulation (> 3).  Rules [1], [2], [3].
            if (( nbrs == 2 || nbrs == 3 )); then
                nxt=1                          # [2] SURVIVAL
            else
                (( DEATHS++ ))                 # [1] or [3] DEATH
                (( changed++ ))
            fi
        else
            # Cell is DEAD: is born if it has exactly 3 live neighbours.
            # Rule [4] — REPRODUCTION.
            if (( nbrs == 3 )); then
                nxt=1                          # [4] BIRTH
                (( BIRTHS++ ))
                (( changed++ ))
            fi
        fi
        # ─────────────────────────────────────────────────────────────────────

        NEW_GRID[$i]=$nxt
        (( POPULATION += nxt ))

    done
    # ── End main flat iteration ───────────────────────────────────────────────

    # Swap the scratch buffer in as the new current grid
    GRID=("${NEW_GRID[@]}")
    (( GENERATION++ ))

    # Track peak population
    (( POPULATION > PEAK_POPULATION )) && PEAK_POPULATION=$POPULATION

    # Stability: unchanged generations counter
    if (( changed == 0 )); then
        (( STABLE_GENS++ ))
    else
        STABLE_GENS=0
    fi
}

# =============================================================================
#  RENDER
#
#  Draws the entire grid to the terminal without clearing the screen.
#  We move the cursor to the top-left and overwrite in place — this
#  eliminates the flicker that full clear-and-redraw would cause.
#
#  ITERATION: Two nested loops — outer over rows, inner over columns.
#  At each cell we choose a glyph and colour based on:
#    - Current state (alive/dead)
#    - Previous state (born/died this tick)
#    - Neighbour count (colours vary by how crowded the cell is)
# =============================================================================
render() {
    cursor_to 1 1

    # ── Header bar ────────────────────────────────────────────────────────────
    printf "${BG_BLACK}${BR_WHITE}${BOLD}"
    printf " %-*s " $(( TERM_COLS - 2 )) \
        "CONWAY'S GAME OF LIFE  |  Gen: $(printf '%5d' $GENERATION)  |  Pop: $(printf '%5d' $POPULATION)  |  Births: $(printf '%4d' $BIRTHS)  Deaths: $(printf '%4d' $DEATHS)  |  Peak: $PEAK_POPULATION  |  Author: Shivani Bhat"
    printf "${RESET}\n"

    # ── Sub-header: pattern + controls ───────────────────────────────────────
    printf "${DIM}"
    printf " Pattern: ${BR_WHITE}%-14s${RESET}${DIM}" "$PATTERN"
    printf " Wrap: ${BR_WHITE}%-4s${RESET}${DIM}"  "$(( WRAP  ? 'ON' : 'OFF' ))"
    printf " Stable: ${BR_WHITE}%3d${RESET}${DIM}"  "$STABLE_GENS"
    printf " [p]ause [r]eset [n]ext-pattern [+/-] speed [w]rap [q]uit${RESET}\n"

    # ── Top border ────────────────────────────────────────────────────────────
    printf " ${DIM}+"
    for (( x = 0; x < GRID_W; x++ )); do printf "--"; done
    printf "+${RESET}\n"

    # =========================================================================
    # RENDER ITERATION: row by row, column by column
    #
    # This is O(W * H) per frame.  We build each row as a single printf
    # call (by accumulating a string) rather than one printf per cell —
    # this reduces the number of write() syscalls from W*H to H per frame,
    # which makes a noticeable difference in bash.
    # =========================================================================
    local i cur prv row_str cell_str col

    for (( y = 0; y < GRID_H; y++ )); do      # OUTER ITERATION: rows

        row_str=" ${DIM}|${RESET}"             # Start each row with side border

        for (( x = 0; x < GRID_W; x++ )); do  # INNER ITERATION: columns

            i=$(( y * GRID_W + x ))
            cur="${GRID[$i]:-0}"
            prv="${PREV_GRID[$i]:-0}"

            if (( COLOUR_MODE )); then
                if (( cur == 1 && prv == 0 )); then
                    # BORN this generation — bright white flash
                    cell_str="${BR_WHITE}${BOLD}${CELL_BORN}${RESET}"

                elif (( cur == 1 )); then
                    # ALIVE and was alive last gen — colour by neighbour pressure
                    # We use precomputed NBRS to count neighbours inline
                    local base=$(( i * 8 ))
                    local lnbrs=$(( \
                        ${GRID[${NBRS[$base]}]:-0} + \
                        ${GRID[${NBRS[$(( base+1 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+2 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+3 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+4 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+5 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+6 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( base+7 ))]}]:-0} \
                    ))
                    # Colour gradient: 2=cyan, 3=blue(crowded), other=green
                    case $lnbrs in
                        2)  col="${BR_CYAN}" ;;
                        3)  col="${BR_BLUE}${BOLD}" ;;
                        *)  col="${GREEN}" ;;
                    esac
                    cell_str="${col}${CELL_ALIVE}${RESET}"

                elif (( cur == 0 && prv == 1 )); then
                    # DIED this generation — dim red ghost
                    cell_str="${DIM}${RED}${CELL_DIED}${RESET}"

                else
                    # DEAD and was dead — empty space
                    cell_str="${CELL_DEAD}"
                fi
            else
                # Monochrome mode
                if   (( cur == 1 && prv == 0 )); then
                    cell_str="${BOLD}${CELL_BORN}${RESET}"
                elif (( cur == 1 )); then
                    cell_str="${CELL_ALIVE}"
                elif (( cur == 0 && prv == 1 )); then
                    cell_str="${DIM}${CELL_DIED}${RESET}"
                else
                    cell_str="${CELL_DEAD}"
                fi
            fi

            row_str+="$cell_str"

        done  # end column loop

        row_str+="${DIM}|${RESET}"
        printf "%s\n" "$row_str"

    done  # end row loop
    # =========================================================================

    # ── Bottom border ─────────────────────────────────────────────────────────
    printf " ${DIM}+"
    for (( x = 0; x < GRID_W; x++ )); do printf "--"; done
    printf "+${RESET}\n"
}

# =============================================================================
#  PATTERN LIBRARY
#
#  Each pattern function stamps a set of live cells onto the grid.
#  Coordinates are relative to the given origin (ox, oy).
#
#  stamp() applies a list of (dx, dy) offsets to the origin.
#  ITERATION: each stamp() call iterates over its coordinate list.
# =============================================================================

# stamp <ox> <oy> <dx1> <dy1> <dx2> <dy2> ...
stamp() {
    local ox="$1" oy="$2"
    shift 2
    while (( $# >= 2 )); do
        local x=$(( ox + $1 ))
        local y=$(( oy + $2 ))
        if (( x >= 0 && x < GRID_W && y >= 0 && y < GRID_H )); then
            GRID[$(( y * GRID_W + x ))]=1
        fi
        shift 2
    done
}

# ── Pattern: Blinker (period-2 oscillator, the simplest) ─────────────────────
pattern_blinker() {
    local cx=$(( GRID_W/2 - 1 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy  0 0  1 0  2 0
}

# ── Pattern: Block (still life — never changes) ───────────────────────────────
pattern_block() {
    local cx=$(( GRID_W/2 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy  0 0  1 0  0 1  1 1
}

# ── Pattern: Glider (period-4 spaceship, travels diagonally) ──────────────────
# The simplest pattern that moves.  Discovered by Richard Guy in 1970.
pattern_glider() {
    local cx=$(( GRID_W/4 )) cy=$(( GRID_H/4 ))
    stamp $cx $cy \
              1 0 \
        2 1 \
        0 2  1 2  2 2
}

# ── Pattern: Lightweight Spaceship (LWSS) ────────────────────────────────────
# Travels horizontally, period 4.
pattern_lwss() {
    local cx=$(( GRID_W/2 - 2 )) cy=$(( GRID_H/2 - 1 ))
    stamp $cx $cy \
        1 0  4 0 \
        0 1 \
        0 2        4 2 \
        0 3  1 3  2 3  3 3
}

# ── Pattern: Heavyweight Spaceship (HWSS) ────────────────────────────────────
# Larger horizontal spaceship.
pattern_hwss() {
    local cx=$(( GRID_W/2 - 3 )) cy=$(( GRID_H/2 - 2 ))
    stamp $cx $cy \
        2 0  3 0 \
        0 1  1 1  4 1  5 1 \
        0 2  1 2  2 2  3 2  4 2  5 2 \
        1 3  2 3  3 3  4 3
}

# ── Pattern: R-Pentomino ──────────────────────────────────────────────────────
# Only 5 cells, yet it takes 1103 generations to fully stabilise.
# Discovered by Conway himself. It spawns gliders, blocks, and blinkers.
pattern_rpentomino() {
    local cx=$(( GRID_W/2 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        1 0  2 0 \
        0 1  1 1 \
        1 2
}

# ── Pattern: Diehard ──────────────────────────────────────────────────────────
# Completely disappears after exactly 130 generations — not one more, not less.
pattern_diehard() {
    local cx=$(( GRID_W/2 - 4 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        6 0 \
        0 1  1 1 \
        1 2  5 2  6 2  7 2
}

# ── Pattern: Acorn ────────────────────────────────────────────────────────────
# Only 7 cells. Takes 5206 generations to stabilise.
# Produces 633 cells at its peak. A true Methuselah.
pattern_acorn() {
    local cx=$(( GRID_W/2 - 3 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        1 0 \
        3 1 \
        0 2  1 2  4 2  5 2  6 2
}

# ── Pattern: Pulsar (period-3 oscillator) ────────────────────────────────────
# A gorgeous, highly symmetric pattern. One of the most famous oscillators.
pattern_pulsar() {
    local cx=$(( GRID_W/2 - 6 )) cy=$(( GRID_H/2 - 6 ))
    stamp $cx $cy \
        2 0  3 0  4 0  8 0  9 0  10 0 \
        0 2  5 2  7 2  12 2 \
        0 3  5 3  7 3  12 3 \
        0 4  5 4  7 4  12 4 \
        2 5  3 5  4 5  8 5  9 5  10 5 \
        2 7  3 7  4 7  8 7  9 7  10 7 \
        0 8  5 8  7 8  12 8 \
        0 9  5 9  7 9  12 9 \
        0 10 5 10 7 10 12 10 \
        2 12 3 12 4 12 8 12 9 12 10 12
}

# ── Pattern: Pentadecathlon (period-15 oscillator) ───────────────────────────
# A chain of 10 cells that oscillates with period 15 — unusual and elegant.
pattern_pentadecathlon() {
    local cx=$(( GRID_W/2 - 1 )) cy=$(( GRID_H/2 - 5 ))
    stamp $cx $cy \
        1 0 \
        1 1 \
        0 2  2 2 \
        1 3 \
        1 4 \
        1 5 \
        1 6 \
        0 7  2 7 \
        1 8 \
        1 9
}

# ── Pattern: Gosper Glider Gun ────────────────────────────────────────────────
# The FIRST infinite-growth pattern ever discovered (Bill Gosper, 1970).
# It refutes Conway's conjecture that all patterns eventually stabilise.
# Emits one glider every 30 generations — forever.
pattern_gosper() {
    local ox=2 oy=4
    stamp $ox $oy \
        24 0 \
        22 1  24 1 \
        12 2  13 2  20 2  21 2  34 2  35 2 \
        11 3  15 3  20 3  21 3  34 3  35 3 \
         0 4   1 4  10 4  16 4  20 4  21 4 \
         0 5   1 5  10 5  14 5  16 5  17 5  22 5  24 5 \
        10 6  16 6  24 6 \
        11 7  15 7 \
        12 8  13 8
}

# ── Pattern: Glider Fleet ─────────────────────────────────────────────────────
# Multiple gliders travelling in formation — visually striking.
pattern_glider_fleet() {
    local offsets=( 0 0  10 4  20 8  30 12  5 16  15 20 )
    local i
    for (( i = 0; i < ${#offsets[@]}; i += 2 )); do
        local ox=$(( GRID_W/5 + offsets[i] ))
        local oy=$(( 2 + offsets[i+1] ))
        stamp $ox $oy \
                  1 0 \
            2 1 \
            0 2  1 2  2 2
    done
}

# ── Pattern: Random fill ──────────────────────────────────────────────────────
# ITERATION: nested loop fills every cell with probability DENSITY/100.
pattern_random() {
    # Re-seed RANDOM from /dev/urandom for true randomness each call
    RANDOM=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ') || RANDOM=$$

    for (( y = 0; y < GRID_H; y++ )); do
        for (( x = 0; x < GRID_W; x++ )); do
            # Live if random 0-99 falls below density threshold
            GRID[$(( y * GRID_W + x ))]=$(( RANDOM % 100 < DENSITY ? 1 : 0 ))
        done
    done
}

# =============================================================================
#  INIT GRID
#  Clears the grid and applies the chosen pattern.
#  Rebuilds the neighbour table if grid dimensions changed.
# =============================================================================
init_grid() {
    GENERATION=0
    POPULATION=0
    BIRTHS=0
    DEATHS=0
    STABLE_GENS=0
    PREV_POPULATION=0

    # Zero fill
    GRID=()
    PREV_GRID=()
    NEW_GRID=()
    local i
    for (( i = 0; i < TOTAL_CELLS; i++ )); do
        GRID[$i]=0
        PREV_GRID[$i]=0
        NEW_GRID[$i]=0
    done

    # Stamp pattern
    case "$PATTERN" in
        glider)          pattern_glider ;;
        gosper)          pattern_gosper ;;
        pulsar)          pattern_pulsar ;;
        pentadecathlon)  pattern_pentadecathlon ;;
        blinker)         pattern_blinker ;;
        block)           pattern_block ;;
        rpentomino)      pattern_rpentomino ;;
        diehard)         pattern_diehard ;;
        acorn)           pattern_acorn ;;
        lwss)            pattern_lwss ;;
        hwss)            pattern_hwss ;;
        fleet|glider_fleet) pattern_glider_fleet ;;
        random|*)        pattern_random ;;
    esac

    # Count initial population
    POPULATION=0
    for (( i = 0; i < TOTAL_CELLS; i++ )); do
        (( POPULATION += ${GRID[$i]:-0} ))
    done
    PEAK_POPULATION=$POPULATION
}

# =============================================================================
#  CYCLE PATTERN
#  Move to the next pattern in the PATTERN_LIST and reinitialise.
# =============================================================================
cycle_pattern() {
    PATTERN_IDX=$(( (PATTERN_IDX + 1) % ${#PATTERN_LIST[@]} ))
    PATTERN="${PATTERN_LIST[$PATTERN_IDX]}"
    init_grid
    NBRS=()
    build_neighbour_table
}

# =============================================================================
#  ARGUMENT PARSING
# =============================================================================
usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

  --pattern  NAME   Starting pattern:
                      random glider gosper pulsar pentadecathlon
                      blinker rpentomino diehard acorn lwss hwss fleet
  --width    N      Grid width  in cells  (default: 64)
  --height   N      Grid height in cells  (default: 26)
  --delay    S      Seconds between ticks (default: 0.07)
  --gens     N      Stop after N generations, 0=forever (default: 0)
  --density  N      Random fill density % (default: 28)
  --no-wrap         Disable toroidal edge wrapping
  --mono            Monochrome (no cell colours)
  --fast            Set delay to 0.02s
  --help            Show this message

Controls during simulation:
  [p] pause/resume    [r] reset    [n] next pattern
  [+] faster          [-] slower   [w] toggle wrap
  [c] toggle colour   [q] quit

Examples:
  $0 --pattern gosper
  $0 --pattern acorn --fast
  $0 --pattern random --density 40 --width 80 --height 30
  $0 --pattern pulsar --delay 0.2

USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pattern)  PATTERN="$2";  shift 2 ;;
        --width)    GRID_W="$2";   shift 2 ;;
        --height)   GRID_H="$2";   shift 2 ;;
        --delay)    DELAY="$2";    shift 2 ;;
        --gens)     MAX_GENS="$2"; shift 2 ;;
        --density)  DENSITY="$2";  shift 2 ;;
        --no-wrap)  WRAP=0;        shift 1 ;;
        --mono)     COLOUR_MODE=0; shift 1 ;;
        --fast)     DELAY=0.02;    shift 1 ;;
        --help|-h)  usage ;;
        *) printf "Unknown option: %s\n" "$1"; usage ;;
    esac
done

# =============================================================================
#  VALIDATE INPUTS
# =============================================================================
if ! [[ "$GRID_W" =~ ^[0-9]+$ ]] || (( GRID_W < 10 || GRID_W > 200 )); then
    printf "Error: --width must be 10-200 (got %s)\n" "$GRID_W"; exit 1
fi
if ! [[ "$GRID_H" =~ ^[0-9]+$ ]] || (( GRID_H < 5 || GRID_H > 100 )); then
    printf "Error: --height must be 5-100 (got %s)\n" "$GRID_H"; exit 1
fi
if ! [[ "$DENSITY" =~ ^[0-9]+$ ]] || (( DENSITY < 1 || DENSITY > 99 )); then
    printf "Error: --density must be 1-99 (got %s)\n" "$DENSITY"; exit 1
fi

# =============================================================================
#  INTRO SCREEN
# =============================================================================
intro_screen() {
    clear_screen
    printf "${BR_GREEN}${BOLD}"
    cat <<'BANNER'

  +=========================================================================+
  |                                                                         |
  |    C O N W A Y ' S   G A M E   O F   L I F E                          |
  |    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                        |
  |                                                                         |
  |   A zero-player cellular automaton. Infinite complexity. Four rules.   |
  |                                                                         |
  |   THE FOUR LAWS (applied SIMULTANEOUSLY every generation):              |
  |                                                                         |
  |    [1] UNDERPOPULATION : < 2 live neighbours  ->  cell dies            |
  |    [2] SURVIVAL        : 2 or 3 neighbours    ->  cell lives on        |
  |    [3] OVERPOPULATION  : > 3 live neighbours  ->  cell dies            |
  |    [4] REPRODUCTION    : exactly 3 neighbours ->  dead cell is born    |
  |                                                                         |
  |   PATTERNS AVAILABLE                                                    |
  |    random         -- probabilistic fill                                 |
  |    glider         -- diagonal spaceship, period 4                      |
  |    gosper         -- Gosper Glider Gun: emits gliders forever           |
  |    pulsar         -- symmetric oscillator, period 3                    |
  |    pentadecathlon -- oscillator, period 15                             |
  |    rpentomino     -- methuselah: 5 cells, 1103 gens to stabilise       |
  |    acorn          -- methuselah: 7 cells, 5206 gens to stabilise       |
  |    diehard        -- dies completely after exactly 130 generations     |
  |    lwss / hwss    -- horizontal spaceships                             |
  |    fleet          -- six gliders in formation                          |
  |                                                                         |
  |   Controls: [p]ause  [r]eset  [n]ext-pattern  [+/-] speed             |
  |             [w]rap   [c]olour [q]uit                                   |
  |                                                                         |
  +=========================================================================+

BANNER
    printf "${RESET}"
    printf "  Pattern  : ${BR_WHITE}${BOLD}%s${RESET}\n" "$PATTERN"
    printf "  Grid     : ${BR_WHITE}${BOLD}%d x %d${RESET}  (%d cells)\n" "$GRID_W" "$GRID_H" "$(( GRID_W * GRID_H ))"
    printf "  Delay    : ${BR_WHITE}${BOLD}%.3f s${RESET}\n" "$DELAY"
    printf "  Wrapping : ${BR_WHITE}${BOLD}%s${RESET}\n" "$(( WRAP ? 'toroidal (edges connect)' : 'finite (hard boundary)' ))"
    echo ""
    printf "  ${DIM}Press ENTER to begin...${RESET}"
    read -r
}

# =============================================================================
#  OUTRO / SUMMARY SCREEN
# =============================================================================
outro_screen() {
    printf "\n${BR_CYAN}${BOLD}"
    echo "  +============================================================+"
    echo "  |  SIMULATION COMPLETE                                       |"
    echo "  +------------------------------------------------------------+"
    printf "  |  %-58s|\n" "  Pattern          : $PATTERN"
    printf "  |  %-58s|\n" "  Generations run  : $GENERATION"
    printf "  |  %-58s|\n" "  Final population : $POPULATION"
    printf "  |  %-58s|\n" "  Peak population  : $PEAK_POPULATION"
    printf "  |  %-58s|\n" "  Grid             : ${GRID_W} x ${GRID_H} = $TOTAL_CELLS cells"
    printf "  |  %-58s|\n" "  Wrapping         : $(( WRAP ? 'toroidal' : 'finite' ))"
    echo "  +------------------------------------------------------------+"
    echo "  |  ITERATION BREAKDOWN                                       |"
    echo "  |                                                            |"
    printf "  |  %-58s|\n" "  Cells evaluated  : $(( GENERATION * TOTAL_CELLS ))"
    printf "  |  %-58s|\n" "  Neighbour reads  : $(( GENERATION * TOTAL_CELLS * 8 ))"
    echo "  |                                                            |"
    echo "  |  Algorithm: pure nested iteration, zero recursion.        |"
    echo "  |  Each generation requires exactly O(W * H) evaluations.   |"
    echo "  |  Neighbour table built once: O(W * H) startup cost.       |"
    echo "  |  Double-buffer swap ensures simultaneous rule application. |"
    echo "  +============================================================+"
    printf "${RESET}\n"
}

# =============================================================================
#  TERMINAL SETUP / TEARDOWN
# =============================================================================
setup_terminal() {
    stty -echo -icanon time 0 min 0 2>/dev/null || true
    hide_cursor
}

restore_terminal() {
    stty sane 2>/dev/null || true
    show_cursor
    printf "${RESET}\n"
}
trap restore_terminal EXIT INT TERM

# =============================================================================
#  NON-BLOCKING KEY READ
# =============================================================================
check_key() {
    local key=""
    IFS= read -r -s -n1 -t0.005 key 2>/dev/null || true
    case "$key" in
        q|Q) restore_terminal; outro_screen; exit 0 ;;
        p|P) PAUSED=$(( 1 - PAUSED )) ;;
        r|R) init_grid; NBRS=(); build_neighbour_table ;;
        n|N) cycle_pattern ;;
        w|W) WRAP=$(( 1 - WRAP )); NBRS=(); build_neighbour_table ;;
        c|C) COLOUR_MODE=$(( 1 - COLOUR_MODE )) ;;
        +|=) DELAY=$(awk "BEGIN{d=$DELAY-0.01; print (d<0.005)?0.005:d}") ;;
        -)   DELAY=$(awk "BEGIN{d=$DELAY+0.02; print (d>3.0)?3.0:d}") ;;
    esac
}

# =============================================================================
#  MAIN
# =============================================================================
query_term_size
TOTAL_CELLS=$(( GRID_W * GRID_H ))

intro_screen
clear_screen
setup_terminal
init_grid
build_neighbour_table

# Prime previous-grid buffer
PREV_GRID=("${GRID[@]}")

# Set initial pattern index position (for cycling)
for (( i = 0; i < ${#PATTERN_LIST[@]}; i++ )); do
    [[ "${PATTERN_LIST[$i]}" == "$PATTERN" ]] && PATTERN_IDX=$i && break
done

# ─────────────────────────────────────────────────────────────────────────────
# THE MAIN SIMULATION LOOP
#
# This is the top-level iteration: one pass = one generation of Life.
# Each pass invokes:
#   1. check_key()       -- handle keyboard input (non-blocking)
#   2. next_generation() -- apply the four rules to all W*H cells
#   3. render()          -- draw the updated grid to the terminal
#   4. sleep             -- pace the frame rate
#
# Exit conditions:
#   - User presses [q]
#   - MAX_GENS reached (if set)
#   - Population drops to zero (extinction)
#   - Grid unchanged for 40 generations (stasis)
# ─────────────────────────────────────────────────────────────────────────────
while (( RUNNING )); do

    check_key

    if (( PAUSED )); then
        cursor_to 1 1
        printf "${REVERSE}${BR_YELLOW}${BOLD}  ** PAUSED **  press [p] to resume  ${RESET}\n"
        sleep 0.1
        continue
    fi

    # Exit conditions
    (( MAX_GENS > 0 && GENERATION >= MAX_GENS )) && break
    (( POPULATION == 0 && GENERATION > 0 )) && {
        cursor_to $(( GRID_H + 5 )) 1
        printf "${BR_RED}${BOLD}  Extinction at generation %d.${RESET}\n" "$GENERATION"
        sleep 2
        break
    }
    (( STABLE_GENS >= 40 )) && {
        cursor_to $(( GRID_H + 5 )) 1
        printf "${BR_YELLOW}${BOLD}  Stasis reached at generation %d.${RESET}\n" "$GENERATION"
        sleep 2
        break
    }

    next_generation
    render
    sleep "$DELAY"

done

restore_terminal
outro_screen
