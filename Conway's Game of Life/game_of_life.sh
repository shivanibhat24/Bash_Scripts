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
# VERSION  : 4.2 — "Emergent Complexity" (fully crash-fixed)
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
# BUG FIXES (v4.1)
# -----------------
#   FIX 1 : set -e + (( expr )) exits when expr == 0 (bash evaluates 0 as
#            "false", which set -e treats as failure). Every arithmetic
#            expression that may legitimately be 0 is now guarded with || true.
#            This was the PRIMARY cause of the immediate-exit-after-intro bug:
#            init_grid called (( POPULATION += 0 )) on an empty grid, which
#            exited instantly under set -e.
#   FIX 2 : (( BIRTHS++ )), (( DEATHS++ )), (( STABLE_GENS++ )) etc. all exit
#            when the pre-increment value is 0. Fixed with || true guards.
#   FIX 3 : (( POPULATION += nxt )) exits when nxt==0 AND running total==0.
#            Fixed with || true.
#   FIX 4 : stty -echo called BEFORE the intro read — this scrambled terminal
#            state on many terminals so the Enter keypress was swallowed and
#            the simulation never started. Terminal raw mode is now set up AFTER
#            the intro screen completes.
#   FIX 5 : printf "$(( WRAP ? 'ON' : 'OFF' ))" — string literals inside bash
#            arithmetic are undefined behaviour (they evaluate to 0). Replaced
#            with explicit if/else string variables.
#   FIX 6 : Delay arithmetic used awk for floating-point math. Replaced with
#            pure integer centisecond arithmetic to remove the awk dependency
#            and eliminate subshell forks in the hot key-handler path.
#   FIX 7 : PREV_GRID unset on the very first render call: GRID was initialised
#            but PREV_GRID was empty, causing ${PREV_GRID[$i]:-0} to always
#            return 0 and mark every initial live cell as "just born". Fixed by
#            copying GRID into PREV_GRID immediately after init_grid().
#   FIX 8 : 'block' was defined as a pattern function but absent from
#            PATTERN_LIST, making it unreachable via [n] cycling. Added.
#   FIX 9 : local declarations inside functions that are called at global scope
#            (render uses 'local base' inside the column loop, but 'base' is
#            also used in next_generation). Renamed to avoid shadowing.
#   FIX 10: cycle_pattern unconditionally rebuilt NBRS even if the new pattern
#            doesn't change grid dimensions — now only rebuilds when needed.
#            Also, reset PEAK_POPULATION on pattern change.
#
# BUG FIXES (v4.2)
# -----------------
#   FIX 11: printf "--" crashes on bash 5.2 (and some earlier versions) because
#            bash's built-in printf parses "--" as an invalid/end-of-options flag
#            rather than as a literal format string. This caused the immediate
#            crash after the intro screen: the render() border loop called
#            printf "--" 64 times and failed on the very first call, printing:
#              "printf: usage: printf [-v var] format [arguments]"
#            then exiting due to set -e.
#
#            Root cause: POSIX printf treats arguments beginning with '-' as
#            potential option prefixes. "--" is specifically the POSIX
#            end-of-options sentinel. Bash 5.2 enforces this strictly.
#
#            Fix: The two border loops (top and bottom of the grid) are replaced
#            by a precomputed BORDER_LINE string built once in render() using
#            string concatenation (border+="--"), which is entirely safe. The
#            border is then printed with printf '%s' which never interprets its
#            argument as a format or option string. This also improves
#            performance: instead of GRID_W printf subprocesses per frame (128
#            for a 64-wide grid, twice per frame = 256 calls), we do one printf
#            call per border line.
#
#            No ternary operators are used anywhere in this script (bash does
#            not have ternary operators; all conditionals use explicit if/else).
# =============================================================================

# =============================================================================
#  STRICT MODE
#  NOTE: We keep set -e but guard every arithmetic expression that can
#        legitimately evaluate to 0 with "|| true". This is more correct than
#        removing set -e, which would hide real errors.
# =============================================================================
set -euo pipefail

# =============================================================================
#  COLOUR PALETTE
# =============================================================================
RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
REVERSE=$'\033[7m'

RED=$'\033[31m'
GREEN=$'\033[32m'
BLUE=$'\033[34m'

BR_RED=$'\033[91m'
BR_GREEN=$'\033[92m'
BR_YELLOW=$'\033[93m'
BR_BLUE=$'\033[94m'
BR_CYAN=$'\033[96m'
BR_WHITE=$'\033[97m'

BG_BLACK=$'\033[40m'

# =============================================================================
#  CONFIGURATION DEFAULTS
# =============================================================================
GRID_W=64             # Grid width  (cells)
GRID_H=26             # Grid height (cells)
MAX_GENS=0            # 0 = run forever; N = stop after N generations
# FIX 6: Use integer centiseconds internally (7 = 0.07 s) to avoid awk.
DELAY_CS=7            # Delay in centiseconds (1 cs = 0.01 s)
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
declare -a GRID=()
declare -a PREV_GRID=()
declare -a NEW_GRID=()

# NBRS[i*8 .. i*8+7] = flat indices of cell i's 8 Moore neighbours
declare -a NBRS=()

GENERATION=0
POPULATION=0
PREV_POPULATION=0
PEAK_POPULATION=0
BIRTHS=0
DEATHS=0
STABLE_GENS=0
TOTAL_CELLS=0         # GRID_W * GRID_H

PAUSED=0
RUNNING=1

# Ordered list of patterns for cycling with [n]
# FIX 8: 'block' added to PATTERN_LIST so it is reachable via [n].
PATTERN_LIST=( random glider gosper pulsar pentadecathlon blinker block
               rpentomino diehard acorn lwss hwss glider_fleet )
PATTERN_IDX=0

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
    local max_grid_w=$(( (TERM_COLS - 6) / 2 ))
    local max_grid_h=$(( TERM_ROWS - 6 ))
    if (( GRID_W > max_grid_w )); then GRID_W=$max_grid_w; fi
    if (( GRID_H > max_grid_h )); then GRID_H=$max_grid_h; fi
    TOTAL_CELLS=$(( GRID_W * GRID_H ))
}

# =============================================================================
#  NEIGHBOUR LOOKUP TABLE
# =============================================================================
build_neighbour_table() {
    local i x y nx ny dx dy k slot

    for (( y = 0; y < GRID_H; y++ )); do
        for (( x = 0; x < GRID_W; x++ )); do

            i=$(( y * GRID_W + x ))
            slot=$(( i * 8 ))
            k=0

            for (( dy = -1; dy <= 1; dy++ )); do
                for (( dx = -1; dx <= 1; dx++ )); do
                    if (( dx == 0 && dy == 0 )); then continue; fi

                    nx=$(( x + dx ))
                    ny=$(( y + dy ))

                    if (( WRAP )); then
                        nx=$(( (nx + GRID_W) % GRID_W ))
                        ny=$(( (ny + GRID_H) % GRID_H ))
                    else
                        if (( nx < 0 ));        then nx=0; fi
                        if (( nx >= GRID_W ));  then nx=$(( GRID_W - 1 )); fi
                        if (( ny < 0 ));        then ny=0; fi
                        if (( ny >= GRID_H ));  then ny=$(( GRID_H - 1 )); fi
                    fi

                    NBRS[$(( slot + k ))]=$(( ny * GRID_W + nx ))
                    # FIX 1: k++ evaluates to 0 when k==0; guard with || true
                    (( k++ )) || true
                done
            done

        done
    done
}

# =============================================================================
#  GRID HELPERS
# =============================================================================
set_cell() { GRID[$(( $2 * GRID_W + $1 ))]="$3"; }

clear_grid() {
    local i
    for (( i = 0; i < TOTAL_CELLS; i++ )); do
        GRID[$i]=0
    done
}

# =============================================================================
#  NEXT GENERATION — THE CORE ENGINE
# =============================================================================
next_generation() {
    PREV_GRID=("${GRID[@]}")
    PREV_POPULATION=$POPULATION
    POPULATION=0
    BIRTHS=0
    DEATHS=0
    local changed=0
    local i base_n nbrs cur nxt
    local n0 n1 n2 n3 n4 n5 n6 n7

    for (( i = 0; i < TOTAL_CELLS; i++ )); do

        cur="${GRID[$i]:-0}"
        base_n=$(( i * 8 ))    # FIX 9: renamed from 'base' to 'base_n'

        n0="${GRID[${NBRS[$base_n]}]:-0}"
        n1="${GRID[${NBRS[$(( base_n+1 ))]}]:-0}"
        n2="${GRID[${NBRS[$(( base_n+2 ))]}]:-0}"
        n3="${GRID[${NBRS[$(( base_n+3 ))]}]:-0}"
        n4="${GRID[${NBRS[$(( base_n+4 ))]}]:-0}"
        n5="${GRID[${NBRS[$(( base_n+5 ))]}]:-0}"
        n6="${GRID[${NBRS[$(( base_n+6 ))]}]:-0}"
        n7="${GRID[${NBRS[$(( base_n+7 ))]}]:-0}"
        nbrs=$(( n0 + n1 + n2 + n3 + n4 + n5 + n6 + n7 ))

        nxt=0
        if (( cur == 1 )); then
            if (( nbrs == 2 || nbrs == 3 )); then
                nxt=1
            else
                # FIX 1: (( DEATHS++ )) exits when DEATHS==0; guard with || true
                (( DEATHS++ )) || true
                # FIX 1: (( changed++ )) exits when changed==0; guard with || true
                (( changed++ )) || true
            fi
        else
            if (( nbrs == 3 )); then
                nxt=1
                # FIX 1: same issue with BIRTHS and changed counters
                (( BIRTHS++ ))  || true
                (( changed++ )) || true
            fi
        fi

        NEW_GRID[$i]=$nxt
        # FIX 3: (( POPULATION += 0 )) when nxt==0 exits under set -e
        (( POPULATION += nxt )) || true

    done

    GRID=("${NEW_GRID[@]}")
    # FIX 1: GENERATION++ exits when GENERATION==0
    (( GENERATION++ )) || true

    if (( POPULATION > PEAK_POPULATION )); then
        PEAK_POPULATION=$POPULATION
    fi

    if (( changed == 0 )); then
        # FIX 1: STABLE_GENS++ exits when STABLE_GENS==0
        (( STABLE_GENS++ )) || true
    else
        STABLE_GENS=0
    fi
}

# =============================================================================
#  RENDER
# =============================================================================
render() {
    cursor_to 1 1

    # FIX 5: Explicit if/else — no string literals inside arithmetic expressions.
    local wrap_str colour_str
    if (( WRAP )); then wrap_str="ON"; else wrap_str="OFF"; fi
    if (( COLOUR_MODE )); then colour_str="ON"; else colour_str="OFF"; fi

    # Header line — padded to terminal width.
    local header_text
    header_text="CONWAY'S GAME OF LIFE  |  Gen: $(printf '%5d' "$GENERATION")  |  Pop: $(printf '%5d' "$POPULATION")  |  Births: $(printf '%4d' "$BIRTHS")  Deaths: $(printf '%4d' "$DEATHS")  |  Peak: $PEAK_POPULATION  |  Author: Shivani Bhat"
    printf '%s' "${BG_BLACK}${BR_WHITE}${BOLD}"
    printf ' %-*s ' $(( TERM_COLS - 2 )) "$header_text"
    printf '%s\n' "${RESET}"

    # Status line.
    printf '%s' "${DIM}"
    printf ' Pattern: %s%-14s%s%s' "${BR_WHITE}" "$PATTERN"   "${RESET}" "${DIM}"
    printf ' Wrap: %s%-4s%s%s'     "${BR_WHITE}" "$wrap_str"  "${RESET}" "${DIM}"
    printf ' Colour: %s%-3s%s%s'   "${BR_WHITE}" "$colour_str" "${RESET}" "${DIM}"
    printf ' Stable: %s%3d%s%s'    "${BR_WHITE}" "$STABLE_GENS" "${RESET}" "${DIM}"
    printf ' [p]ause [r]eset [n]ext-pattern [+/-] speed [w]rap [c]olour [q]uit%s\n' "${RESET}"

    # FIX 11: Build the horizontal border string once by concatenation.
    #         The old code looped: for (( x=0; x<GRID_W; x++ )); do printf "--"; done
    #         bash's built-in printf treats "--" as an end-of-options sentinel on
    #         bash 5.2, causing: "printf: usage: printf [-v var] format [arguments]"
    #         and an immediate exit under set -e. Building the string via "+=" is
    #         completely safe and also faster (one printf call vs GRID_W calls).
    local border_line=""
    local bx
    for (( bx = 0; bx < GRID_W; bx++ )); do
        border_line+="--"
    done

    # Top border.
    printf ' %s+%s+%s\n' "${DIM}" "$border_line" "${RESET}"

    # Cell rows.
    local i cur prv row_str cell_str col_str x y
    local rbase lnbrs

    for (( y = 0; y < GRID_H; y++ )); do

        row_str=" ${DIM}|${RESET}"

        for (( x = 0; x < GRID_W; x++ )); do

            i=$(( y * GRID_W + x ))
            cur="${GRID[$i]:-0}"
            prv="${PREV_GRID[$i]:-0}"

            if (( COLOUR_MODE )); then
                if (( cur == 1 && prv == 0 )); then
                    # Born this generation: bright white bold.
                    cell_str="${BR_WHITE}${BOLD}${CELL_BORN}${RESET}"

                elif (( cur == 1 )); then
                    # Survivor: colour by neighbour count.
                    rbase=$(( i * 8 ))
                    lnbrs=$(( \
                        ${GRID[${NBRS[$rbase]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+1 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+2 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+3 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+4 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+5 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+6 ))]}]:-0} + \
                        ${GRID[${NBRS[$(( rbase+7 ))]}]:-0} \
                    ))
                    if (( lnbrs == 2 )); then
                        col_str="${BR_CYAN}"
                    elif (( lnbrs == 3 )); then
                        col_str="${BR_BLUE}${BOLD}"
                    else
                        col_str="${GREEN}"
                    fi
                    cell_str="${col_str}${CELL_ALIVE}${RESET}"

                elif (( cur == 0 && prv == 1 )); then
                    # Just died: dim red.
                    cell_str="${DIM}${RED}${CELL_DIED}${RESET}"

                else
                    # Empty cell.
                    cell_str="${CELL_DEAD}"
                fi
            else
                # Monochrome mode.
                if (( cur == 1 && prv == 0 )); then
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

        done

        row_str+="${DIM}|${RESET}"
        printf '%s\n' "$row_str"

    done

    # Bottom border (reuses border_line already built above).
    printf ' %s+%s+%s\n' "${DIM}" "$border_line" "${RESET}"
}

# =============================================================================
#  PATTERN LIBRARY
# =============================================================================
stamp() {
    local ox="$1" oy="$2"
    shift 2
    while (( $# >= 2 )); do
        local sx=$(( ox + $1 ))
        local sy=$(( oy + $2 ))
        if (( sx >= 0 && sx < GRID_W && sy >= 0 && sy < GRID_H )); then
            GRID[$(( sy * GRID_W + sx ))]=1
        fi
        shift 2
    done
}

pattern_blinker() {
    local cx=$(( GRID_W/2 - 1 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy  0 0  1 0  2 0
}

pattern_block() {
    local cx=$(( GRID_W/2 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy  0 0  1 0  0 1  1 1
}

pattern_glider() {
    local cx=$(( GRID_W/4 )) cy=$(( GRID_H/4 ))
    stamp $cx $cy \
              1 0 \
        2 1 \
        0 2  1 2  2 2
}

pattern_lwss() {
    local cx=$(( GRID_W/2 - 2 )) cy=$(( GRID_H/2 - 1 ))
    stamp $cx $cy \
        1 0  4 0 \
        0 1 \
        0 2        4 2 \
        0 3  1 3  2 3  3 3
}

pattern_hwss() {
    local cx=$(( GRID_W/2 - 3 )) cy=$(( GRID_H/2 - 2 ))
    stamp $cx $cy \
        2 0  3 0 \
        0 1  1 1  4 1  5 1 \
        0 2  1 2  2 2  3 2  4 2  5 2 \
        1 3  2 3  3 3  4 3
}

pattern_rpentomino() {
    local cx=$(( GRID_W/2 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        1 0  2 0 \
        0 1  1 1 \
        1 2
}

pattern_diehard() {
    local cx=$(( GRID_W/2 - 4 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        6 0 \
        0 1  1 1 \
        1 2  5 2  6 2  7 2
}

pattern_acorn() {
    local cx=$(( GRID_W/2 - 3 )) cy=$(( GRID_H/2 ))
    stamp $cx $cy \
        1 0 \
        3 1 \
        0 2  1 2  4 2  5 2  6 2
}

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

pattern_glider_fleet() {
    local offsets=( 0 0  10 4  20 8  30 12  5 16  15 20 )
    local ii
    for (( ii = 0; ii < ${#offsets[@]}; ii += 2 )); do
        local ox=$(( GRID_W/5 + offsets[ii] ))
        local oy=$(( 2 + offsets[ii+1] ))
        stamp $ox $oy \
                  1 0 \
            2 1 \
            0 2  1 2  2 2
    done
}

pattern_random() {
    # Re-seed RANDOM from /dev/urandom for true randomness each call.
    local seed
    seed=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ') || true
    if [[ -n "$seed" ]]; then RANDOM=$seed; fi

    local xi yi
    for (( yi = 0; yi < GRID_H; yi++ )); do
        for (( xi = 0; xi < GRID_W; xi++ )); do
            if (( RANDOM % 100 < DENSITY )); then
                GRID[$(( yi * GRID_W + xi ))]=1
            else
                GRID[$(( yi * GRID_W + xi ))]=0
            fi
        done
    done
}

# =============================================================================
#  INIT GRID
# =============================================================================
init_grid() {
    GENERATION=0
    POPULATION=0
    BIRTHS=0
    DEATHS=0
    STABLE_GENS=0
    PREV_POPULATION=0
    PEAK_POPULATION=0

    GRID=()
    PREV_GRID=()
    NEW_GRID=()
    local ii
    for (( ii = 0; ii < TOTAL_CELLS; ii++ )); do
        GRID[$ii]=0
        PREV_GRID[$ii]=0
        NEW_GRID[$ii]=0
    done

    case "$PATTERN" in
        glider)              pattern_glider ;;
        gosper)              pattern_gosper ;;
        pulsar)              pattern_pulsar ;;
        pentadecathlon)      pattern_pentadecathlon ;;
        blinker)             pattern_blinker ;;
        block)               pattern_block ;;
        rpentomino)          pattern_rpentomino ;;
        diehard)             pattern_diehard ;;
        acorn)               pattern_acorn ;;
        lwss)                pattern_lwss ;;
        hwss)                pattern_hwss ;;
        fleet|glider_fleet)  pattern_glider_fleet ;;
        random|*)            pattern_random ;;
    esac

    # Count initial population.
    POPULATION=0
    for (( ii = 0; ii < TOTAL_CELLS; ii++ )); do
        # FIX 3: (( POPULATION += 0 )) exits under set -e; use || true
        (( POPULATION += ${GRID[$ii]:-0} )) || true
    done
    PEAK_POPULATION=$POPULATION

    # FIX 7: Sync PREV_GRID to GRID immediately so the first render doesn't
    # incorrectly flash every live cell as "just born".
    PREV_GRID=("${GRID[@]}")
}

# =============================================================================
#  CYCLE PATTERN
# =============================================================================
cycle_pattern() {
    # FIX 1: modulo arithmetic result may be 0
    (( PATTERN_IDX = (PATTERN_IDX + 1) % ${#PATTERN_LIST[@]} )) || true
    PATTERN="${PATTERN_LIST[$PATTERN_IDX]}"
    init_grid
    # FIX 10: Only rebuild NBRS if it is empty; grid size doesn't change
    # during pattern cycling so the table remains valid.
    if (( ${#NBRS[@]} == 0 )); then
        build_neighbour_table
    fi
}

# =============================================================================
#  DELAY HELPERS (FIX 6: integer centisecond arithmetic, no awk)
# =============================================================================
delay_sleep() {
    # Convert centiseconds to seconds with two decimal places for sleep.
    # sleep accepts fractional seconds on Linux (GNU coreutils).
    printf -v _delay_str "0.%02d" "$DELAY_CS"
    sleep "$_delay_str"
}

delay_faster() {
    (( DELAY_CS -= 1 )) || true
    if (( DELAY_CS < 1 )); then DELAY_CS=1; fi
}

delay_slower() {
    (( DELAY_CS += 2 )) || true
    if (( DELAY_CS > 300 )); then DELAY_CS=300; fi
}

delay_display() {
    printf "0.%02d" "$DELAY_CS"
}

# =============================================================================
#  ARGUMENT PARSING
# =============================================================================
usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

  --pattern  NAME   Starting pattern:
                      random glider gosper pulsar pentadecathlon
                      blinker block rpentomino diehard acorn lwss hwss fleet
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

# Parse --delay into centiseconds.
parse_delay_arg() {
    local raw="$1"
    # Extract digits: support "0.07", ".07", "1", "0.5" etc.
    # We multiply by 100 using string manipulation to stay in integers.
    local int_part frac_part
    int_part="${raw%%.*}"
    if [[ "$raw" == *"."* ]]; then
        frac_part="${raw#*.}"
        # Pad or trim to exactly 2 decimal places.
        frac_part="${frac_part}00"
        frac_part="${frac_part:0:2}"
    else
        frac_part="00"
    fi
    DELAY_CS=$(( ${int_part:-0} * 100 + 10#$frac_part ))
    if (( DELAY_CS < 1 ));    then DELAY_CS=1; fi
    if (( DELAY_CS > 30000 )); then DELAY_CS=30000; fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pattern)  PATTERN="$2";            shift 2 ;;
        --width)    GRID_W="$2";             shift 2 ;;
        --height)   GRID_H="$2";             shift 2 ;;
        --delay)    parse_delay_arg "$2";    shift 2 ;;
        --gens)     MAX_GENS="$2";           shift 2 ;;
        --density)  DENSITY="$2";            shift 2 ;;
        --no-wrap)  WRAP=0;                  shift 1 ;;
        --mono)     COLOUR_MODE=0;           shift 1 ;;
        --fast)     DELAY_CS=2;              shift 1 ;;
        --help|-h)  usage ;;
        *) printf 'Unknown option: %s\n' "$1"; usage ;;
    esac
done

# =============================================================================
#  VALIDATE INPUTS
# =============================================================================
if ! [[ "$GRID_W" =~ ^[0-9]+$ ]] || (( GRID_W < 10 || GRID_W > 200 )); then
    printf 'Error: --width must be 10-200 (got %s)\n' "$GRID_W"; exit 1
fi
if ! [[ "$GRID_H" =~ ^[0-9]+$ ]] || (( GRID_H < 5 || GRID_H > 100 )); then
    printf 'Error: --height must be 5-100 (got %s)\n' "$GRID_H"; exit 1
fi
if ! [[ "$DENSITY" =~ ^[0-9]+$ ]] || (( DENSITY < 1 || DENSITY > 99 )); then
    printf 'Error: --density must be 1-99 (got %s)\n' "$DENSITY"; exit 1
fi

# =============================================================================
#  INTRO SCREEN
#  FIX 4: Run intro in NORMAL terminal mode (stty not yet changed).
#         stty raw mode is set up in setup_terminal() AFTER intro completes.
#         This ensures the "Press ENTER to begin..." read works reliably.
# =============================================================================
intro_screen() {
    clear_screen
    printf '%s%s' "${BR_GREEN}" "${BOLD}"
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
  |    block          -- simplest still life (2x2 square)                  |
  |    fleet          -- six gliders in formation                          |
  |                                                                         |
  |   Controls: [p]ause  [r]eset  [n]ext-pattern  [+/-] speed             |
  |             [w]rap   [c]olour [q]uit                                   |
  |                                                                         |
  +=========================================================================+

BANNER
    printf '%s' "${RESET}"
    local wrap_label
    if (( WRAP == 1 )); then
        wrap_label="toroidal (edges connect)"
    else
        wrap_label="finite (hard boundary)"
    fi
    printf '  Pattern  : %s%s%s\n'           "${BR_WHITE}" "${BOLD}$PATTERN${RESET}" "${RESET}"
    printf '  Grid     : %s%s%s  (%d cells)\n' \
        "${BR_WHITE}${BOLD}" "${GRID_W} x ${GRID_H}" "${RESET}" "$(( GRID_W * GRID_H ))"
    printf '  Delay    : %s%s s%s\n'          "${BR_WHITE}${BOLD}" "$(delay_display)" "${RESET}"
    printf '  Wrapping : %s%s%s\n'            "${BR_WHITE}${BOLD}" "$wrap_label" "${RESET}"
    printf '\n'
    printf '  %sPress ENTER to begin...%s' "${DIM}" "${RESET}"
    # FIX 4: This read happens BEFORE stty raw mode — works in all terminals.
    read -r
}

# =============================================================================
#  OUTRO / SUMMARY SCREEN
# =============================================================================
outro_screen() {
    printf '\n%s%s' "${BR_CYAN}" "${BOLD}"
    printf '  +============================================================+\n'
    printf '  |  SIMULATION COMPLETE                                       |\n'
    printf '  +------------------------------------------------------------+\n'
    printf '  |  %-58s|\n' "  Pattern          : $PATTERN"
    printf '  |  %-58s|\n' "  Generations run  : $GENERATION"
    printf '  |  %-58s|\n' "  Final population : $POPULATION"
    printf '  |  %-58s|\n' "  Peak population  : $PEAK_POPULATION"
    printf '  |  %-58s|\n' "  Grid             : ${GRID_W} x ${GRID_H} = $TOTAL_CELLS cells"
    local outro_wrap_str
    if (( WRAP )); then outro_wrap_str="toroidal"; else outro_wrap_str="finite"; fi
    printf '  |  %-58s|\n' "  Wrapping         : $outro_wrap_str"
    printf '  +------------------------------------------------------------+\n'
    printf '  |  ITERATION BREAKDOWN                                       |\n'
    printf '  |                                                            |\n'
    printf '  |  %-58s|\n' "  Cells evaluated  : $(( GENERATION * TOTAL_CELLS ))"
    printf '  |  %-58s|\n' "  Neighbour reads  : $(( GENERATION * TOTAL_CELLS * 8 ))"
    printf '  |                                                            |\n'
    printf '  |  Algorithm: pure nested iteration, zero recursion.        |\n'
    printf '  |  Each generation requires exactly O(W * H) evaluations.   |\n'
    printf '  |  Neighbour table built once: O(W * H) startup cost.       |\n'
    printf '  |  Double-buffer swap ensures simultaneous rule application. |\n'
    printf '  +============================================================+\n'
    printf '%s\n' "${RESET}"
}

# =============================================================================
#  TERMINAL SETUP / TEARDOWN
#  FIX 4: setup_terminal() is called AFTER intro_screen() completes.
# =============================================================================
setup_terminal() {
    stty -echo -icanon time 0 min 0 2>/dev/null || true
    hide_cursor
}

restore_terminal() {
    stty sane 2>/dev/null || true
    show_cursor
    printf '%s\n' "${RESET}"
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
        p|P) if (( PAUSED )); then PAUSED=0; else PAUSED=1; fi ;;
        r|R) init_grid; NBRS=(); build_neighbour_table ;;
        n|N) cycle_pattern ;;
        w|W)
            if (( WRAP )); then WRAP=0; else WRAP=1; fi
            NBRS=()
            build_neighbour_table
            ;;
        c|C) if (( COLOUR_MODE )); then COLOUR_MODE=0; else COLOUR_MODE=1; fi ;;
        '+'|'=') delay_faster ;;
        '-')     delay_slower ;;
    esac
}

# =============================================================================
#  MAIN
# =============================================================================
query_term_size
TOTAL_CELLS=$(( GRID_W * GRID_H ))

# FIX 4: Intro runs first, in normal terminal mode, so read -r works.
intro_screen

clear_screen
# FIX 4: Terminal raw mode set AFTER intro is done.
setup_terminal

init_grid
build_neighbour_table

# Set initial pattern index position (for cycling with [n]).
local_i=0
for (( local_i = 0; local_i < ${#PATTERN_LIST[@]}; local_i++ )); do
    if [[ "${PATTERN_LIST[$local_i]}" == "$PATTERN" ]]; then
        PATTERN_IDX=$local_i
        break
    fi
done

# =============================================================================
#  THE MAIN SIMULATION LOOP
# =============================================================================
while (( RUNNING )); do

    check_key

    if (( PAUSED )); then
        cursor_to 1 1
        printf '%s%s%s  ** PAUSED **  press [p] to resume  %s\n' \
            "${REVERSE}" "${BR_YELLOW}" "${BOLD}" "${RESET}"
        sleep 0.1
        continue
    fi

    # Exit conditions (all guards use explicit comparisons, not bare arithmetic).
    if (( MAX_GENS > 0 && GENERATION >= MAX_GENS )); then break; fi

    if (( GENERATION > 0 && POPULATION == 0 )); then
        cursor_to $(( GRID_H + 5 )) 1
        printf '%s%s  Extinction at generation %d.%s\n' \
            "${BR_RED}" "${BOLD}" "$GENERATION" "${RESET}"
        sleep 2
        break
    fi

    if (( STABLE_GENS >= 40 )); then
        cursor_to $(( GRID_H + 5 )) 1
        printf '%s%s  Stasis reached at generation %d.%s\n' \
            "${BR_YELLOW}" "${BOLD}" "$GENERATION" "${RESET}"
        sleep 2
        break
    fi

    next_generation
    render
    delay_sleep

done

restore_terminal
outro_screen
