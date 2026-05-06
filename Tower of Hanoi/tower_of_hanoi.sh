#!/usr/bin/env bash
# =============================================================================
#
#  ████████╗ ██████╗ ██╗    ██╗███████╗██████╗      ██████╗ ███████╗
#     ██╔══╝██╔═══██╗██║    ██║██╔════╝██╔══██╗    ██╔═══██╗██╔════╝
#     ██║   ██║   ██║██║ █╗ ██║█████╗  ██████╔╝    ██║   ██║█████╗
#     ██║   ██║   ██║██║███╗██║██╔══╝  ██╔══██╗    ██║   ██║██╔══╝
#     ██║   ╚██████╔╝╚███╔███╔╝███████╗██║  ██║    ╚██████╔╝██║
#     ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝ ╚═╝
#
#  ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗
#  ██║  ██║██╔══██╗████╗  ██║██╔═══██╗██║
#  ███████║███████║██╔██╗ ██║██║   ██║██║
#  ██╔══██║██╔══██║██║╚██╗██║██║   ██║██║
#  ██║  ██║██║  ██║██║ ╚████║╚██████╔╝██║
#  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝
#
# =============================================================================
# AUTHOR   : Shivani Bhat
# REQUIRES : bash >= 4.3  (nameref support), a 256-colour terminal
#
# PURPOSE  : An immersive, fully-annotated Tower of Hanoi solver that
#            demonstrates RECURSION through live terminal animation.
#            Every recursive call, every stack frame, every base-case
#            hit is visible in real time.
#
# ALGORITHM OVERVIEW
# ------------------
# The Tower of Hanoi is solved by a single elegant recursive insight:
#
#   To move N discs from SOURCE to DESTINATION (using AUXILIARY):
#     1. Recursively move (N-1) discs: SOURCE  -> AUXILIARY    [sub-problem]
#     2. Move disc N directly       : SOURCE  -> DESTINATION   [base action]
#     3. Recursively move (N-1) discs: AUXILIARY -> DESTINATION [sub-problem]
#
#   BASE CASE: N == 1 — move the single disc directly, no recursion needed.
#
#   This achieves the MINIMUM possible number of moves: 2^N - 1.
#   Time complexity : O(2^N)
#   Space complexity: O(N)  — the call stack is at most N frames deep.
#
# THE LEGEND
# ----------
#   In a temple in Hanoi, 64 golden discs rest on a diamond needle.
#   Priests move one disc at a time, never placing larger on smaller.
#   When all 64 discs reach the third needle — the universe ends.
#   Moves required: 2^64 - 1 = 18,446,744,073,709,551,615
#   At one move per second: ~585 billion years.
#   The observable universe is 13.8 billion years old.
#
# CONTROLS (during animation)
#   [+] / [-]   Speed up / slow down
#   [s]         Skip to end (solve instantly)
#   [q]         Quit
#
# USAGE
#   ./tower_of_hanoi.sh [--discs N] [--delay S] [--fast] [--no-stack]
#
# =============================================================================

# =============================================================================
#  STRICT MODE
#  -e : exit on error   -u : treat unset vars as errors   -o pipefail
# =============================================================================
set -euo pipefail

# =============================================================================
#  COLOUR PALETTE
#  All colours defined as ANSI escape sequences.
#  Usage: echo -e "${RED}text${RESET}"
# =============================================================================
RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
ITALIC=$'\033[3m'
UNDERLINE=$'\033[4m'
REVERSE=$'\033[7m'

# Standard foreground
RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'
MAGENTA=$'\033[35m'
CYAN=$'\033[36m'
WHITE=$'\033[37m'

# Bright foreground
BR_RED=$'\033[91m'
BR_GREEN=$'\033[92m'
BR_YELLOW=$'\033[93m'
BR_BLUE=$'\033[94m'
BR_MAGENTA=$'\033[95m'
BR_CYAN=$'\033[96m'
BR_WHITE=$'\033[97m'

# Background
BG_BLACK=$'\033[40m'
BG_RED=$'\033[41m'
BG_GREEN=$'\033[42m'
BG_YELLOW=$'\033[43m'
BG_BLUE=$'\033[44m'
BG_MAGENTA=$'\033[45m'
BG_CYAN=$'\033[46m'
BG_WHITE=$'\033[47m'

# =============================================================================
#  DISC COLOUR MAP
#  Disc 1 (smallest) = brightest colour.
#  Disc N (largest)  = deepest colour.
#  Index 0 is a sentinel / unused slot.
# =============================================================================
DISC_COLOURS=(
    ""                # [0] unused sentinel
    $'\033[91m'       # [1] Bright Red       — smallest disc
    $'\033[93m'       # [2] Bright Yellow
    $'\033[92m'       # [3] Bright Green
    $'\033[96m'       # [4] Bright Cyan
    $'\033[94m'       # [5] Bright Blue
    $'\033[95m'       # [6] Bright Magenta
    $'\033[31m'       # [7] Red
    $'\033[33m'       # [8] Yellow           — largest disc (max 8)
)

# Disc label characters — shown inside each disc body for quick identification
DISC_LABELS=( "" "1" "2" "3" "4" "5" "6" "7" "8" )

# =============================================================================
#  CONFIGURATION DEFAULTS
#  All overridable via command-line flags (see parse_args below).
# =============================================================================
NUM_DISCS=5          # Number of discs to solve (1-8)
DELAY=0.30           # Seconds to sleep between moves
SHOW_STACK=1         # 1 = show the recursive call-stack panel
SKIP=0               # 1 = solve without animation (benchmark mode)

# =============================================================================
#  GLOBAL STATE
#
#  The three pegs are modelled as bash indexed arrays acting as stacks.
#  The BOTTOM of each stack (index 0) holds the largest disc.
#  The TOP of each stack (last index) holds the smallest disc.
#
#  PEG_A = Source      (all discs start here)
#  PEG_B = Auxiliary   (scratch space)
#  PEG_C = Destination (all discs must end here)
# =============================================================================
declare -a PEG_A
declare -a PEG_B
declare -a PEG_C

MOVE_COUNT=0         # Incremented on every leaf-level disc move
TOTAL_MOVES=0        # Pre-calculated optimal total: 2^N - 1
RECURSION_DEPTH=0    # Tracks current call-stack depth (for visualisation)
MAX_DEPTH_SEEN=0     # Deepest recursion level reached so far

# Call-stack display: each frame is a string "hanoi(n,from->to)"
declare -a CALL_STACK

# Terminal dimensions (queried once at startup)
TERM_COLS=80
TERM_ROWS=24

# =============================================================================
#  GLOBAL RETURN VALUE FOR pop()
#
#  FIX FOR BUG 1:
#  pop() formerly used `printf '%s' "$_top"` so callers wrote:
#      disc=$(pop "$from")
#  The $(...) command substitution spawns a subshell.  All array mutations
#  inside pop() (the unset that removes the top element) happen in that
#  subshell and are lost when it exits — the peg never actually shrinks.
#
#  Solution: pop() writes its result here instead of to stdout.
#  Callers must do:
#      pop "$peg_name"
#      disc="$POPPED"
# =============================================================================
POPPED=""

# =============================================================================
#  STACK OPERATIONS
#  These functions simulate push/pop/peek on named bash arrays.
#  We use bash namerefs (declare -n) — available since bash 4.3.
#  A nameref is a variable that is an alias for another variable.
# =============================================================================

# push <array_name> <value>
# -----------------------------------------------------------------------------
# Appends a value to the end of the named array (top of stack).
# Uses eval to allow dynamic variable-name addressing.
push() {
    # eval is safe here: array name is always an internal identifier
    eval "$1+=($2)"
}

# pop <array_name>
# -----------------------------------------------------------------------------
# Removes the top element of the named array and stores it in $POPPED.
# Does NOT print anything — see the POPPED global above for rationale.
#
# FIX BUG 1: result goes to global POPPED, not stdout.  No subshell needed.
# FIX BUG 3: uses eval "unset '${1}[-1]'" instead of unset "_ref[-1]".
#            The nameref form silently unsets a variable called literally
#            "_ref[-1]" rather than the last element of the target array.
pop() {
    local -n _ref="$1"
    POPPED="${_ref[-1]}"
    eval "unset '${1}[-1]'"
}

# peek <array_name>  --> prints the top value without removing it
# (Used for display only; safe with printf since the array is not mutated.)
peek() {
    local -n _ref="$1"
    printf '%s' "${_ref[-1]:-0}"
}

# stack_size <array_name>  --> prints the number of elements
stack_size() {
    local -n _ref="$1"
    printf '%s' "${#_ref[@]}"
}

# =============================================================================
#  TERMINAL UTILITIES
# =============================================================================

# cursor_to <row> <col>  — moves the terminal cursor (1-indexed)
cursor_to() { printf '\033[%d;%dH' "$1" "$2"; }

# clear_screen — hard clear with cursor reset
clear_screen() { printf '\033[2J\033[H'; }

# hide/show cursor
hide_cursor() { printf '\033[?25l'; }
show_cursor() { printf '\033[?25h'; }

# save/restore cursor position
save_cursor()    { printf '\033[s'; }
restore_cursor() { printf '\033[u'; }

# query terminal size and store in TERM_COLS / TERM_ROWS
query_term_size() {
    # Use tput if available; fall back to stty or hard defaults
    if command -v tput &>/dev/null; then
        TERM_COLS=$(tput cols  2>/dev/null || echo 80)
        TERM_ROWS=$(tput lines 2>/dev/null || echo 24)
    elif command -v stty &>/dev/null; then
        local size
        size=$(stty size 2>/dev/null || echo "24 80")
        TERM_ROWS="${size% *}"
        TERM_COLS="${size#* }"
    fi
}

# =============================================================================
#  PROGRESS BAR
#  Renders a filled/unfilled block bar with percentage.
#
#  ITERATION: the one explicit loop in the rendering path.
# =============================================================================
progress_bar() {
    local current="$1"
    local total="$2"
    local width="${3:-24}"     # bar character width

    local filled=$(( total > 0 ? current * width / total : 0 ))
    local bar=""

    # ITERATE to build the bar string character by character
    for (( i = 0; i < width; i++ )); do
        if (( i < filled )); then
            bar+="█"
        elif (( i == filled && current < total )); then
            bar+="▓"    # leading edge — gives a "filling" effect
        else
            bar+="░"
        fi
    done

    local pct=$(( total > 0 ? current * 100 / total : 0 ))
    printf "${BR_GREEN}%s${RESET} ${BR_WHITE}%3d%%${RESET}" "$bar" "$pct"
}

# =============================================================================
#  DRAW HEADER
#  Prints the fixed title bar at the top of the screen.
# =============================================================================
draw_header() {
    printf "${BG_BLUE}${BR_WHITE}${BOLD}"
    printf "  %-*s  " $(( TERM_COLS - 4 )) \
        "TOWER OF HANOI  |  Discs: ${NUM_DISCS}  |  Optimal: ${TOTAL_MOVES} moves  |  Author: Shivani Bhat"
    printf "${RESET}\n"
}

# =============================================================================
#  DRAW STATS BAR
#  Printed below the pegs — shows move counter, progress, last action.
# =============================================================================
draw_stats() {
    local from_lbl="${1:-}"
    local to_lbl="${2:-}"
    local disc_id="${3:-0}"

    printf "  ${BR_WHITE}${BOLD}Move ${BR_YELLOW}%4d${RESET}${BR_WHITE} / ${BR_RED}%-4d${RESET}  " \
        "$MOVE_COUNT" "$TOTAL_MOVES"

    progress_bar "$MOVE_COUNT" "$TOTAL_MOVES" 28

    printf "  ${DIM}Depth: ${BR_MAGENTA}%d${RESET}${DIM}  Max: ${BR_CYAN}%d${RESET}" \
        "$RECURSION_DEPTH" "$MAX_DEPTH_SEEN"

    echo ""

    if [[ -n "$from_lbl" && "$disc_id" -gt 0 ]]; then
        local col="${DISC_COLOURS[$disc_id]}"
        printf "  ${DIM}Last move: disc ${col}${BOLD}[%s]${RESET}${DIM}  %s  -->  %s${RESET}\n" \
            "${DISC_LABELS[$disc_id]}" "$from_lbl" "$to_lbl"
    else
        printf "  ${DIM}%s${RESET}\n" "Awaiting first move..."
    fi
}

# =============================================================================
#  DRAW CALL STACK PANEL
#  Shows the live recursion call stack on the right side of the terminal.
#  This makes the abstract concept of "stack frames" tangible and visible.
#
#  Each entry shows: hanoi(n, from->to)
#  The bottom of the panel = the outermost call.
#  The top entry = the currently executing frame.
# =============================================================================
draw_call_stack() {
    (( SHOW_STACK == 0 )) && return

    local panel_col=$(( TERM_COLS - 32 ))
    local panel_rows=18
    local stack_depth="${#CALL_STACK[@]}"

    # Panel border
    cursor_to 3 "$panel_col"
    printf "${DIM}${CYAN}┌─── Recursion Call Stack ────┐${RESET}"

    local display_start=$(( stack_depth > panel_rows ? stack_depth - panel_rows : 0 ))

    local row=4
    for (( i = display_start; i < stack_depth; i++ )); do
        cursor_to "$row" "$panel_col"
        local is_top=$(( i == stack_depth - 1 ))
        if (( is_top )); then
            # Highlight the currently active frame
            printf "${CYAN}│ ${BR_YELLOW}${BOLD}%-28s${RESET}${CYAN}│${RESET}" "${CALL_STACK[$i]}"
        else
            printf "${DIM}${CYAN}│ %-28s│${RESET}" "${CALL_STACK[$i]}"
        fi
        # FIX BUG 2: (( row++ )) returns exit-code 1 when row was 0.
        # Although row starts at 4 here (so the immediate risk is low),
        # guard with || true for robustness and consistency.
        (( row++ )) || true
    done

    # Pad empty rows
    while (( row < 4 + panel_rows )); do
        cursor_to "$row" "$panel_col"
        printf "${DIM}${CYAN}│%30s│${RESET}" ""
        (( row++ )) || true
    done

    cursor_to "$row" "$panel_col"
    printf "${DIM}${CYAN}└──────────────────────────────┘${RESET}"

    (( row++ )) || true
    cursor_to "$row" "$panel_col"
    printf "${DIM}  Frames: %d / %d (max)${RESET}" "$stack_depth" "$NUM_DISCS"
}

# =============================================================================
#  DRAW PEGS
#
#  This is the visual centrepiece of the program.
#  It renders three vertical pegs with coloured disc blocks stacked on each.
#
#  Layout:
#    - Each peg column is (NUM_DISCS * 2 + 3) characters wide.
#    - Disc width = disc_size * 2 - 1 characters (plus 1-char borders each side).
#    - Rows are rendered top-to-bottom; row 1 = top of peg.
#    - Empty rows show just the vertical pole character (|).
#
#  ITERATION: Two nested loops — one over rows, one over the three pegs.
#             A third inner loop draws each disc's body character-by-character.
# =============================================================================
draw_pegs() {
    local max_discs="$NUM_DISCS"

    # Column width for each peg section
    # Largest disc fills (max_discs * 2 + 1) chars; +2 for one space margin each side
    local peg_col_w=$(( max_discs * 2 + 5 ))

    # Copy peg arrays for safe indexing (we don't pop — just read)
    local -a pa=("${PEG_A[@]+"${PEG_A[@]}"}")
    local -a pb=("${PEG_B[@]+"${PEG_B[@]}"}")
    local -a pc=("${PEG_C[@]+"${PEG_C[@]}"}")
    local -a peg_arrays=( "pa" "pb" "pc" )
    local -a peg_names=( "  A   SOURCE  " "  B  AUXILIARY" "  C    DEST   " )

    echo ""

    # ── OUTER ITERATION: rows from top (empty) down to base ──────────────────
    # row 1 = topmost empty row, row max_discs = lowest slot (largest disc)
    for (( row = max_discs; row >= 1; row-- )); do

        printf "  "     # left margin

        # ── MIDDLE ITERATION: left peg, centre peg, right peg ────────────────
        for peg_idx in 0 1 2; do
            local -n cur_peg="${peg_arrays[$peg_idx]}"
            local peg_sz="${#cur_peg[@]}"

            # Which disc (if any) occupies this row?
            # Stack index: bottom=0, top=peg_sz-1.
            # Visual row: row=max_discs is bottom, row=1 is top.
            # Disc at visual row R lives at stack index (peg_sz - (max_discs - R + 1))
            local disc_stack_idx=$(( peg_sz - (max_discs - row + 1) ))

            if (( disc_stack_idx >= 0 && disc_stack_idx < peg_sz )); then
                # ---- A disc exists at this row --------------------------------
                local d="${cur_peg[$disc_stack_idx]}"
                local col="${DISC_COLOURS[$d]}"
                local lbl="${DISC_LABELS[$d]}"
                local disc_half="$d"                         # half-width in chars
                local pad=$(( max_discs - disc_half + 1 ))   # spaces left of disc

                printf "%*s" "$pad" ""                       # left pad

                # ── INNER ITERATION: draw the disc body ──────────────────────
                printf "${col}${BOLD}"
                printf "["       # left edge

                # Centre section: label in middle, fill with equals signs
                local body_w=$(( disc_half * 2 - 1 ))
                local mid=$(( body_w / 2 ))
                for (( k = 0; k < body_w; k++ )); do
                    if (( k == mid )); then
                        printf "%s" "$lbl"     # disc label character
                    else
                        printf "="
                    fi
                done

                printf "]"       # right edge
                printf "${RESET}"
                # ─────────────────────────────────────────────────────────────

                printf "%*s" "$pad" ""                       # right pad
            else
                # ---- Empty slot — draw just the pole -------------------------
                local pad=$(( max_discs ))
                printf "%*s" "$pad" ""
                printf "${DIM}${WHITE}|${RESET}"
                printf "%*s" "$pad" ""
                printf " "
            fi

            printf "   "        # gap between peg sections
        done

        echo ""
    done
    # ── End outer row loop ────────────────────────────────────────────────────

    # ── Base platform ─────────────────────────────────────────────────────────
    printf "  "
    for (( p = 0; p < 3; p++ )); do
        printf "${BR_WHITE}${BOLD}"
        printf "="
        for (( k = 0; k < peg_col_w; k++ )); do printf "="; done
        printf "${RESET}"
        printf "   "
    done
    echo ""

    # ── Peg labels ────────────────────────────────────────────────────────────
    printf "  "
    for peg_idx in 0 1 2; do
        printf "${BR_CYAN}${BOLD}"
        printf "%-$(( peg_col_w + 4 ))s" "    ${peg_names[$peg_idx]}"
        printf "${RESET}"
    done
    echo ""
    echo ""
}

# =============================================================================
#  RENDER FRAME
#  Composes a complete screen frame:  header + stats + pegs + call stack.
#  Uses cursor positioning (no full clear) to eliminate flicker.
# =============================================================================
render_frame() {
    local from_lbl="${1:-}"
    local to_lbl="${2:-}"
    local disc_id="${3:-0}"

    cursor_to 1 1
    draw_header
    cursor_to 2 1
    draw_stats "$from_lbl" "$to_lbl" "$disc_id"
    cursor_to 3 1
    draw_pegs
    draw_call_stack
}

# =============================================================================
#  THE RECURSIVE HANOI FUNCTION
#
#  This is the algorithm.  Everything else in this script is scaffolding.
#  Study this function to understand recursion in its purest form.
#
#  Parameters
#  ----------
#  n        : number of discs to move in THIS invocation
#  from     : name of the source peg array  (e.g. "PEG_A")
#  to       : name of the destination peg array
#  aux      : name of the auxiliary peg array
#  from_lbl : human label ("A", "B", or "C")
#  to_lbl   : human label
#  aux_lbl  : human label
#
#  Recursion structure
#  -------------------
#  The call tree for N=3 looks like this (each node = one hanoi() call):
#
#             hanoi(3, A->C)
#            /               \
#      hanoi(2,A->B)       hanoi(2,B->C)        <-- two recursive sub-problems
#      /        \           /        \
#  hanoi(1,A->C) ... hanoi(1,A->C) ...          <-- base cases (actual moves)
#
#  Every LEAF of this tree is a base case that performs exactly one disc move.
#  There are 2^(N-1) leaves, and each internal node performs one additional
#  move (step 2 below), giving 2^(N-1) + 2^(N-2) + ... + 1 = 2^N - 1 total.
# =============================================================================
hanoi() {
    local n="$1"
    local from="$2"  to="$3"  aux="$4"
    local from_lbl="$5"  to_lbl="$6"  aux_lbl="$7"

    # FIX BUG 2: Guard all (( expr++ / expr-- )) with || true.
    # When the expression evaluates to 0 (e.g. depth was 0 before first ++,
    # or depth returns to 0 on final --), bash returns exit-code 1, which
    # kills the script under `set -e`.
    (( RECURSION_DEPTH++ )) || true
    (( RECURSION_DEPTH > MAX_DEPTH_SEEN )) && MAX_DEPTH_SEEN=$RECURSION_DEPTH || true

    # Push this call's description onto the visible call stack
    CALL_STACK+=( "hanoi($n, $from_lbl -> $to_lbl)" )

    # =========================================================================
    # BASE CASE: n == 1
    # -----------------
    # We have exactly one disc to move and nowhere to recurse.
    # Just move it directly from SOURCE to DESTINATION and return.
    #
    # This is the "bottom" of the recursion — where the call stack
    # stops growing and begins to unwind back upward.
    # =========================================================================
    if (( n == 1 )); then
        # FIX BUG 1: Call pop without $(...) so the mutation stays in the
        # current shell.  Read the moved disc from the global $POPPED.
        pop "$from"
        local disc="$POPPED"
        push "$to" "$disc"
        (( MOVE_COUNT++ )) || true   # FIX BUG 2: guard increment

        if (( SKIP == 0 )); then
            render_frame "$from_lbl" "$to_lbl" "$disc"
            printf "  ${BR_YELLOW}${BOLD}BASE CASE${RESET}  hanoi(1)  "
            printf "disc ${DISC_COLOURS[$disc]}${BOLD}[%s]${RESET}  " "${DISC_LABELS[$disc]}"
            printf "${from_lbl}  -->  ${to_lbl}\n"
            printf "  ${DIM}The call stack unwinds from here.${RESET}\n"
            sleep "$DELAY"

            # Handle live keypresses during animation
            _check_key
        fi

        # Pop this frame off the visible call stack and decrement depth
        unset 'CALL_STACK[-1]'
        (( RECURSION_DEPTH-- )) || true   # FIX BUG 2: guard decrement
        return
    fi

    # =========================================================================
    # RECURSIVE CASE: n > 1
    #
    # Three steps.  Only step 2 touches the actual pegs directly.
    # Steps 1 and 3 are entirely handled by recursive calls.
    # =========================================================================

    # -------------------------------------------------------------------------
    # STEP 1: Move the top (n-1) discs  SOURCE -> AUXILIARY
    #
    # We "park" every disc above disc-n on the auxiliary peg.
    # Notice the role rotation: from->aux via to (to becomes the new aux).
    # -------------------------------------------------------------------------
    hanoi $(( n - 1 )) "$from" "$aux" "$to" "$from_lbl" "$aux_lbl" "$to_lbl"


    # -------------------------------------------------------------------------
    # STEP 2: Move disc n (the largest in this sub-problem)  SOURCE -> DEST
    #
    # Now that smaller discs are out of the way, we slide the big disc over.
    # This is the single "real move" at this recursion level.
    # FIX BUG 1: Use pop-without-subshell pattern.
    # -------------------------------------------------------------------------
    pop "$from"
    local disc="$POPPED"
    push "$to" "$disc"
    (( MOVE_COUNT++ )) || true   # FIX BUG 2: guard increment

    if (( SKIP == 0 )); then
        render_frame "$from_lbl" "$to_lbl" "$disc"
        printf "  ${BR_MAGENTA}${BOLD}LEVEL %-2d${RESET}  hanoi(%d)  " "$RECURSION_DEPTH" "$n"
        printf "disc ${DISC_COLOURS[$disc]}${BOLD}[%s]${RESET}  " "${DISC_LABELS[$disc]}"
        printf "${from_lbl}  -->  ${to_lbl}\n"
        printf "  ${DIM}Rebuilding the tower of %d discs on top next...${RESET}\n" $(( n - 1 ))
        sleep "$DELAY"

        _check_key
    fi


    # -------------------------------------------------------------------------
    # STEP 3: Move the (n-1) discs from AUXILIARY -> DESTINATION
    #
    # Now we rebuild the sub-tower on top of disc-n.
    # The auxiliary peg becomes the new source; the original source
    # becomes the new auxiliary (its role rotates again).
    # -------------------------------------------------------------------------
    hanoi $(( n - 1 )) "$aux" "$to" "$from" "$aux_lbl" "$to_lbl" "$from_lbl"


    # This frame is done — pop it and restore depth counter
    unset 'CALL_STACK[-1]'
    (( RECURSION_DEPTH-- )) || true   # FIX BUG 2: guard decrement
}

# =============================================================================
#  KEYBOARD HANDLER (non-blocking)
#  Called during animation pauses to allow speed/skip/quit controls.
# =============================================================================
_check_key() {
    local key=""
    IFS= read -r -s -n1 -t0.01 key 2>/dev/null || true
    case "$key" in
        q|Q) _exit_clean ;;
        s|S) SKIP=1 ;;
        +|=) DELAY=$(awk "BEGIN{d=$DELAY-0.05; print (d<0.01)?0.01:d}") ;;
        -)   DELAY=$(awk "BEGIN{d=$DELAY+0.05; print (d>2.0)?2.0:d}") ;;
    esac
}

# =============================================================================
#  CLEAN EXIT — restore terminal state before quitting
# =============================================================================
_exit_clean() {
    show_cursor
    printf "${RESET}\n"
    echo "  Exited at move ${MOVE_COUNT} of ${TOTAL_MOVES}."
    exit 0
}
trap _exit_clean INT TERM

# =============================================================================
#  INTRO SCREEN
# =============================================================================
intro_screen() {
    clear_screen
    printf "${BR_YELLOW}${BOLD}"
    cat <<'BANNER'

  +=======================================================================+
  |                                                                       |
  |      T O W E R   O F   H A N O I   --   R E C U R S I O N           |
  |      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~             |
  |                                                                       |
  |   Invented by Edouard Lucas, French mathematician, 1883.             |
  |                                                                       |
  |   Three pegs.  A tower of N discs.  Two immutable rules:             |
  |                                                                       |
  |       [1]  Move only ONE disc at a time.                             |
  |       [2]  Never place a LARGER disc on top of a SMALLER one.        |
  |                                                                       |
  |   Goal: move the entire tower from Peg A to Peg C.                   |
  |                                                                       |
  |   The recursive solution requires exactly  2^N - 1  moves.           |
  |   For N=64, that is 18,446,744,073,709,551,615 moves.                |
  |   At one move per second: approximately 585 billion years.           |
  |                                                                       |
  |   Controls during animation:                                         |
  |       [+] faster    [-] slower    [s] skip    [q] quit               |
  |                                                                       |
  +=======================================================================+

BANNER
    printf "${RESET}"
    printf "  ${BR_CYAN}Discs      : ${BR_WHITE}${BOLD}%d${RESET}\n" "$NUM_DISCS"
    printf "  ${BR_CYAN}Total moves: ${BR_WHITE}${BOLD}%d${RESET}\n" "$TOTAL_MOVES"
    printf "  ${BR_CYAN}Delay      : ${BR_WHITE}${BOLD}%.2f s${RESET}\n" "$DELAY"
    printf "  ${BR_CYAN}Call stack : ${BR_WHITE}${BOLD}%s${RESET}\n" "$(( SHOW_STACK ? 'visible' : 'hidden' ))"
    echo ""
    printf "  ${DIM}Press ENTER to begin...${RESET}"
    read -r
}

# =============================================================================
#  OUTRO SCREEN
# =============================================================================
outro_screen() {
    echo ""
    printf "${BR_GREEN}${BOLD}"
    echo "  +============================================================+"
    echo "  |  PUZZLE SOLVED                                             |"
    echo "  +------------------------------------------------------------+"
    printf "  |  %-58s|\n" "  Discs        : ${NUM_DISCS}"
    printf "  |  %-58s|\n" "  Moves made   : ${MOVE_COUNT}  (minimum possible: ${TOTAL_MOVES})"
    printf "  |  %-58s|\n" "  Formula      : 2^N - 1  =  2^${NUM_DISCS} - 1  =  ${TOTAL_MOVES}"
    printf "  |  %-58s|\n" "  Max depth    : ${MAX_DEPTH_SEEN} call frames"
    echo "  +------------------------------------------------------------+"
    echo "  |  RECURSION ANATOMY                                         |"
    echo "  |                                                            |"
    echo "  |  hanoi(n) makes TWO recursive calls:                      |"
    echo "  |      hanoi(n-1, source -> aux)    [step 1: clear path]    |"
    echo "  |      hanoi(n-1, aux   -> dest)    [step 3: rebuild]       |"
    echo "  |                                                            |"
    echo "  |  Base case: hanoi(1) = 1 direct move, no recursion.       |"
    echo "  |  Call tree: binary tree of depth N.                       |"
    echo "  |  Leaf count: 2^(N-1)  (each leaf = one base-case move)    |"
    echo "  |  Internal nodes: 2^(N-1) - 1  (each does 1 direct move)  |"
    echo "  |  Total: 2^(N-1) + 2^(N-1) - 1 = 2^N - 1  (QED)          |"
    echo "  |                                                            |"
    echo "  |  Space complexity: O(N) stack frames at any moment.       |"
    echo "  |  Time complexity : O(2^N) — irreducible lower bound.      |"
    echo "  +============================================================+"
    printf "${RESET}\n"
}

# =============================================================================
#  ARGUMENT PARSING
# =============================================================================
usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

  --discs  N     Number of discs to solve   (1-8,  default: 5)
  --delay  S     Seconds between moves      (0.0+, default: 0.30)
  --fast         Set delay to 0.05s
  --instant      Solve with no animation    (benchmark mode)
  --no-stack     Hide the call-stack panel
  --help         Show this message

Examples:
  $0 --discs 6
  $0 --discs 7 --fast
  $0 --discs 3 --delay 0.8
  $0 --discs 8 --instant

USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --discs)    NUM_DISCS="$2";   shift 2 ;;
        --delay)    DELAY="$2";       shift 2 ;;
        --fast)     DELAY=0.05;       shift 1 ;;
        --instant)  SKIP=1;           shift 1 ;;
        --no-stack) SHOW_STACK=0;     shift 1 ;;
        --help|-h)  usage ;;
        *) printf "Unknown option: %s\n" "$1"; usage ;;
    esac
done

# =============================================================================
#  INPUT VALIDATION
# =============================================================================
if ! [[ "$NUM_DISCS" =~ ^[0-9]+$ ]] || (( NUM_DISCS < 1 || NUM_DISCS > 8 )); then
    printf "${BR_RED}Error: --discs must be an integer between 1 and 8 (got: %s)${RESET}\n" "$NUM_DISCS"
    exit 1
fi

# =============================================================================
#  INITIALISE
#
#  ITERATION: the ONE explicit loop in the entire program.
#  Everything else is driven by recursion.
#
#  We push discs onto Peg A from LARGEST (N) to SMALLEST (1).
#  After the loop, PEG_A[-1] == 1 (smallest, on top).
#  PEG_A[0]  == NUM_DISCS (largest, at bottom).
# =============================================================================
TOTAL_MOVES=$(( (1 << NUM_DISCS) - 1 ))   # Bitshift: 2^N - 1

# ITERATIVE setup — the only loop in the whole program
# Fills the source peg from bottom (largest) to top (smallest)
for (( disc = NUM_DISCS; disc >= 1; disc-- )); do
    #
    # NOTE: This downward-counting loop is the only iteration.
    #       The entire solve is driven by hanoi() — pure recursion.
    #       disc=NUM_DISCS is the widest (base) disc.
    #       disc=1 is the narrowest (top) disc, pushed last.
    #
    push "PEG_A" "$disc"
done

# =============================================================================
#  MAIN
# =============================================================================
query_term_size
intro_screen
clear_screen
hide_cursor

# Show the initial state before solving
render_frame "" "" 0
printf "  ${DIM}Initial state: %d discs on peg A.  Starting recursion...${RESET}\n" "$NUM_DISCS"
sleep 1.0

# ─────────────────────────────────────────────────────────────────────────────
#  THE SINGLE ENTRY POINT INTO THE RECURSIVE ALGORITHM.
#
#  This one line call triggers a cascade of 2^N - 1 disc moves.
#  The recursion tree has depth N, branching factor 2.
#  Every path from root to leaf corresponds to moving one disc.
# ─────────────────────────────────────────────────────────────────────────────
hanoi "$NUM_DISCS"  "PEG_A"  "PEG_C"  "PEG_B"  "A"  "C"  "B"

# Show the final solved state
clear_screen
render_frame "" "" 0
outro_screen

show_cursor
