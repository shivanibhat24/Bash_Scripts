#!/bin/bash

# Simple CLI To-Do List Application
# Usage: ./todo.sh [add|remove|list|done] [task description/id]

TODO_FILE="$HOME/.todo.txt"

# Create the todo file if it doesn't exist
if [ ! -f "$TODO_FILE" ]; then
    touch "$TODO_FILE"
    echo "# ID,STATUS,DESCRIPTION" > "$TODO_FILE"
fi

# Function to display usage information
show_usage() {
    echo "Usage: $0 [command] [arguments]"
    echo "Commands:"
    echo "  add [task]     - Add a new task"
    echo "  list           - List all tasks"
    echo "  done [id]      - Mark a task as completed"
    echo "  remove [id]    - Remove a task"
    echo "  help           - Show this help message"
}

# Function to add a new task
add_task() {
    if [ -z "$1" ]; then
        echo "Error: Task description required"
        return 1
    fi
    
    # Count existing tasks to generate new ID
    task_count=$(grep -v "^#" "$TODO_FILE" | wc -l)
    new_id=$((task_count + 1))
    
    # Add new task with status "TODO"
    echo "$new_id,TODO,$*" >> "$TODO_FILE"
    echo "Task added: $*"
}

# Function to list all tasks
list_tasks() {
    if [ "$(grep -v "^#" "$TODO_FILE" | wc -l)" -eq 0 ]; then
        echo "No tasks found."
        return 0
    fi
    
    echo "ID | STATUS | DESCRIPTION"
    echo "-------------------------"
    
    # Skip the header line and format the output
    grep -v "^#" "$TODO_FILE" | while IFS="," read -r id status description; do
        if [ "$status" = "DONE" ]; then
            echo "$id | $status  | $description ✓"
        else
            echo "$id | $status | $description"
        fi
    done
}

# Function to mark a task as done
mark_done() {
    if [ -z "$1" ]; then
        echo "Error: Task ID required"
        return 1
    fi
    
    # Check if the ID exists
    if ! grep -q "^$1," "$TODO_FILE"; then
        echo "Error: Task ID $1 not found"
        return 1
    fi
    
    # Create a temporary file
    temp_file=$(mktemp)
    
    # Replace the status of the specified task
    awk -F, -v id="$1" 'BEGIN {OFS=","} {
        if ($1 == id && $2 == "TODO") {
            $2 = "DONE"
            print
        } else {
            print
        }
    }' "$TODO_FILE" > "$temp_file"
    
    # Replace the original file
    mv "$temp_file" "$TODO_FILE"
    echo "Task $1 marked as done"
}

# Function to remove a task
remove_task() {
    if [ -z "$1" ]; then
        echo "Error: Task ID required"
        return 1
    fi
    
    # Check if the ID exists
    if ! grep -q "^$1," "$TODO_FILE"; then
        echo "Error: Task ID $1 not found"
        return 1
    fi
    
    # Create a temporary file
    temp_file=$(mktemp)
    
    # Write header and all lines except the one to be removed
    grep "^#" "$TODO_FILE" > "$temp_file"
    grep -v -E "^($1,|#)" "$TODO_FILE" >> "$temp_file"
    
    # Replace the original file
    mv "$temp_file" "$TODO_FILE"
    echo "Task $1 removed"
}

# Main command handling
case "$1" in
    add)
        shift
        add_task "$*"
        ;;
    list)
        list_tasks
        ;;
    done)
        mark_done "$2"
        ;;
    remove)
        remove_task "$2"
        ;;
    help)
        show_usage
        ;;
    *)
        show_usage
        ;;
esac

exit 0
