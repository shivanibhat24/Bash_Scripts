#!/bin/bash

# Git Automation Script
# Usage: ./gitauto.sh [commit message]
# This script automates git add, commit, and push in one command

# Set color codes for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check if we're in a git repository
check_git_repo() {
  if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo -e "${RED}Error: Not a git repository${NC}"
    echo "Please run this script from within a git repository."
    exit 1
  fi
}

# Function to show usage information
show_usage() {
  echo -e "${YELLOW}Git Automation Script${NC}"
  echo "Automates git add, commit, and push operations."
  echo
  echo "Usage:"
  echo "  $(basename "$0") [commit message]"
  echo
  echo "Examples:"
  echo "  $(basename "$0") \"Fix login bug\""
  echo "  $(basename "$0") \"Update README with installation instructions\""
}

# Main execution starts here
check_git_repo

# Check if commit message is provided
if [ $# -eq 0 ]; then
  echo -e "${RED}Error: No commit message provided${NC}"
  show_usage
  exit 1
fi

# Store the commit message from all arguments
COMMIT_MESSAGE="$*"

# Get current branch name
CURRENT_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null)
if [ $? -ne 0 ]; then
  echo -e "${RED}Error: Unable to determine current branch${NC}"
  exit 1
fi

# Display git status
echo -e "${YELLOW}Current status:${NC}"
git status -s

# Confirm with user
echo
echo -e "${YELLOW}About to perform the following actions:${NC}"
echo -e "1. Add all changes (git add .)"
echo -e "2. Commit with message: ${GREEN}\"$COMMIT_MESSAGE\"${NC}"
echo -e "3. Push to remote branch: ${GREEN}$CURRENT_BRANCH${NC}"
echo
read -p "Continue? (y/n): " CONFIRM

if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  # Execute git commands
  echo
  echo -e "${YELLOW}Adding all changes...${NC}"
  git add .
  
  echo -e "${YELLOW}Committing changes...${NC}"
  git commit -m "$COMMIT_MESSAGE"
  
  # Check if commit was successful
  if [ $? -ne 0 ]; then
    echo -e "${RED}Commit failed. Exiting without pushing.${NC}"
    exit 1
  fi
  
  echo -e "${YELLOW}Pushing to remote...${NC}"
  git push origin "$CURRENT_BRANCH"
  
  # Check push result
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Success! All changes have been added, committed, and pushed.${NC}"
  else
    echo -e "${RED}Push failed. Changes were committed but not pushed.${NC}"
    echo "You may need to manually run: git push origin $CURRENT_BRANCH"
    exit 1
  fi
else
  echo -e "${YELLOW}Operation cancelled.${NC}"
  exit 0
fi
