#!/bin/bash
### Basic installation for common environment ###
# ============================================
# Hypersecure Shell Installer
# ============================================

# Colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
RESET=$(tput sgr0)

# Global variables
START_TIME=$(date +%s)
TOTAL_STEPS=2

# Header
show_header() {
    clear
    echo "${BOLD}Easy Shell Installer Console${RESET}"
    echo "================================"
    echo
}

# Status
show_status() {
    local step=$1
    local total=$2
    local message=$3
    printf "${GREEN}${BOLD}[%d/%d]${RESET} %s\n" "$step" "$total" "$message"
}

# Diagnose
system_check() {
    show_status 1 "$TOTAL_STEPS" "System Check"

    # Check Python ????
    if ! command -v python3 &> /dev/null; then
        echo "${RED}${BOLD}ERROR: Python3 not found!${RESET}"
        echo "Please install Python3 first."
        exit 1
    fi

    # Check pip ???
    if ! command -v pip &> /dev/null; then
        echo "${RED}${BOLD}ERROR: pip not found!${RESET}"
        echo "Please install pip first."
        exit 1
    fi

    echo "Check passed."
}

run_command() {
    local cmd="$1"
    local step_msg="$2"
    local step_num="$3"

    show_status "$step_num" "$TOTAL_STEPS" "$step_msg"
    echo "CMD: $cmd"
    if ! eval "$cmd"; then
        echo "${RED}${BOLD}ERROR: Operation failed${RESET}"
        exit 1
    fi
    echo "Status: ${GREEN}Success${RESET}"
}

install_dependencies() {
    run_command \
        "sudo apt update && sudo apt upgrade -y" \
        "Update & Upgrade this System..." \
        1
    run_command \
        "chmod +x update.sh && chmod +x uninstall.sh && chmod +x ezsh.py" \
        "Setting up..." \
        2
}

show_success() {
    local end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))

    echo "${GREEN}${BOLD}Installation Completed Successfully!${RESET}"
    echo "• Total time: ${elapsed} seconds"
    echo "Run command.'./ezsh.py server' to begin EZSH server"
}

main() {
    show_header
    system_check
    install_dependencies
    show_success
}

main "$@"
