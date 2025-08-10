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
TOTAL_STEPS=9

# Header
show_header() {
    clear
    echo "${BOLD}Hypersecure Shell Installer${RESET}"
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
        #exit 1
    fi
    echo "Status: ${GREEN}Success${RESET}"
}

install_dependencies() {
    run_command \
        "sudo apt update && sudo apt upgrade -y" \
        "Update & Upgrade this System..." \
        2
    run_command \
        "sudo apt install -y cmake build-essential libssl-dev libffi-dev python3-dev" \
        "Installing system packages..." \
        3
    run_command \
        "sudo apt install git" \
        "Installing git..." \
        4
    run_command \
        "git clone https://github.com/open-quantum-safe/liboqs-python.git" \
        "Installing Open-Quantum-Safe..." \
        5
    run_command \
        "pip install liboqs-python/" \
        "Installing Open-Quantum-Safe Cryptography..." \
        6
    run_command \
        "python3 .hardcfg/check_oqs.py" \
        "Configuring OQS Import System" \
        7
    run_command \
        "pip install cryptography pycryptodome" \
        "Installing Cryptography Libraries" \
        8
    run_command \
        "chmod +x update.sh && chmod +x uninstall.sh && chmod +x hss.py" \
        "Setting up..." \
        9
}

show_success() {
    local end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))

    echo "${GREEN}${BOLD}Installation Completed Successfully!${RESET}"
    echo "• Total time: ${elapsed} seconds"
    echo "Run command.'./hss.py server' to begin HSS server"
}

main() {
    show_header
    system_check
    install_dependencies
    show_success
}

main "$@"
