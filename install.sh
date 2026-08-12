#!/bin/bash

# AirJack Installer Script
# This script installs AirJack and its dependencies on macOS

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/etc/airjack"
MAN_DIR="/usr/local/share/man/man1"
TEMP_DIR=$(mktemp -d)
REPO_URL="https://github.com/rtulke/AirJack.git"

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to get the full path of a command
get_command_path() {
    command -v "$1"
}

# Determine the Python interpreter the 'airjack' launcher will actually use.
# Mirrors airjack's own logic: system Python on macOS 15+ (required for
# Location Services), otherwise the default python3 on PATH.
get_target_python() {
    local macos_major
    macos_major=$(sw_vers -productVersion | cut -d. -f1)
    if [ "$macos_major" -ge 15 ] && command -v /usr/bin/python3 &> /dev/null; then
        echo "/usr/bin/python3"
    else
        echo "python3"
    fi
}

# Install one or more pip packages for the given interpreter, tolerating
# PEP 668 "externally managed" environments.
pip_install_for() {
    local py=$1; shift
    "$py" -m pip install --user "$@" \
        || "$py" -m pip install --user --break-system-packages "$@"
}

# Function to print colored messages
print_message() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to ask for confirmation
ask_continue() {
    local message=$1
    local default=${2:-y}
    local options="y/n/c/f"
    local prompt
    
    if [ "$default" = "y" ]; then
        prompt="[Y/n/c/f]"
    elif [ "$default" = "n" ]; then
        prompt="[y/N/c/f]"
    else
        prompt="[y/n/c/f]"
    fi
    
    while true; do
        echo -e "${BLUE}==>${NC} ${message} ${prompt}: "
        read -r answer
        answer=${answer:-$default}
        
        case ${answer:0:1} in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            c|C) print_warning "Installation cancelled by user"; exit 1 ;;
            f|F) print_warning "Skipping but continuing..."; return 2 ;;
            *) echo "Please answer y (yes), n (no), c (cancel), or f (forward/next)." ;;
        esac
    done
}

# Check if running on macOS
check_macos() {
    if [ "$(uname)" != "Darwin" ]; then
        print_error "This script is for macOS only."
        exit 1
    fi
    print_success "Running on macOS $(sw_vers -productVersion)"
}

# Check if Homebrew is installed, install if not
setup_homebrew() {
    if ! command -v brew &> /dev/null; then
        if ask_continue "Homebrew is not installed. Install now?"; then
            print_message "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            if [ -f ~/.zshrc ]; then
                echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
                eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [ -f ~/.bash_profile ]; then
                echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.bash_profile
                eval "$(/opt/homebrew/bin/brew shellenv)"
            fi
        else
            print_error "Homebrew is required for installing dependencies."
            exit 1
        fi
    else
        print_success "Homebrew is already installed."
    fi
}

# Install Python and pip if needed
install_python() {
    if ask_continue "Install/update Python?"; then
        print_message "Installing Python..."
        if brew list python &> /dev/null; then
            brew upgrade python || true
        else
            brew install python
        fi
        print_success "Python installed."
    else
        if ! command -v python3 &> /dev/null; then
            print_error "Python is required but not installed. Installation cannot continue."
            exit 1
        fi
    fi
}

# Install required tools via Homebrew
install_tools() {
    if ask_continue "Install required tools (hashcat, hcxtools)?"; then
        print_message "Installing hashcat..."
        if brew list hashcat &> /dev/null; then
            brew upgrade hashcat || true
        else
            brew install hashcat
        fi
        
        print_message "Installing hcxtools..."
        if brew list hcxtools &> /dev/null; then
            brew upgrade hcxtools || true
        else
            brew install hcxtools
        fi
        
        print_success "Tools installed successfully."
    fi
}

# Install zizzania (capture backend)
install_zizzania() {
    if ask_continue "Install zizzania (capture backend)?"; then
        print_message "Installing zizzania dependencies (libpcap)..."
        brew install libpcap wget || true

        # Determine source directory (prefer existing repo clone if present)
        SRC_DIR=""
        if [ -d "$TEMP_DIR/zizzania/src" ]; then
            SRC_DIR="$TEMP_DIR/zizzania"
        elif [ -d "$HOME/zizzania/src" ]; then
            SRC_DIR="$HOME/zizzania"
        else
            print_message "Cloning zizzania..."
            git clone https://github.com/cyrus-and/zizzania.git "$TEMP_DIR/zizzania"
            SRC_DIR="$TEMP_DIR/zizzania"
        fi

        if [ ! -d "$SRC_DIR/src" ]; then
            print_error "Could not find zizzania sources."
            return 1
        fi

        print_message "Building zizzania..."
        if [ -f "$SRC_DIR/config.Makefile" ]; then
            make -C "$SRC_DIR" -f config.Makefile
        fi
        make -C "$SRC_DIR"

        ZIZZANIA_PATH="$SRC_DIR/src/zizzania"
        if [ -x "$ZIZZANIA_PATH" ]; then
            print_success "zizzania built at $ZIZZANIA_PATH"
        else
            print_error "Failed to build zizzania."
        fi
    fi
}

# Install AirSnare via Homebrew tap
install_airsnare() {
    if ask_continue "Install AirSnare - required for handshake capture?"; then
        print_message "Installing AirSnare via Homebrew tap..."
        brew tap rtulke/airsnare
        if brew list airsnare &> /dev/null; then
            brew upgrade airsnare || true
        else
            brew install airsnare
        fi

        AIRSNARE_PATH="$(brew --prefix airsnare)/bin/airsnare"
        if [ -x "$AIRSNARE_PATH" ]; then
            print_success "AirSnare installed at $AIRSNARE_PATH"
        else
            print_error "AirSnare installation failed."
            return 1
        fi
    fi
}

# Clone AirJack repository
clone_repo() {
    if ask_continue "Download AirJack?"; then
        print_message "Cloning AirJack repository to temporary directory..."
        cd "$TEMP_DIR"
        git clone "$REPO_URL" .
        print_success "Repository cloned successfully."
    else
        print_error "Cannot continue without AirJack source code."
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    if ask_continue "Install Python dependencies?"; then
        local py; py=$(get_target_python)
        print_message "Installing Python dependencies for $py ..."
        # macOS 15+ breaks Location Services inside a virtualenv, so the launcher
        # uses system Python; install the dependencies for that same interpreter.
        if [ -f "$TEMP_DIR/requirements.txt" ]; then
            pip_install_for "$py" -r "$TEMP_DIR/requirements.txt"
        else
            print_warning "requirements.txt not found. Installing manually..."
            pip_install_for "$py" prettytable pyfiglet pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
        fi
        print_success "Python dependencies installed for $py."
    fi
}

# Create configuration directory and install config file
setup_config() {
    if ask_continue "Create configuration files?"; then
        local py; py=$(get_target_python)
        cd "$TEMP_DIR"

        # Generate the config as the normal user so the target interpreter's
        # --user site-packages are visible (running under sudo would not see
        # them). The system copy is then installed with a plain sudo cp.
        print_message "Creating default user configuration at ~/.airjack.conf ..."
        "$py" airjack.py -C "$HOME/.airjack.conf"
        print_success "User configuration created at ~/.airjack.conf"

        if ask_continue "Also install a system-wide config to $CONFIG_DIR?"; then
            print_message "Installing system configuration (administrator password required)..."
            sudo mkdir -p "$CONFIG_DIR"
            sudo cp "$HOME/.airjack.conf" "$CONFIG_DIR/airjack.conf"
            print_success "System configuration installed at $CONFIG_DIR/airjack.conf"
        fi

        print_success "Configuration set up successfully."
    fi
}

# Install the man page
install_manpage() {
    if ask_continue "Install man page?"; then
        print_message "Installing man page..."
        sudo mkdir -p "$MAN_DIR"
        
        if [ -f "$TEMP_DIR/airjack.1" ]; then
            sudo cp "$TEMP_DIR/airjack.1" "$MAN_DIR/"
            
            # Update man database
            if command -v mandb &> /dev/null; then
                sudo mandb
            elif command -v makewhatis &> /dev/null; then
                sudo makewhatis
            fi
            
            print_success "Man page installed. Use 'man airjack' to view."
        else
            print_warning "Man page not found in repository."
        fi
    fi
}

# Install the main script
install_script() {
    if ask_continue "Install AirJack script to $INSTALL_DIR?"; then
        print_message "Installing AirJack script and launcher..."
        sudo mkdir -p "$INSTALL_DIR"

        chmod +x "$TEMP_DIR/airjack.py"
        sudo cp "$TEMP_DIR/airjack.py" "$INSTALL_DIR/"

        # Install the launcher shipped with the repo. It selects system Python on
        # macOS 15+ (required for Location Services) and falls back to python3
        # otherwise - do NOT regenerate a venv-based launcher here, which would
        # reintroduce the Location Services failure on macOS 15+.
        if [ -f "$TEMP_DIR/airjack" ]; then
            chmod +x "$TEMP_DIR/airjack"
            sudo cp "$TEMP_DIR/airjack" "$INSTALL_DIR/"
            print_success "AirJack installed at $INSTALL_DIR/airjack"
        else
            print_warning "Launcher 'airjack' not found in repo; installed airjack.py only."
            print_message "Run it directly with: /usr/bin/python3 $INSTALL_DIR/airjack.py"
        fi
    fi
}

# Check and set correct tool paths
detect_tool_paths() {
    print_message "Detecting installed tools..."
    
    # Find hashcat
    if command_exists hashcat; then
        HASHCAT_PATH=$(get_command_path hashcat)
        print_success "Found hashcat at: $HASHCAT_PATH"
    else
        HASHCAT_PATH="$HOME/hashcat/hashcat"
        print_warning "Hashcat not found in PATH, will use default: $HASHCAT_PATH"
    fi
    
    # Find AirSnare
    if [ -x "$HOME/airsnare/build/airsnare" ]; then
        AIRSNARE_PATH="$HOME/airsnare/build/airsnare"
        print_success "Found airsnare at: $AIRSNARE_PATH"
    elif [ -x "$HOME/airsnare/src/airsnare" ]; then
        AIRSNARE_PATH="$HOME/airsnare/src/airsnare"
        print_success "Found AirSnare at: $AIRSNARE_PATH"
    else
        AIRSNARE_PATH="$HOME/airsnare/src/airsnare"
        print_warning "AirSnare not found, will use default: $AIRSNARE_PATH"
    fi

    # Find zizzania
    if [ -x "$HOME/zizzania/src/zizzania" ]; then
        ZIZZANIA_PATH="$HOME/zizzania/src/zizzania"
        print_success "Found zizzania at: $ZIZZANIA_PATH"
    elif [ -x "$TEMP_DIR/zizzania/src/zizzania" ]; then
        ZIZZANIA_PATH="$TEMP_DIR/zizzania/src/zizzania"
        print_success "Found zizzania at: $ZIZZANIA_PATH"
    else
        ZIZZANIA_PATH="$HOME/zizzania/src/zizzania"
        print_warning "zizzania not found, will use default: $ZIZZANIA_PATH"
    fi

    # Decide capture tool preference
    if [ -x "$ZIZZANIA_PATH" ]; then
        CAPTURE_TOOL="zizzania"
    elif [ -x "$AIRSNARE_PATH" ]; then
        CAPTURE_TOOL="airsnare"
    else
        CAPTURE_TOOL="airsnare"
    fi
    
    # Update configuration with correct paths
    if [ -f "$HOME/.airjack.conf" ]; then
        print_message "Updating paths in user configuration..."
        # Create temporary file
        local temp_file=$(mktemp)
        
        # Read the file line by line
        while IFS= read -r line; do
            # Check if the line contains hashcat_path or AirSnare_path
            if [[ $line == hashcat_path* ]]; then
                echo "hashcat_path = $HASHCAT_PATH" >> "$temp_file"
            elif [[ $line == airsnare_path* ]]; then
                echo "airsnare_path = $AIRSNARE_PATH" >> "$temp_file"
            elif [[ $line == zizzania_path* ]]; then
                echo "zizzania_path = $ZIZZANIA_PATH" >> "$temp_file"
            elif [[ $line == capture_tool* ]]; then
                echo "capture_tool = $CAPTURE_TOOL" >> "$temp_file"
            else
                echo "$line" >> "$temp_file"
            fi
        done < "$HOME/.airjack.conf"
        
        # Replace the original file with the modified one
        mv "$temp_file" "$HOME/.airjack.conf"
        print_success "Configuration updated with correct tool paths."
    fi
}

# Function to uninstall AirJack
uninstall() {
    print_message "Uninstalling AirJack"
    print_message "===================="
    echo ""
    
    if ask_continue "Remove AirJack script from $INSTALL_DIR?"; then
        sudo rm -f "$INSTALL_DIR/airjack.py" "$INSTALL_DIR/airjack"
        print_success "Removed AirJack scripts"
    fi
    
    if ask_continue "Remove AirJack configuration?"; then
        sudo rm -rf "$CONFIG_DIR"
        rm -f "$HOME/.airjack.conf"
        print_success "Removed AirJack configuration"
    fi
    
    if ask_continue "Remove AirJack man page?"; then
        sudo rm -f "$MAN_DIR/airjack.1"
        
        # Update man database
        if command -v mandb &> /dev/null; then
            sudo mandb
        elif command -v makewhatis &> /dev/null; then
            sudo makewhatis
        fi
        
        print_success "Removed AirJack man page"
    fi
    
    if ask_continue "Remove Python virtual environment?"; then
        rm -rf "$HOME/.airjack/venv"
        print_success "Removed Python virtual environment"
    fi
    
    if ask_continue "Remove AirSnare?"; then
        rm -rf "$HOME/airsnare"
        print_success "Removed AirSnare"
    fi
    
    echo ""
    print_success "AirJack uninstallation complete!"
    return 0
}

# Final cleanup
cleanup() {
    print_message "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    print_success "Cleanup complete."
}

# Function to display usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -U, --uninstall         Uninstall AirJack"
    echo "  -SI, --setup COMPONENT  Install specific component(s)"
    echo ""
    echo "Components for --setup:"
    echo "  homebrew    Install Homebrew"
    echo "  python      Install/update Python"
    echo "  tools       Install hashcat and hcxtools"
    echo "  airsnare    Install AirSnare"
    echo "  zizzania    Install zizzania (capture backend alternative)"
    echo "  repo        Download AirJack repository"
    echo "  python_deps Install Python dependencies"
    echo "  config      Create configuration files"
    echo "  manpage     Install man page"
    echo "  script      Install AirJack script"
    echo "  all         Install everything (default)"
    echo ""
}

# Main installer function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -U|--uninstall)
                uninstall
                exit $?
                ;;
            -SI|--setup)
                if [[ -z $2 ]]; then
                    print_error "Missing component for --setup"
                    show_usage
                    exit 1
                fi
                SETUP_COMPONENT=$2
                shift # Remove argument name
                shift # Remove argument value
                ;;
            *)
                # Unknown option
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_message "AirJack Installer"
    print_message "================="
    echo ""
    
    # Check system
    check_macos
    
    # Check if we're in setup mode
    if [[ -n $SETUP_COMPONENT ]]; then
        case $SETUP_COMPONENT in
            homebrew)
                setup_homebrew
                ;;
            python)
                install_python
                ;;
            tools)
                setup_homebrew
                install_tools
                ;;
            airsnare)
                setup_homebrew
                install_airsnare
                ;;
            zizzania)
                setup_homebrew
                install_zizzania
                ;;
            repo)
                clone_repo
                ;;
            python_deps)
                install_python_deps
                ;;
            config)
                setup_config
                ;;
            manpage)
                install_manpage
                ;;
            script)
                install_script
                detect_tool_paths
                ;;
            all)
                # Dependencies
                setup_homebrew
                install_python
                install_tools
                install_airsnare
                
                # Download and install AirJack
                clone_repo
                install_zizzania
                install_python_deps
                setup_config
                install_manpage
                install_script
                detect_tool_paths
                ;;
            *)
                print_error "Unknown component: $SETUP_COMPONENT"
                show_usage
                exit 1
                ;;
        esac
    else
        # Run full installation
        
        # Dependencies
        setup_homebrew
        install_python
        install_tools
        install_airsnare
        
        # Download and install AirJack
        clone_repo
        install_zizzania
        install_python_deps
        setup_config
        install_manpage
        install_script
        detect_tool_paths
    fi
    
    # Cleanup
    cleanup
    
    echo ""
    print_success "AirJack installation complete!"
    print_message "You can now run 'airjack' from anywhere."
    print_message "For help, run 'airjack --help' or 'man airjack'"
}

main "$@"
