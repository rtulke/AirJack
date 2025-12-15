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
REPO_URL="https://github.com/rtulke/airjack.git"

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to get the full path of a command
get_command_path() {
    command -v "$1"
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
            print_message "Cloning AirJack repo to build zizzania..."
            git clone https://github.com/rtulke/AirJack.git "$TEMP_DIR/zizzania"
            SRC_DIR="$TEMP_DIR/zizzania/zizzania"
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

# Install AirSnare
install_airsnare() {
    if ask_continue "Install AirSnare - required for handshake capture?"; then
        print_message "Installing AirSnare dependencies..."
        brew install --formula cmake libpcap wget
        
        # Set up environment for AirSnare compilation
        export LDFLAGS="-L$(brew --prefix libpcap)/lib"
        export CPPFLAGS="-I$(brew --prefix libpcap)/include"
        export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig"
        
        print_message "Cloning AirSnare repository..."
        if [ -d ~/airsnare ]; then
            print_warning "AirSnare directory already exists at ~/airsnare."
            if ask_continue "Re-install AirSnare?"; then
                rm -rf ~/airsnare
                git clone https://github.com/rtulke/airsnare.git ~/airsnare
            fi
        else
            git clone https://github.com/rtulke/airsnare.git ~/airsnare
        fi
        
        if [ -d ~/airsnare ]; then
            cd ~/airsnare
            print_message "Configuring AirSnare..."
            
            # Check for different build systems
            if [ -f "CMakeLists.txt" ]; then
                mkdir -p build
                cd build
                cmake ..
                print_message "Compiling AirSnare..."
                make
                print_success "AirSnare installed at ~/airesnare/build"
                AIRSNARE_PATH="$HOME/airesnare/build/airesnare"
            elif [ -f "Makefile" ]; then
                print_message "Compiling airesnare..."
                make
                make install
                print_success "AirSnare installed at ~/airesnare"
                AIRSNARE_PATH="$HOME/airesnare/src/airesnare"
            elif [ -f "config.Makefile" ]; then
                print_message "Using config.Makefile..."
                make -f config.Makefile
                print_message "Compiling AirSnare..."
                make
                print_success "AirSnare installed at ~/airesnare"
                AIRSNARE_PATH="$HOME/airesnare/src/airesnare"
            else
                print_message "Manual build required. Attempting autogen/configure..."
                if [ -f "autogen.sh" ]; then
                    ./autogen.sh
                    ./configure
                    make
                    print_success "AirSnare installed at ~/airesnare"
                    AIRSNARE_PATH="$HOME/airesnare/src/airesnare"
                else
                    print_error "No build system detected. Check the README in ~/airesnare"
                    return 1
                fi
            fi
            
            # Configure sudo permissions for AirSnare
            if ask_continue "Configure sudo to allow passwordless execution of AirSnare?"; then
                print_message "Setting up sudo permissions for AirSnare..."
                
                # Determine current username
                CURRENT_USER=$(whoami)
                
                # Verify AirSnare path
                if [ ! -x "$AIRSNARE_PATH" ]; then
                    print_warning "AirSnare not found at $AIRSNARE_PATH, trying to locate it..."
                    if [ -x "$HOME/airsnare/build/airsnare" ]; then
                        AIRSNARE_PATH="$HOME/airsnare/build/airsnare"
                    elif [ -x "$HOME/airsnare/src/airsnare" ]; then
                        AIRSNARE_PATH="$HOME/airsnare/src/airsnare"
                    else
                        print_error "Cannot find AirSnare executable"
                        return 1
                    fi
                fi
                
                print_message "Using AirSnare path: $AIRSNARE_PATH"
                
                # Create a temporary sudoers file
                SUDOERS_TMP=$(mktemp)
                echo "$CURRENT_USER ALL=(ALL) NOPASSWD: $AIRSNARE_PATH" > "$SUDOERS_TMP"
                
                # Validate the syntax
                visudo -cf "$SUDOERS_TMP"
                if [ $? -ne 0 ]; then
                    print_error "Invalid sudoers syntax"
                    rm -f "$SUDOERS_TMP"
                    return 1
                fi
                
                # Add to sudoers.d directory
                sudo mkdir -p /etc/sudoers.d
                sudo cp "$SUDOERS_TMP" /etc/sudoers.d/airsnare
                sudo chmod 0440 /etc/sudoers.d/airsnare
                rm -f "$SUDOERS_TMP"
                
                print_success "Sudo permissions configured for $AIRSNARE_PATH"
            fi
        else
            print_error "Failed to install AirSnare."
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
        print_message "Creating virtual environment..."
        python3 -m venv "$TEMP_DIR/venv"
        source "$TEMP_DIR/venv/bin/activate"
        
        print_message "Installing Python dependencies in virtual environment..."
        if [ -f "$TEMP_DIR/requirements.txt" ]; then
            python3 -m pip install -r "$TEMP_DIR/requirements.txt"
            print_success "Python dependencies installed."
        else
            print_warning "requirements.txt not found. Installing manually..."
            python3 -m pip install prettytable pyfiglet pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
        fi
        
        # Deactivate virtual environment
        deactivate
    fi
}

# Create configuration directory and install config file
setup_config() {
    if ask_continue "Create configuration files?"; then
        print_message "Creating configuration directory (administrator password required)..."
        sudo mkdir -p "$CONFIG_DIR"
        
        # Create virtual environment in user home
        VENV_PATH="$HOME/.airjack/venv"
        print_message "Creating virtual environment in $VENV_PATH..."
        mkdir -p "$(dirname "$VENV_PATH")"
        python3 -m venv "$VENV_PATH"
        source "$VENV_PATH/bin/activate"
        python3 -m pip install prettytable pyfiglet pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
        
        # Use sudo to run the python script for system config
        print_message "Creating default configuration file (administrator password may be required)..."
        cd "$TEMP_DIR"
        # Make sure the script runs with the virtual environment's Python
        sudo "$VENV_PATH/bin/python3" airjack.py -C "$CONFIG_DIR/airjack.conf"
        
        # Also create user config
        if ask_continue "Create user-specific configuration?"; then
            python3 airjack.py -C ~/.airjack.conf
            print_success "User configuration created at ~/.airjack.conf"
        fi
        
        # Deactivate virtual environment
        deactivate
        
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
        print_message "Installing AirJack script..."
        sudo mkdir -p "$INSTALL_DIR"
        
        # Make sure the script is executable
        chmod +x "$TEMP_DIR/airjack.py"
        
        # Create a launcher script without .py extension
        cat > "$TEMP_DIR/airjack" << EOF
#!/bin/bash
# Check if we need to set up virtual environment
VENV_PATH="\$HOME/.airjack/venv"
if [ ! -d "\$VENV_PATH" ]; then
    echo "Setting up virtual environment..."
    mkdir -p "\$(dirname "\$VENV_PATH")"
    python3 -m venv "\$VENV_PATH"
    source "\$VENV_PATH/bin/activate"
    python3 -m pip install prettytable pyfiglet pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
    deactivate
fi

# Activate virtual environment and run script
source "\$VENV_PATH/bin/activate"
python3 $INSTALL_DIR/airjack.py "\$@"
deactivate
EOF
        
        # Make the launcher executable
        chmod +x "$TEMP_DIR/airjack"
        
        # Install both scripts
        sudo cp "$TEMP_DIR/airjack.py" "$INSTALL_DIR/"
        sudo cp "$TEMP_DIR/airjack" "$INSTALL_DIR/"
        
        print_success "AirJack installed at $INSTALL_DIR/airjack"
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
        sudo rm -f "$INSTALL_DIR/airjack.py" "$INSTALL_DIR/AirJack"
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
