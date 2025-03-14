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

# Install zizzania
install_zizzania() {
    if ask_continue "Install zizzania (required for handshake capture)?"; then
        print_message "Installing zizzania dependencies..."
        brew install --formula cmake libpcap
        
        # Set up environment for zizzania compilation
        export LDFLAGS="-L$(brew --prefix libpcap)/lib"
        export CPPFLAGS="-I$(brew --prefix libpcap)/include"
        export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig"
        
        print_message "Cloning zizzania repository..."
        if [ -d ~/zizzania ]; then
            print_warning "Zizzania directory already exists at ~/zizzania."
            if ask_continue "Re-install zizzania?"; then
                rm -rf ~/zizzania
                git clone https://github.com/cyrus-and/zizzania.git ~/zizzania
            fi
        else
            git clone https://github.com/cyrus-and/zizzania.git ~/zizzania
        fi
        
        if [ -d ~/zizzania ]; then
            cd ~/zizzania
            print_message "Configuring zizzania..."
            
            # Check for different build systems
            if [ -f "CMakeLists.txt" ]; then
                mkdir -p build
                cd build
                cmake ..
                print_message "Compiling zizzania..."
                make
                print_success "Zizzania installed at ~/zizzania/build"
            elif [ -f "Makefile" ]; then
                print_message "Compiling zizzania..."
                make
                print_success "Zizzania installed at ~/zizzania"
            elif [ -f "config.Makefile" ]; then
                print_message "Using config.Makefile..."
                cp config.Makefile Makefile
                print_message "Compiling zizzania..."
                make
                print_success "Zizzania installed at ~/zizzania"
            else
                print_message "Manual build required. Attempting autogen/configure..."
                if [ -f "autogen.sh" ]; then
                    ./autogen.sh
                    ./configure
                    make
                    print_success "Zizzania installed at ~/zizzania"
                else
                    print_error "No build system detected. Check the README in ~/zizzania"
                    return 1
                fi
            fi
        else
            print_error "Failed to install zizzania."
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
            python3 -m pip install prettytable pyfiglet
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
        
        print_message "Creating default configuration file..."
        cd "$TEMP_DIR"
        python3 airjack.py -C "$CONFIG_DIR/airjack.conf"
        
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

# Final cleanup
cleanup() {
    print_message "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    print_success "Cleanup complete."
}

# Main installer function
main() {
    print_message "AirJack Installer"
    print_message "================="
    echo ""
    
    # Check system
    check_macos
    
    # Dependencies
    setup_homebrew
    install_python
    install_tools
    install_zizzania
    
    # Download and install AirJack
    clone_repo
    install_python_deps
    setup_config
    install_manpage
    install_script
    
    # Cleanup
    cleanup
    
    echo ""
    print_success "AirJack installation complete!"
    print_message "You can now run 'AirJack' from anywhere."
    print_message "For help, run 'AirJack --help' or 'man airjack'"
}

main "$@"
