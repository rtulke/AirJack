#!/usr/bin/env python3
"""
Terminal Color Palette Display
Shows all 256 terminal colors with their codes for background selection
"""

def show_256_colors():
    """Display all 256 colors available in terminal."""
    print("\n" + "="*80)
    print("256 TERMINAL COLORS - Background Mode (for selection highlighting)")
    print("="*80 + "\n")

    # Standard colors (0-15)
    print("Standard Colors (0-15):")
    print("-" * 80)
    for i in range(16):
        bg_code = f"\033[48;5;{i}m"
        reset = "\033[0m"
        # Use white or black text depending on background brightness
        fg_code = "\033[97m" if i < 8 else "\033[30m"

        print(f"{bg_code}{fg_code} Color {i:3d} {reset}", end="")
        if (i + 1) % 8 == 0:
            print()

    print("\n")

    # 216 colors (16-231) - 6x6x6 RGB cube
    print("RGB Color Cube (16-231):")
    print("-" * 80)
    for i in range(16, 232):
        bg_code = f"\033[48;5;{i}m"
        reset = "\033[0m"
        # Determine if we need light or dark text
        base = i - 16
        r = (base // 36) * 51
        g = ((base % 36) // 6) * 51
        b = (base % 6) * 51
        brightness = (r + g + b) / 3
        fg_code = "\033[97m" if brightness < 128 else "\033[30m"

        print(f"{bg_code}{fg_code} {i:3d} {reset}", end="")
        if (i - 15) % 12 == 0:
            print()

    print("\n")

    # Grayscale (232-255)
    print("Grayscale (232-255):")
    print("-" * 80)
    for i in range(232, 256):
        bg_code = f"\033[48;5;{i}m"
        reset = "\033[0m"
        # Lighter backgrounds need dark text
        fg_code = "\033[97m" if i < 244 else "\033[30m"

        print(f"{bg_code}{fg_code} {i:3d} {reset}", end="")
        if (i - 231) % 12 == 0:
            print()

    print("\n")


def show_recommended_for_selection():
    """Show recommended colors for selection highlighting."""
    print("="*80)
    print("RECOMMENDED COLORS FOR SELECTION HIGHLIGHTING")
    print("="*80 + "\n")

    recommended = [
        (234, "Very Dark Gray (almost black)"),
        (235, "Dark Gray (current)"),
        (236, "Medium Dark Gray"),
        (237, "Medium Gray"),
        (238, "Light Gray"),
        (17, "Dark Blue"),
        (18, "Blue"),
        (22, "Dark Green"),
        (23, "Green"),
        (52, "Dark Red/Wine"),
        (53, "Dark Magenta"),
        (58, "Brown/Orange"),
    ]

    sample_text = "Sample selected line with BSSID: AA:BB:CC:DD:EE:FF  RSSI: -45dBm  SSID: MyNetwork"

    for color_code, description in recommended:
        bg_code = f"\033[48;5;{color_code}m"
        reset = "\033[0m"

        # Show with colorful text to simulate actual output
        print(f"\nColor {color_code:3d} - {description}:")
        print(f"{bg_code}{sample_text}{reset}")


def show_rgb_examples():
    """Show examples of custom RGB background colors."""
    print("\n" + "="*80)
    print("CUSTOM RGB BACKGROUND COLORS")
    print("="*80 + "\n")
    print("Format: \\033[48;2;R;G;Bm where R,G,B are 0-255\n")

    rgb_examples = [
        ((40, 40, 60), "Dark Blue-Gray"),
        ((30, 50, 30), "Dark Green"),
        ((50, 30, 30), "Dark Red"),
        ((40, 40, 40), "Dark Gray"),
        ((50, 50, 50), "Medium Gray"),
        ((30, 40, 50), "Dark Slate Blue"),
        ((45, 35, 25), "Dark Brown"),
    ]

    sample_text = "Sample selected line with BSSID: AA:BB:CC:DD:EE:FF  RSSI: -45dBm  SSID: MyNetwork"

    for (r, g, b), description in rgb_examples:
        bg_code = f"\033[48;2;{r};{g};{b}m"
        reset = "\033[0m"

        print(f"RGB({r:3d},{g:3d},{b:3d}) - {description}:")
        print(f'{bg_code}{sample_text}{reset}')
        print(f'Code: "\\033[48;2;{r};{g};{b}m"\n')


def main():
    """Main function."""
    print("\n" + "█"*80)
    print("█" + " "*78 + "█")
    print("█" + " "*25 + "TERMINAL COLOR PALETTE" + " "*32 + "█")
    print("█" + " "*78 + "█")
    print("█"*80)

    show_256_colors()
    show_recommended_for_selection()
    show_rgb_examples()

    print("\n" + "="*80)
    print("USAGE IN CODE:")
    print("="*80)
    print('bg_highlight = "\\033[48;5;235m"  # 256-color mode (replace 235 with desired color)')
    print('bg_highlight = "\\033[48;2;40;40;60m"  # RGB mode (R=40, G=40, B=60)')
    print('bg_reset = "\\033[49m"  # Reset background to default')
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
