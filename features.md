# AirDetect - Feature Ideas & Roadmap

This document contains feature ideas and potential improvements for AirDetect.

## 1. Performance & UI Improvements

### Export Function
- **Description**: Export AP list to various formats
- **Key**: `e` for export
- **Formats**: CSV, JSON, TXT
- **Data**: BSSID, SSID, RSSI, Channel, Security, Vendor, etc.
- **Use Case**: Data analysis, reporting, documentation

### Filter Function
- **Description**: Filter displayed APs by criteria
- **Key**: `f` for filter
- **Filter Options**:
  - SSID (text search)
  - Vendor (text search)
  - Security type (WPA2, WPA3, Open, etc.)
  - Channel range
  - Signal strength (RSSI threshold)
- **Implementation**: Popup with filter options, checkboxes and text input

### Advanced Sorting
- **Description**: Sort by different columns, not just RSSI
- **Key**: `o` for sort options
- **Sort Options**:
  - BSSID
  - RSSI (current default)
  - Average RSSI
  - Channel
  - SSID (alphabetical)
  - Vendor
  - Security type
  - Rate (max/real)
- **Implementation**: Toggle ascending/descending

### Auto-Hide Invisible APs
- **Description**: Option to automatically hide APs that are no longer visible
- **Implementation**: Setup menu option "Auto-hide invisible APs: [x]/[ ]"
- **Behavior**: Remove gray APs from list after X scans

## 2. Setup Menu Extensions

### Color Theme
- **Description**: Customize color scheme for signal strength indicators
- **Options**:
  - Default (Green/Yellow/Purple/Red)
  - Monochrome (Grayscale)
  - High Contrast
  - Custom RGB values
- **Implementation**: Setup menu → "Color Theme" submenu

### Auto-Refresh Display
- **Description**: Refresh display even without new scan data
- **Purpose**: Update runtime counter, timestamps
- **Implementation**: Setup menu option with refresh rate (1-10s)

### Max AP Limit
- **Description**: Limit number of displayed APs
- **Range**: 10-500 or unlimited
- **Purpose**: Performance optimization for areas with many APs
- **Implementation**: Setup menu → "Max APs: X"

## 3. Advanced Features

### GPS Coordinates
- **Description**: Store GPS location per AP detection
- **Requirements**: GPS device or coordinates from system
- **Use Case**: War-driving, AP location mapping
- **Implementation**: Optional GPS input, stored per AP

### Signal History Graph
- **Description**: Visual mini-graph of RSSI history
- **Location**: AP detail menu
- **Data**: Last 10-20 RSSI measurements
- **Visualization**: ASCII bar chart or line graph

### Enhanced MAC Vendor Lookup
- **Description**: Better vendor identification
- **Options**:
  - Local OUI database (updated)
  - Online API lookup (optional)
  - Cache results
- **Implementation**: Fallback mechanism (local → online → unknown)

### BSSID Copy to Clipboard
- **Description**: Quick copy BSSID or other data
- **Key**: `c` when AP is selected
- **Options**: Copy BSSID, SSID, or full AP info
- **Implementation**: Use `pbcopy` (macOS) or `xclip` (Linux)

## 4. Statistics & Logging

### Session Logging
- **Description**: Save all scans to log file
- **Format**: JSON or CSV with timestamps
- **Location**: `~/.airdetect/logs/session_YYYYMMDD_HHMMSS.json`
- **Content**: All AP data per scan interval
- **Auto-rotate**: Option to limit log file size

### Channel Utilization Heatmap
- **Description**: Overview of channel usage
- **Visualization**: Bar chart showing AP count per channel
- **Display**: Separate view accessible with key `u` (utilization)
- **Info**: Shows congestion, interference zones

### Best Channel Recommendation
- **Description**: Recommend least crowded channel
- **Analysis**:
  - Count APs per channel
  - Consider overlapping channels (2.4 GHz: 1, 6, 11)
  - Factor in signal strength
- **Display**: In channel heatmap view or separate menu

## 5. UX Improvements

### Confirmation Dialogs
- **Description**: Confirm before critical actions
- **Actions**:
  - Exit with unsaved data
  - Clear AP list
  - Delete logs
- **Implementation**: Simple Y/N popup

### Search/Jump to SSID
- **Description**: Quick search and jump to specific AP
- **Key**: `/` for search (like vim)
- **Behavior**: Highlight matching APs, jump to first match
- **Navigation**: `n` for next match, `N` for previous

### Bookmark/Favorite APs
- **Description**: Mark important APs for quick access
- **Key**: `b` to bookmark selected AP
- **Visualization**: Star symbol (★) or different color
- **Persistence**: Save bookmarks to config file
- **Feature**: Jump to bookmarks menu

## 6. Technical Improvements

### Configuration File
- **Description**: Persistent settings
- **Location**: `~/.airdetect/config.json`
- **Stored Settings**:
  - Column visibility preferences
  - Color theme
  - Default interval/timeout
  - Filter presets
  - Bookmarked BSSIDs

### Plugin System
- **Description**: Extensible architecture for custom features
- **Implementation**: Python plugin directory
- **Capabilities**: Custom columns, export formats, analysis tools

### Multi-Interface Support
- **Description**: Scan on multiple interfaces simultaneously
- **Use Case**: Monitor multiple bands or channels
- **Implementation**: Thread per interface, merged AP pool

## Priority Ranking

### High Priority (Quick Wins)
1. Export function (CSV/JSON)
2. Filter by SSID/Vendor
3. Configuration file for persistent settings
4. Search/Jump functionality

### Medium Priority
1. Advanced sorting options
2. Session logging
3. Channel utilization view
4. BSSID copy to clipboard

### Low Priority (Nice to Have)
1. GPS coordinates
2. Signal history graphs
3. Color theme customization
4. Plugin system

## Implementation Notes

- Keep terminal-based UI lightweight and responsive
- Maintain compatibility with macOS and Linux
- Preserve current keyboard navigation patterns
- Ensure all new features are optional and don't clutter default view
