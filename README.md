# LIB Analyzer

A powerful Windows static library (.lib) analysis tool with a modern dark-themed web interface.

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

- 🔍 **Complete Analysis** - Parse AR archive and COFF object files
- 🌐 **Web Interface** - Modern dark-themed UI with smooth animations
- 🌍 **Multi-language** - Chinese and English support
- 📊 **Symbol Table** - Automatic classification of functions, imports, and variables
- 🔎 **Search** - Full-text search across all files
- 💾 **Extract** - Export individual or all files
- 📱 **Responsive** - Works on desktop and mobile devices

## Quick Start

### Web UI (Recommended)

```bash
# Start server (auto-installs dependencies)
start_web.bat

# Open browser
http://localhost:5000
```

### Command Line

```bash
# List files
python lib_analyzer.py list mylib.lib

# View symbols
python lib_analyzer.py symbols mylib.lib

# Search keyword
python lib_analyzer.py search mylib.lib "driver"

# Extract file
python lib_analyzer.py extract mylib.lib 3 output.obj
```

## Installation

### Requirements

- Python 3.7+
- Flask 2.0+

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Or manual install
pip install flask
```

## Usage

### Web Interface

1. **Upload** - Drag and drop .lib file or click to select
2. **Analyze** - View files, symbols, and details
3. **Search** - Find keywords across all files
4. **Extract** - Download individual files
5. **Language** - Switch between Chinese and English

### Command Line

```bash
# Interactive mode
python lib_analyzer.py

# Direct commands
python lib_analyzer.py <command> [args]
```

**Available Commands:**

- `list <file>` - List all files in library
- `info <file> <index>` - Show file details
- `symbols <file> [index]` - Display symbol table
- `extract <file> <index> [output]` - Extract file
- `extract-all <file> [dir]` - Extract all files
- `search <file> <keyword>` - Search for keyword

## API Endpoints

```
POST   /api/upload          - Upload .lib file
GET    /api/files           - Get file list
GET    /api/file/<index>    - Get file details
GET    /api/symbols         - Get symbol table
GET    /api/search?q=<kw>   - Search keyword
GET    /api/extract/<index> - Download file
```

## Architecture

### Backend (Flask)

- AR archive format parser
- COFF object file parser
- Symbol table analyzer
- RESTful API server

### Frontend (HTML/CSS/JS)

- Dark theme UI
- Drag-and-drop upload
- Real-time language switching
- Responsive design

## File Structure

```
lib_analyzer/
├── lib_analyzer.py          # CLI tool
├── web_server.py            # Web server
├── start_web.bat            # Startup script
├── requirements.txt         # Dependencies
└── templates/
    └── index.html           # Web interface
```

## Examples

### Analyze Static Library

```bash
# Start web server
python web_server.py

# Upload 2019_MD_TX__x64.lib
# View 5 files, 1323 symbols
# Extract Driver.obj for further analysis
```

### Search for Functions

```bash
# Search for driver-related functions
python lib_analyzer.py search mylib.lib "LoadNTDriver"

# Found in file 3: /0
# Offset 0x12980: ...?LoadNTDriver@@YAHPEBD0@Z...
```

### Extract Object Files

```bash
# Extract main object file
python lib_analyzer.py extract mylib.lib 3 Driver.obj

# Use with IDA Pro or Ghidra for reverse engineering
```

## Configuration

### Change Port

Edit `web_server.py`:

```python
app.run(host='0.0.0.0', port=8080, debug=True)
```

### Change Theme Colors

Edit `templates/index.html` CSS variables:

```css
:root {
    --bg-primary: #0a0e27;
    --accent-primary: #00d4ff;
}
```

## Performance

- File size limit: 100MB (configurable)
- Symbol display: First 50 functions
- Search results: 10 matches per file
- Hex preview: First 256 bytes

## Browser Support

- Chrome 90+
- Edge 90+
- Firefox 88+
- Safari 14+

## Troubleshooting

### Flask Not Installed

```bash
pip install flask
```

### Port Already in Use

```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <pid> /F

# Or change port in web_server.py
```

### Language Not Switching

- Clear browser cache
- Press Ctrl+F5 to hard refresh
- Check browser console for errors

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

MIT License - feel free to use for educational and research purposes.

## Acknowledgments

- Flask - Web framework
- Python - Programming language
- Modern browsers - Rendering engines


***

**Start analyzing now!** 🚀

```bash
cd your-project-directory
start_web.bat
```

