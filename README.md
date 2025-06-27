# Generic String Search Tool

A powerful Python utility for searching text patterns across files and directories. Originally designed for CTF challenges and digital forensics, this tool can search for any string pattern in both text and binary files with detailed context reporting.

## Features

- 🔍 **Smart Search**: Searches both text and binary files
- 📁 **Recursive Directory Scanning**: Search entire directory trees
- 🎯 **Pattern Variations**: Automatically searches for pattern variations (case-insensitive, with trailing content)
- 📄 **Context Display**: Shows surrounding text/data for each match
- 💾 **Results Export**: Saves detailed results to text files
- ⚡ **Progress Tracking**: Real-time progress display during large scans
- 🔧 **Flexible Options**: Case sensitivity, recursion control, verbosity levels

## Installation

### Requirements
- Python 3.6+
- No external dependencies (uses only standard library)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/string-finder-tool.git
cd string-finder-tool

# Make the script executable (optional)
chmod +x string_finder.py

# Run the tool
python string_finder.py
```

## Usage

### Basic Syntax
```bash
python string_finder.py [directory] [pattern] [options]
```

### Examples

#### Search for CTF flags
```bash
# Search for HTB{ flags in current directory (default behavior)
python string_finder.py

# Search for HTB{ flags in a specific directory
python string_finder.py recovered_files

# Search for other flag formats
python string_finder.py . "flag{"
python string_finder.py . "CTF{"
```

#### General string searches
```bash
# Search for passwords
python string_finder.py /path/to/files "password"

# Search for API keys
python string_finder.py . "api_key"

# Search for email addresses (basic)
python string_finder.py . "@gmail.com"
```

#### Advanced options
```bash
# Case-sensitive search
python string_finder.py . "SecretFlag" --case-sensitive

# Non-recursive (current directory only)
python string_finder.py . "HTB{" --no-recursive

# Quiet mode (less verbose output)
python string_finder.py large_directory "pattern" --quiet
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `directory` | Directory to search in | `.` (current directory) |
| `pattern` | String pattern to search for | `HTB{` |
| `--case-sensitive` | Enable case-sensitive searching | Case-insensitive |
| `--no-recursive` | Disable recursive directory scanning | Recursive enabled |
| `--quiet` | Reduce output verbosity | Verbose mode |
| `--help` | Show help message and exit | - |

## Output

### Console Output
The tool provides real-time feedback including:
- Search configuration summary
- Progress indicator with file count
- Detailed match information with context
- Summary statistics

### Example Output
```
============================================================
GENERIC STRING SEARCH TOOL
============================================================
Directory: /home/user/recovered_files
Pattern: 'HTB{'
Case sensitive: False
Recursive: True

Scanning 752 files...
----------------------------------------
[752/752] Scanning: signature_found_8.exe

🎯 FOUND 'HTB{' in 3 files!
============================================================

📁 FILE: recovered_files/http_file_234.bin
   Size: 1024 bytes
   Matches: 1

   Match 1:
   Type: text
   Found: 'HTB{secret_flag_here}'
   Position: 456
   Context (lines):
     Some content before
     >>> This line contains HTB{secret_flag_here} in the middle
     Some content after
```

### Results File
Detailed results are automatically saved to `search_results_[pattern].txt` containing:
- Search configuration
- Complete match details
- File paths and sizes
- Full context for each match

## Use Cases

### Digital Forensics
- Extract flags from network traffic captures
- Search for credentials in memory dumps
- Find specific strings in disk images

### CTF Challenges
- Locate hidden flags in recovered files
- Search for clues across multiple file types
- Analyze exfiltrated data

### General File Analysis
- Find configuration parameters
- Locate API keys or passwords
- Search log files for specific events

## Technical Details

### Search Strategy
1. **Text Mode**: Attempts to read files as UTF-8 text and uses regex matching
2. **Binary Mode**: Searches raw bytes for pattern variations
3. **Pattern Variations**: Automatically searches for:
   - Exact pattern match
   - Pattern followed by content until `}`
   - Pattern followed by word characters
   - Case variations (upper, lower, original)

### File Type Support
- **Text files**: .txt, .log, .json, .xml, .html, etc.
- **Binary files**: .exe, .bin, .img, .pcap, etc.
- **Archives**: Content within files (not archive extraction)
- **Any file type**: No restrictions on file extensions

### Performance
- Optimized for large directory scans
- Memory-efficient streaming file reading
- Progress tracking for long-running searches
- Duplicate result filtering

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/yourusername/string-finder-tool.git
cd string-finder-tool

# Run tests (if you add them)
python -m pytest tests/

# Check code style
python -m flake8 string_finder.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release
- Basic string searching functionality
- Text and binary file support
- Recursive directory scanning
- Results export

## Troubleshooting

### Common Issues

**"Directory not found" error**
- Ensure the directory path is correct
- Use absolute paths if relative paths aren't working

**No matches found**
- Try case-insensitive search (default)
- Check if pattern needs escaping for special characters
- Use broader search terms

**Permission errors**
- Ensure read permissions on target files
- Run with appropriate user privileges

**Large directory scans are slow**
- Use `--no-recursive` for single directory
- Use `--quiet` to reduce output overhead
- Consider searching specific subdirectories

## Related Tools

- `grep` - Unix/Linux text searching utility
- `ripgrep` - Fast text search tool
- `find` - File system search utility
- `strings` - Extract text from binary files

## Support

If you encounter any issues or have questions:
1. Check the troubleshooting section above
2. Search existing [GitHub Issues](https://github.com/yourusername/string-finder-tool/issues)
3. Create a new issue with detailed information about your problem

---

**Happy searching!** 🔍
