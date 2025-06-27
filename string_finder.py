#!/usr/bin/env python3
"""
Generic String Search Tool

This script searches for a specified pattern in all files within a directory
and reports which files contain it along with the context.

Usage:
    python string_finder.py [directory] [pattern]
    python string_finder.py                          # Search for 'HTB{' in current directory
    python string_finder.py /path/to/files          # Search for 'HTB{' in specified directory
    python string_finder.py . "flag{"               # Search for 'flag{' in current directory
    python string_finder.py recovered_files "CTF"   # Search for 'CTF' in recovered_files directory
"""

import os
import re
import sys
import argparse
from pathlib import Path

class StringSearchTool:
    def __init__(self, directory=".", pattern="HTB{"):
        self.directory = directory
        self.pattern = pattern
        self.case_sensitive = False
        
    def search_pattern_in_file(self, filepath):
        """
        Search for pattern in a file (both text and binary modes)
        
        Args:
            filepath (str): Path to the file to search
            
        Returns:
            list: List of findings with context
        """
        findings = []
        
        try:
            # First try as text file
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Search for pattern (case insensitive by default)
                flags = 0 if self.case_sensitive else re.IGNORECASE
                escaped_pattern = re.escape(self.pattern)
                
                # Also search for pattern with common variations
                patterns_to_search = [
                    self.pattern,  # Exact pattern
                    escaped_pattern + r'[^}]*}',  # Pattern followed by content until }
                    escaped_pattern + r'\w*',     # Pattern followed by word characters
                ]
                
                for search_pattern in patterns_to_search:
                    try:
                        matches = list(re.finditer(search_pattern, content, flags))
                        
                        for match in matches:
                            start = max(0, match.start() - 50)
                            end = min(len(content), match.end() + 50)
                            context = content[start:end].replace('\n', '\\n').replace('\r', '\\r')
                            
                            findings.append({
                                'type': 'text',
                                'match': match.group(),
                                'position': match.start(),
                                'context': context,
                                'line_context': self.get_line_context(content, match.start())
                            })
                    except re.error:
                        # If regex fails, fall back to simple string search
                        pass
                        
            except UnicodeDecodeError:
                pass
            
            # Also try as binary file for hex-encoded or binary data
            with open(filepath, 'rb') as f:
                binary_content = f.read()
            
            # Search for pattern in binary (case variations)
            pattern_bytes = self.pattern.encode('utf-8')
            pattern_variations = [
                pattern_bytes,
                pattern_bytes.lower(),
                pattern_bytes.upper(),
            ]
            
            for pattern_var in pattern_variations:
                offset = 0
                while True:
                    pos = binary_content.find(pattern_var, offset)
                    if pos == -1:
                        break
                    
                    # Get context around the match
                    start = max(0, pos - 50)
                    end = min(len(binary_content), pos + 50)
                    context_bytes = binary_content[start:end]
                    
                    # Try to decode context for display
                    try:
                        context_str = context_bytes.decode('utf-8', errors='ignore')
                    except:
                        context_str = str(context_bytes)
                    
                    findings.append({
                        'type': 'binary',
                        'match': pattern_var.decode('utf-8', errors='ignore'),
                        'position': pos,
                        'context': context_str,
                        'hex_context': context_bytes.hex()
                    })
                    
                    offset = pos + 1
            
            # Remove duplicates (same position, same type)
            unique_findings = []
            seen = set()
            for finding in findings:
                key = (finding['type'], finding['position'], finding['match'])
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            
            return unique_findings
            
        except Exception as e:
            if self.verbose:
                print(f"Error reading {filepath}: {e}")
            return []

    def get_line_context(self, content, position):
        """Get the line containing the match and surrounding lines"""
        lines = content.split('\n')
        char_count = 0
        
        for i, line in enumerate(lines):
            if char_count <= position <= char_count + len(line):
                # Found the line, get context
                start_line = max(0, i - 2)
                end_line = min(len(lines), i + 3)
                context_lines = lines[start_line:end_line]
                
                # Mark the target line
                if i - start_line < len(context_lines):
                    context_lines[i - start_line] = f">>> {context_lines[i - start_line]}"
                
                return '\n'.join(context_lines)
            
            char_count += len(line) + 1  # +1 for newline
        
        return "Line context not found"

    def search_all_files(self, recursive=True, verbose=True):
        """
        Search for pattern in all files in the directory
        
        Args:
            recursive (bool): Search subdirectories recursively
            verbose (bool): Show detailed output
        """
        self.verbose = verbose
        
        if not os.path.exists(self.directory):
            print(f"Directory '{self.directory}' not found!")
            return
        
        print("="*60)
        print("GENERIC STRING SEARCH TOOL")
        print("="*60)
        print(f"Directory: {os.path.abspath(self.directory)}")
        print(f"Pattern: '{self.pattern}'")
        print(f"Case sensitive: {self.case_sensitive}")
        print(f"Recursive: {recursive}")
        print()
        
        # Get list of files
        if recursive:
            files = list(Path(self.directory).rglob("*"))
        else:
            files = list(Path(self.directory).glob("*"))
        
        # Filter only files (not directories)
        files = [f for f in files if f.is_file()]
        total_files = len(files)
        files_with_pattern = []
        
        if total_files == 0:
            print("No files found in the specified directory.")
            return
        
        print(f"Scanning {total_files} files...")
        print("-" * 40)
        
        for i, filepath in enumerate(files, 1):
            if verbose:
                print(f"\r[{i:3d}/{total_files}] Scanning: {str(filepath)[-50:]:<50}", end="", flush=True)
            
            findings = self.search_pattern_in_file(filepath)
            
            if findings:
                files_with_pattern.append((filepath, findings))
        
        if verbose:
            print("\n" + "-" * 40)
        
        if not files_with_pattern:
            print(f"\nNo files containing '{self.pattern}' were found.")
            
            # Suggest alternative searches
            if self.pattern == "HTB{":
                print("\nTrying alternative searches:")
                alternative_patterns = ["HTB", "flag{", "FLAG{", "ctf{", "CTF{", "{", "}"]
                
                for alt_pattern in alternative_patterns:
                    print(f"\nSearching for '{alt_pattern}'...")
                    alt_tool = StringSearchTool(self.directory, alt_pattern)
                    found_files = self.quick_search_for_pattern(alt_pattern)
                    if found_files:
                        print(f"  Found in {len(found_files)} files:")
                        for filepath in found_files[:5]:  # Show first 5
                            print(f"    - {filepath}")
                        if len(found_files) > 5:
                            print(f"    ... and {len(found_files) - 5} more")
            
            return
        
        print(f"\n🎯 FOUND '{self.pattern}' in {len(files_with_pattern)} files!")
        print("=" * 60)
        
        for filepath, findings in files_with_pattern:
            print(f"\n📁 FILE: {filepath}")
            print(f"   Size: {filepath.stat().st_size} bytes")
            print(f"   Matches: {len(findings)}")
            
            for j, finding in enumerate(findings, 1):
                print(f"\n   Match {j}:")
                print(f"   Type: {finding['type']}")
                print(f"   Found: '{finding['match']}'")
                print(f"   Position: {finding['position']}")
                
                if finding['type'] == 'text' and 'line_context' in finding:
                    print(f"   Context (lines):")
                    for line in finding['line_context'].split('\n'):
                        print(f"     {line}")
                else:
                    print(f"   Context: {finding['context'][:100]}...")
                    if 'hex_context' in finding:
                        print(f"   Hex: {finding['hex_context'][:100]}...")
            
            print("-" * 50)
        
        # Summary
        print(f"\n📋 SUMMARY:")
        print(f"   Total files scanned: {total_files}")
        print(f"   Files containing '{self.pattern}': {len(files_with_pattern)}")
        
        # Save results to file
        self.save_results(files_with_pattern)

    def quick_search_for_pattern(self, pattern):
        """Quick search for any pattern in files (for suggestions)"""
        found_files = []
        
        try:
            if os.path.exists(self.directory):
                files = list(Path(self.directory).rglob("*") if True else Path(self.directory).glob("*"))
                files = [f for f in files if f.is_file()]
                
                for filepath in files[:50]:  # Limit to first 50 files for quick search
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if pattern.lower() in content.lower():
                                found_files.append(filepath.name)
                    except:
                        try:
                            with open(filepath, 'rb') as f:
                                content = f.read()
                                if pattern.lower().encode() in content.lower():
                                    found_files.append(filepath.name)
                        except:
                            pass
        except:
            pass
        
        return found_files

    def save_results(self, files_with_pattern):
        """Save search results to a file"""
        safe_pattern = re.sub(r'[^\w\-_]', '_', self.pattern)
        results_file = os.path.join(self.directory, f"search_results_{safe_pattern}.txt")
        
        try:
            with open(results_file, 'w') as f:
                f.write(f"STRING SEARCH RESULTS\n")
                f.write(f"Pattern: '{self.pattern}'\n")
                f.write(f"Directory: {os.path.abspath(self.directory)}\n")
                f.write("=" * 50 + "\n\n")
                
                for filepath, findings in files_with_pattern:
                    f.write(f"FILE: {filepath}\n")
                    f.write(f"Size: {filepath.stat().st_size} bytes\n")
                    f.write(f"Matches: {len(findings)}\n\n")
                    
                    for j, finding in enumerate(findings, 1):
                        f.write(f"  Match {j}:\n")
                        f.write(f"    Type: {finding['type']}\n")
                        f.write(f"    Found: '{finding['match']}'\n")
                        f.write(f"    Position: {finding['position']}\n")
                        f.write(f"    Context: {finding['context'][:200]}...\n")
                        f.write("\n")
                    
                    f.write("-" * 40 + "\n\n")
            
            print(f"\n💾 Results saved to: {results_file}")
            
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Search for a pattern in all files within a directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python string_finder.py                          # Search for 'HTB{' in current directory
  python string_finder.py recovered_files          # Search for 'HTB{' in recovered_files directory  
  python string_finder.py . "flag{"               # Search for 'flag{' in current directory
  python string_finder.py /path/to/files "CTF"    # Search for 'CTF' in specified directory
  python string_finder.py . "password" --no-recursive  # Non-recursive search
        """
    )
    
    parser.add_argument(
        'directory', 
        nargs='?', 
        default='.', 
        help='Directory to search in (default: current directory)'
    )
    
    parser.add_argument(
        'pattern', 
        nargs='?', 
        default='HTB{', 
        help='Pattern to search for (default: HTB{)'
    )
    
    parser.add_argument(
        '--case-sensitive', 
        action='store_true', 
        help='Make the search case-sensitive'
    )
    
    parser.add_argument(
        '--no-recursive', 
        action='store_true', 
        help='Do not search subdirectories recursively'
    )
    
    parser.add_argument(
        '--quiet', 
        action='store_true', 
        help='Reduce output verbosity'
    )
    
    args = parser.parse_args()
    
    # Create search tool
    tool = StringSearchTool(args.directory, args.pattern)
    tool.case_sensitive = args.case_sensitive
    
    # Run search
    tool.search_all_files(
        recursive=not args.no_recursive,
        verbose=not args.quiet
    )

if __name__ == "__main__":
    main()
