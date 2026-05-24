#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys
import os
from datetime import datetime
from pathlib import Path


class COFFObject:
    def __init__(self, data):
        self.data = data
        self.machine = None
        self.num_sections = None
        self.timestamp = None
        self.symbol_table_offset = None
        self.num_symbols = None
        self.sections = []
        self.symbols = []
        self._parse()

    def _parse(self):
        if len(self.data) < 20:
            return

        self.machine = struct.unpack('<H', self.data[0:2])[0]
        self.num_sections = struct.unpack('<H', self.data[2:4])[0]
        self.timestamp = struct.unpack('<I', self.data[4:8])[0]
        self.symbol_table_offset = struct.unpack('<I', self.data[8:12])[0]
        self.num_symbols = struct.unpack('<I', self.data[12:16])[0]
        self.opt_header_size = struct.unpack('<H', self.data[16:18])[0]

        section_table_offset = 20 + self.opt_header_size
        for i in range(min(self.num_sections, 100)):
            offset = section_table_offset + i * 40
            if offset + 40 > len(self.data):
                break

            name = self.data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size = struct.unpack('<I', self.data[offset+8:offset+12])[0]
            virtual_addr = struct.unpack('<I', self.data[offset+12:offset+16])[0]
            raw_size = struct.unpack('<I', self.data[offset+16:offset+20])[0]
            raw_offset = struct.unpack('<I', self.data[offset+20:offset+24])[0]

            self.sections.append({
                'name': name,
                'virtual_size': virtual_size,
                'virtual_addr': virtual_addr,
                'raw_size': raw_size,
                'raw_offset': raw_offset
            })

        self._parse_symbols()

    def _parse_symbols(self):
        if self.symbol_table_offset == 0 or self.num_symbols == 0:
            return

        string_table_offset = self.symbol_table_offset + self.num_symbols * 18

        if string_table_offset + 4 > len(self.data):
            return

        for i in range(self.num_symbols):
            sym_offset = self.symbol_table_offset + i * 18
            if sym_offset + 18 > len(self.data):
                break

            name_field = self.data[sym_offset:sym_offset+8]

            if name_field[0:4] == b'\x00\x00\x00\x00':
                str_offset = struct.unpack('<I', name_field[4:8])[0]
                if str_offset > 0 and string_table_offset + str_offset < len(self.data):
                    str_start = string_table_offset + str_offset
                    str_end = self.data.find(b'\x00', str_start)
                    if str_end != -1:
                        name = self.data[str_start:str_end].decode('ascii', errors='ignore')
                    else:
                        name = self.data[str_start:str_start+50].decode('ascii', errors='ignore')
                else:
                    name = ""
            else:
                name = name_field.rstrip(b'\x00').decode('ascii', errors='ignore')

            value = struct.unpack('<I', self.data[sym_offset+8:sym_offset+12])[0]
            section_num = struct.unpack('<h', self.data[sym_offset+12:sym_offset+14])[0]
            type_val = struct.unpack('<H', self.data[sym_offset+14:sym_offset+16])[0]
            storage_class = struct.unpack('<B', self.data[sym_offset+16:sym_offset+17])[0]

            if name:
                self.symbols.append({
                    'name': name,
                    'value': value,
                    'section': section_num,
                    'type': type_val,
                    'storage_class': storage_class
                })

    def get_machine_name(self):
        machines = {
            0x14c: 'x86 (i386)',
            0x8664: 'x64 (AMD64)',
            0x1c0: 'ARM',
            0xaa64: 'ARM64',
            0x1c4: 'ARM Thumb-2'
        }
        return machines.get(self.machine, f'Unknown ({hex(self.machine)})')


class LibAnalyzer:
    def __init__(self, lib_path):
        self.lib_path = Path(lib_path)
        self.data = None
        self.files = []

        if not self.lib_path.exists():
            raise FileNotFoundError(f"File not found: {lib_path}")

        with open(self.lib_path, 'rb') as f:
            self.data = f.read()

        self._parse()

    def _parse(self):
        if self.data[:8] != b'!<arch>\n':
            raise ValueError("Not a valid AR archive format (.lib file)")

        pos = 8
        file_index = 0

        while pos < len(self.data):
            if pos + 60 > len(self.data):
                break

            header = self.data[pos:pos+60]
            name = header[0:16].rstrip(b' ').decode('ascii', errors='ignore')
            mtime_str = header[16:28].rstrip(b' ').decode('ascii', errors='ignore')

            try:
                mtime = int(mtime_str) if mtime_str else 0
            except:
                mtime = 0

            size_str = header[48:58].rstrip(b' ').decode('ascii', errors='ignore')
            try:
                file_size = int(size_str)
            except:
                break

            file_data_start = pos + 60
            file_data = self.data[file_data_start:file_data_start+file_size]
            file_type = self._detect_file_type(name, file_data)

            self.files.append({
                'index': file_index,
                'name': name,
                'size': file_size,
                'mtime': mtime,
                'offset': file_data_start,
                'data': file_data,
                'type': file_type
            })

            file_index += 1
            pos = file_data_start + file_size
            if file_size % 2 == 1:
                pos += 1

    def _detect_file_type(self, name, data):
        if name in ['/', '//', '__.SYMDEF', '__.SYMDEF SORTED']:
            return 'index'

        if len(data) >= 2:
            machine = struct.unpack('<H', data[0:2])[0]
            if machine in [0x14c, 0x8664, 0x1c0, 0xaa64, 0x1c4]:
                return 'coff'

        return 'unknown'

    def list_files(self):
        print(f"\n{'='*80}")
        print(f"LIB File: {self.lib_path.name}")
        print(f"Total Size: {len(self.data):,} bytes")
        print(f"File Count: {len(self.files)}")
        print(f"{'='*80}\n")

        print(f"{'Index':<6} {'Name':<20} {'Size':<12} {'Type':<10} {'Modified'}")
        print("-" * 80)

        for f in self.files:
            size_str = f"{f['size']:,} B"
            if f['mtime'] > 0:
                mtime_str = datetime.fromtimestamp(f['mtime']).strftime('%Y-%m-%d %H:%M:%S')
            else:
                mtime_str = "N/A"

            print(f"{f['index']:<6} {f['name']:<20} {size_str:<12} {f['type']:<10} {mtime_str}")

    def show_file_info(self, index):
        if index < 0 or index >= len(self.files):
            print(f"Error: Index {index} out of range (0-{len(self.files)-1})")
            return

        file_info = self.files[index]

        print(f"\n{'='*80}")
        print(f"File Details - Index {index}")
        print(f"{'='*80}")
        print(f"Name:       {file_info['name']}")
        print(f"Size:       {file_info['size']:,} bytes")
        print(f"Type:       {file_info['type']}")
        print(f"Offset:     {hex(file_info['offset'])}")

        if file_info['mtime'] > 0:
            print(f"Modified:   {datetime.fromtimestamp(file_info['mtime'])}")

        if file_info['type'] == 'coff':
            print(f"\n--- COFF Object File ---")
            coff = COFFObject(file_info['data'])
            print(f"Machine:    {coff.get_machine_name()}")
            print(f"Sections:   {coff.num_sections}")
            print(f"Symbols:    {coff.num_symbols}")

            if coff.timestamp > 0:
                print(f"Compiled:   {datetime.fromtimestamp(coff.timestamp)}")

            if coff.sections:
                print(f"\nSections:")
                print(f"  {'Name':<12} {'VirtSize':<12} {'RawSize':<12} {'Offset'}")
                print(f"  {'-'*60}")
                for section in coff.sections[:20]:
                    print(f"  {section['name']:<12} {section['virtual_size']:<12} "
                          f"{section['raw_size']:<12} {hex(section['raw_offset'])}")

        print(f"\nFirst 64 bytes (hex):")
        data_preview = file_info['data'][:64]
        for i in range(0, len(data_preview), 16):
            hex_str = ' '.join(f'{b:02x}' for b in data_preview[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_preview[i:i+16])
            print(f"  {i:04x}: {hex_str:<48} {ascii_str}")

    def list_symbols(self, index=None, filter_keyword=None):
        if index is not None:
            if index < 0 or index >= len(self.files):
                print(f"Error: Index {index} out of range")
                return
            files_to_process = [self.files[index]]
        else:
            files_to_process = [f for f in self.files if f['type'] == 'coff']

        total_symbols = 0

        for file_info in files_to_process:
            if file_info['type'] != 'coff':
                print(f"File {file_info['index']} ({file_info['name']}) is not a COFF object file")
                continue

            coff = COFFObject(file_info['data'])

            symbols = coff.symbols
            if filter_keyword:
                symbols = [s for s in symbols if filter_keyword.lower() in s['name'].lower()]

            if not symbols:
                continue

            print(f"\n{'='*80}")
            print(f"File {file_info['index']}: {file_info['name']}")
            print(f"Symbol Count: {len(symbols)}")
            print(f"{'='*80}")

            functions = [s for s in symbols if '@@' in s['name'] or s['name'].startswith('?')]
            variables = [s for s in symbols if s['name'].startswith('_') and '@@' not in s['name']]
            imports = [s for s in symbols if s['name'].startswith('__imp_')]
            others = [s for s in symbols if s not in functions and s not in variables and s not in imports]

            if functions:
                print(f"\n--- Functions ({len(functions)}) ---")
                for sym in functions[:50]:
                    section_str = f"Section {sym['section']}" if sym['section'] > 0 else "External"
                    print(f"  {sym['name']:<60} {section_str}")
                if len(functions) > 50:
                    print(f"  ... and {len(functions)-50} more functions")

            if imports:
                print(f"\n--- Imports ({len(imports)}) ---")
                for sym in imports[:30]:
                    print(f"  {sym['name']}")
                if len(imports) > 30:
                    print(f"  ... and {len(imports)-30} more imports")

            if variables:
                print(f"\n--- Variables ({len(variables)}) ---")
                for sym in variables[:30]:
                    print(f"  {sym['name']}")
                if len(variables) > 30:
                    print(f"  ... and {len(variables)-30} more variables")

            total_symbols += len(symbols)

        print(f"\nTotal: {total_symbols} symbols")

    def extract_file(self, index, output_path=None):
        if index < 0 or index >= len(self.files):
            print(f"Error: Index {index} out of range")
            return

        file_info = self.files[index]

        if output_path is None:
            if file_info['name'].startswith('/'):
                if file_info['type'] == 'coff':
                    output_path = f"extracted_{index}.obj"
                else:
                    output_path = f"extracted_{index}.bin"
            else:
                output_path = file_info['name']

        with open(output_path, 'wb') as f:
            f.write(file_info['data'])

        print(f"Extracted file {index} ({file_info['name']}) to: {output_path}")
        print(f"Size: {file_info['size']:,} bytes")

    def extract_all(self, output_dir=None):
        if output_dir is None:
            output_dir = self.lib_path.stem + "_extracted"

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        print(f"Extracting all files to: {output_path}")
        print()

        for i, file_info in enumerate(self.files):
            if file_info['name'].startswith('/'):
                if file_info['type'] == 'coff':
                    filename = f"file_{i}.obj"
                elif file_info['type'] == 'index':
                    filename = f"index_{i}.bin"
                else:
                    filename = f"file_{i}.bin"
            else:
                filename = file_info['name'].replace('/', '_')

            output_file = output_path / filename

            with open(output_file, 'wb') as f:
                f.write(file_info['data'])

            print(f"  [{i}] {filename} ({file_info['size']:,} bytes)")

        print(f"\nCompleted! Extracted {len(self.files)} files")

    def search_string(self, keyword, case_sensitive=False):
        print(f"\nSearching for: '{keyword}'")
        print(f"Case sensitive: {case_sensitive}")
        print(f"{'='*80}\n")

        if not case_sensitive:
            keyword = keyword.lower()

        total_matches = 0

        for file_info in self.files:
            data = file_info['data']
            matches = []
            pos = 0

            while True:
                if case_sensitive:
                    idx = data.find(keyword.encode('ascii', errors='ignore'), pos)
                else:
                    idx = data.lower().find(keyword.encode('ascii', errors='ignore'), pos)

                if idx == -1:
                    break

                start = max(0, idx - 30)
                end = min(len(data), idx + len(keyword) + 30)
                context = data[start:end]

                try:
                    context_str = context.decode('ascii', errors='ignore')
                    matches.append({
                        'offset': idx,
                        'context': context_str
                    })
                except:
                    pass

                pos = idx + 1

            if matches:
                print(f"File {file_info['index']}: {file_info['name']}")
                print(f"Found {len(matches)} matches\n")

                for match in matches[:10]:
                    print(f"  Offset {hex(match['offset'])}: ...{match['context']}...")

                if len(matches) > 10:
                    print(f"  ... and {len(matches)-10} more matches")

                print()
                total_matches += len(matches)

        print(f"Total: {total_matches} matches")


def print_help():
    help_text = """
LIB Static Library Analyzer - Usage

Usage: python lib_analyzer.py <command> [args]

Commands:
  list <lib_file>                    List all files in library
  info <lib_file> <index>            Show file details
  symbols <lib_file> [index]         List symbol table
  extract <lib_file> <index> [out]   Extract file
  extract-all <lib_file> [dir]       Extract all files
  search <lib_file> <keyword>        Search for keyword

Examples:
  python lib_analyzer.py list mylib.lib
  python lib_analyzer.py info mylib.lib 0
  python lib_analyzer.py symbols mylib.lib
  python lib_analyzer.py extract mylib.lib 0 output.obj
  python lib_analyzer.py search mylib.lib "driver"

Interactive Mode:
  python lib_analyzer.py
  Then follow the prompts
"""
    print(help_text)


def interactive_mode():
    print("=" * 80)
    print("LIB Static Library Analyzer - Interactive Mode")
    print("=" * 80)
    print("Type 'help' for help, 'quit' to exit\n")

    analyzer = None

    while True:
        try:
            cmd = input(">>> ").strip()

            if not cmd:
                continue

            if cmd == 'quit' or cmd == 'exit':
                print("Goodbye!")
                break

            if cmd == 'help':
                print_help()
                continue

            parts = cmd.split()
            command = parts[0]

            if command == 'load':
                if len(parts) < 2:
                    print("Usage: load <lib_file>")
                    continue

                try:
                    analyzer = LibAnalyzer(parts[1])
                    print(f"Loaded: {parts[1]}")
                except Exception as e:
                    print(f"Error: {e}")
                continue

            if analyzer is None:
                print("Please load a library first using 'load <lib_file>'")
                continue

            if command == 'list':
                analyzer.list_files()

            elif command == 'info':
                if len(parts) < 2:
                    print("Usage: info <index>")
                    continue
                try:
                    index = int(parts[1])
                    analyzer.show_file_info(index)
                except ValueError:
                    print("Error: Index must be a number")

            elif command == 'symbols':
                if len(parts) >= 2:
                    try:
                        index = int(parts[1])
                        analyzer.list_symbols(index)
                    except ValueError:
                        print("Error: Index must be a number")
                else:
                    analyzer.list_symbols()

            elif command == 'extract':
                if len(parts) < 2:
                    print("Usage: extract <index> [output]")
                    continue
                try:
                    index = int(parts[1])
                    output = parts[2] if len(parts) >= 3 else None
                    analyzer.extract_file(index, output)
                except ValueError:
                    print("Error: Index must be a number")

            elif command == 'extract-all':
                output_dir = parts[1] if len(parts) >= 2 else None
                analyzer.extract_all(output_dir)

            elif command == 'search':
                if len(parts) < 2:
                    print("Usage: search <keyword>")
                    continue
                keyword = ' '.join(parts[1:])
                analyzer.search_string(keyword)

            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for help")

        except KeyboardInterrupt:
            print("\nUse 'quit' to exit")
        except Exception as e:
            print(f"Error: {e}")


def main():
    if len(sys.argv) < 2:
        interactive_mode()
        return

    command = sys.argv[1]

    if command == 'help' or command == '--help' or command == '-h':
        print_help()
        return

    if command == 'list':
        if len(sys.argv) < 3:
            print("Usage: python lib_analyzer.py list <lib_file>")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        analyzer.list_files()

    elif command == 'info':
        if len(sys.argv) < 4:
            print("Usage: python lib_analyzer.py info <lib_file> <index>")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        index = int(sys.argv[3])
        analyzer.show_file_info(index)

    elif command == 'symbols':
        if len(sys.argv) < 3:
            print("Usage: python lib_analyzer.py symbols <lib_file> [index]")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        index = int(sys.argv[3]) if len(sys.argv) >= 4 else None
        analyzer.list_symbols(index)

    elif command == 'extract':
        if len(sys.argv) < 4:
            print("Usage: python lib_analyzer.py extract <lib_file> <index> [output]")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        index = int(sys.argv[3])
        output = sys.argv[4] if len(sys.argv) >= 5 else None
        analyzer.extract_file(index, output)

    elif command == 'extract-all':
        if len(sys.argv) < 3:
            print("Usage: python lib_analyzer.py extract-all <lib_file> [output_dir]")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        output_dir = sys.argv[3] if len(sys.argv) >= 4 else None
        analyzer.extract_all(output_dir)

    elif command == 'search':
        if len(sys.argv) < 4:
            print("Usage: python lib_analyzer.py search <lib_file> <keyword>")
            return

        analyzer = LibAnalyzer(sys.argv[2])
        keyword = ' '.join(sys.argv[3:])
        analyzer.search_string(keyword)

    else:
        print(f"Unknown command: {command}")
        print("Use 'python lib_analyzer.py help' for help")


if __name__ == '__main__':
    main()
