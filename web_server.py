#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import struct
import re
from datetime import datetime
import os
import tempfile

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

current_analyzer = None


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

            if name:
                self.symbols.append({
                    'name': name,
                    'value': value,
                    'section': section_num
                })

    def get_machine_name(self):
        machines = {
            0x14c: 'x86',
            0x8664: 'x64',
            0x1c0: 'ARM',
            0xaa64: 'ARM64'
        }
        return machines.get(self.machine, 'Unknown')


class LibAnalyzer:
    def __init__(self, lib_path):
        self.lib_path = Path(lib_path)
        self.data = None
        self.files = []

        with open(self.lib_path, 'rb') as f:
            self.data = f.read()

        self._parse()

    def _parse(self):
        if self.data[:8] != b'!<arch>\n':
            raise ValueError("Not a valid AR archive format")

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
            if machine in [0x14c, 0x8664, 0x1c0, 0xaa64]:
                return 'coff'

        return 'unknown'

    def get_file_info(self, index):
        if index < 0 or index >= len(self.files):
            return None

        file_info = self.files[index].copy()

        if file_info['type'] == 'coff':
            coff = COFFObject(file_info['data'])
            file_info['coff'] = {
                'machine': coff.get_machine_name(),
                'num_sections': coff.num_sections,
                'num_symbols': coff.num_symbols,
                'timestamp': coff.timestamp,
                'sections': coff.sections[:20],
                'symbols': coff.symbols[:100]
            }

        preview_data = file_info['data'][:256]
        hex_lines = []
        for i in range(0, len(preview_data), 16):
            chunk = preview_data[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append({
                'offset': f'{i:04x}',
                'hex': hex_str,
                'ascii': ascii_str
            })

        file_info['hex_preview'] = hex_lines
        del file_info['data']

        return file_info

    def search_string(self, keyword):
        results = []
        keyword_bytes = keyword.encode('ascii', errors='ignore')

        for file_info in self.files:
            matches = []
            data = file_info['data']
            pos = 0

            while True:
                idx = data.find(keyword_bytes, pos)
                if idx == -1:
                    break

                start = max(0, idx - 30)
                end = min(len(data), idx + len(keyword) + 30)
                context = data[start:end]

                try:
                    context_str = context.decode('ascii', errors='ignore')
                    matches.append({
                        'offset': hex(idx),
                        'context': context_str
                    })
                except:
                    pass

                pos = idx + 1

            if matches:
                results.append({
                    'file_index': file_info['index'],
                    'file_name': file_info['name'],
                    'matches': matches[:10]
                })

        return results


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    global current_analyzer

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith('.lib'):
        return jsonify({'error': 'Only .lib files are supported'}), 400

    try:
        temp_path = Path(tempfile.gettempdir()) / file.filename
        file.save(temp_path)

        current_analyzer = LibAnalyzer(temp_path)

        return jsonify({
            'success': True,
            'filename': file.filename,
            'size': len(current_analyzer.data),
            'file_count': len(current_analyzer.files)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files')
def list_files():
    if current_analyzer is None:
        return jsonify({'error': 'No library loaded'}), 400

    files = []
    for f in current_analyzer.files:
        files.append({
            'index': f['index'],
            'name': f['name'],
            'size': f['size'],
            'type': f['type'],
            'mtime': f['mtime']
        })

    return jsonify({'files': files})


@app.route('/api/file/<int:index>')
def get_file_info(index):
    if current_analyzer is None:
        return jsonify({'error': 'No library loaded'}), 400

    file_info = current_analyzer.get_file_info(index)
    if file_info is None:
        return jsonify({'error': 'Invalid file index'}), 404

    return jsonify(file_info)


@app.route('/api/symbols')
def list_symbols():
    if current_analyzer is None:
        return jsonify({'error': 'No library loaded'}), 400

    file_index = request.args.get('file', type=int)

    all_symbols = []

    if file_index is not None:
        if file_index < 0 or file_index >= len(current_analyzer.files):
            return jsonify({'error': 'Invalid file index'}), 404

        files_to_process = [current_analyzer.files[file_index]]
    else:
        files_to_process = [f for f in current_analyzer.files if f['type'] == 'coff']

    print(f"[DEBUG] Total files: {len(current_analyzer.files)}")
    print(f"[DEBUG] COFF files to process: {len(files_to_process)}")

    for i, f in enumerate(current_analyzer.files):
        print(f"[DEBUG] File {i}: name={f['name']}, type={f['type']}, size={f['size']}")

    for file_info in files_to_process:
        if file_info['type'] != 'coff':
            continue

        print(f"[DEBUG] Processing file {file_info['index']}: {file_info['name']}")
        coff = COFFObject(file_info['data'])
        print(f"[DEBUG] COFF symbols count: {len(coff.symbols)}")

        functions = [s for s in coff.symbols if '@@' in s['name'] or s['name'].startswith('?')]
        imports = [s for s in coff.symbols if s['name'].startswith('__imp_')]
        variables = [s for s in coff.symbols if s not in functions and s not in imports]

        print(f"[DEBUG] Functions: {len(functions)}, Imports: {len(imports)}, Variables: {len(variables)}")

        all_symbols.append({
            'file_index': file_info['index'],
            'file_name': file_info['name'],
            'functions': functions[:50],
            'imports': imports[:30],
            'variables': variables[:30],
            'total_symbols': len(coff.symbols)
        })

    print(f"[DEBUG] Returning {len(all_symbols)} symbol groups")

    return jsonify({
        'symbols': all_symbols,
        'total_files': len(current_analyzer.files),
        'coff_files': len(files_to_process)
    })


@app.route('/api/search')
def search():
    if current_analyzer is None:
        return jsonify({'error': 'No library loaded'}), 400

    keyword = request.args.get('q', '')
    if not keyword:
        return jsonify({'error': 'No search keyword provided'}), 400

    results = current_analyzer.search_string(keyword)
    return jsonify({'results': results})


@app.route('/api/extract/<int:index>')
def extract_file(index):
    if current_analyzer is None:
        return jsonify({'error': 'No library loaded'}), 400

    if index < 0 or index >= len(current_analyzer.files):
        return jsonify({'error': 'Invalid file index'}), 404

    file_info = current_analyzer.files[index]

    if file_info['name'].startswith('/'):
        if file_info['type'] == 'coff':
            filename = f"file_{index}.obj"
        else:
            filename = f"file_{index}.bin"
    else:
        filename = file_info['name']

    temp_path = Path(tempfile.gettempdir()) / filename
    with open(temp_path, 'wb') as f:
        f.write(file_info['data'])

    return send_file(temp_path, as_attachment=True, download_name=filename)


if __name__ == '__main__':
    print("=" * 60)
    print("LIB Analyzer Web Server")
    print("=" * 60)
    print("\nStarting server at http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
