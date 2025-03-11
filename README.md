# JAR Poisoner
Replaces every class in a JAR file with a malicious one.

## Usage
```plain
usage: poison.py [-h] [-p PAYLOAD] [-t TEMPLATE] [-a [TEMPLATE_ARGS ...]] [-l] input output

Poison a JAR file

positional arguments:
  input                 JAR file to poison
  output                Output JAR file

options:
  -h, --help            show this help message and exit
  -p, --payload PAYLOAD
                        Payload to inject
  -t, --template TEMPLATE
                        Payload template
  -a, --template-args [TEMPLATE_ARGS ...]
                        Payload template arguments
  -l, --list-templates  List available payload templates
```
