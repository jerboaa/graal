# Debugging native-image-utils with GDB

The native-image-utils binary allows for extraction of compressed SBOM bytes
from another native image.

Debugging native-image-utils requires building it with debug symbols.  To do
that, execute:

```bash
$ native-image -g --macro:native-image-utils-launcher
```

Then you can debug `native-image-utils` with GDB:

```bash
$ gdb --args native-image-utils extract-sbom --image-path=/path/to/native-image-with-sbom-embedded
```
