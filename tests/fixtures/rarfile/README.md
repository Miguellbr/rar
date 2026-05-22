# rarfile test corpus

the `.rar`/`.r00`/`.sfx` archives in `files/` and their paired `.exp` golden
dumps are vendored from the [rarfile](https://github.com/markokr/rarfile)
project by Marko Kreen.

## provenance

| | |
| --- | --- |
| source | <https://github.com/markokr/rarfile> |
| path | `test/files/` |
| commit | `db1df339574e76dafb8457e848a09c3c074b03a0` |
| date | 2024-04-07 |

to refresh the corpus, re-copy `test/files/` from the rarfile repository at a
known commit and update the table above.

these files are licensed under ISC (see `LICENSE` in this directory), separate
from the 0BSD license covering the rest of this repository. they are used as
test fixtures only and are not part of the published package.

the `.exp` files are golden dumps produced by rarfile's `dumprar.py`; the test
suite reproduces that dump format to diff against them.
