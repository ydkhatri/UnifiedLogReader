# UnifiedLogReader
A parser for Unified logging .tracev3 files.

## Project Status
#### alpha, experimental
_This is a work in progress.. Currently this does not support the first version of tracev3 which is seen on macOS 10.12.0 (which uses catalog v2). It has been tested to work on catalog v3 files used in macOS 10.12.5 upto the current 10.14.3_

## License
MIT
## Requirements
32 bit Python 2.7 and the following modules
* lz4
* biplist
* ipaddress

The modules can easily be installed using `pip install lz4 biplist ipaddress`

## Usage
The script needs access to files from 3 folders -
* /private/var/db/diagnostics
* /private/var/db/diagnostics/timesync
* /private/var/db/uuidtext

The tracev3 files are located within the diagnostics folder. If you have a disk image, just extract the diagnostics and uuidtext folders (shown at paths above) and provide it to this script.

Currently the script supports TSV and sqlite output.
## Output options
_SQLITE_ gives you every available field in an sqlite db  
_TSV_ALL_ gives you every available field in a tab-seperated file  
_TSV_DEFAULT_ gives only those fields shown by 'log' utility (with no options specified)


```
G:\>c:\Python27\python.exe c:\Github\UnifiedLogReader\UnifiedLogReader.py -h
usage: UnifiedLogReader.py [-h] [-f OUTPUT_FORMAT] [-l LOG_LEVEL]
                           uuidtext_path timesync_path tracev3_path
                           output_path

UnifiedLogReader is a tool to read macOS Unified Logging tracev3 files.
This is version 1.0 tested on macOS 10.12.5 - 10.14.3.

Notes:
-----
If you have a .logarchive, then point uuidtext_path to the .logarchive folder,
 the timesync folder is within the logarchive folder

positional arguments:
  uuidtext_path         Path to uuidtext folder (/var/db/uuidtext)
  timesync_path         Path to timesync folder (/var/db/diagnostics/timesync)
  tracev3_path          Path to either tracev3 file or folder to recurse (/var/db/diagnostics)
  output_path           An existing folder where output will be saved

optional arguments:
  -h, --help            show this help message and exit
  -f OUTPUT_FORMAT, --output_format OUTPUT_FORMAT
                        SQLITE, TSV_ALL, TSV_DEFAULT  (Default is TSV_DEFAULT)
  -l LOG_LEVEL, --log_level LOG_LEVEL
                        Log levels: INFO, DEBUG, WARNING, ERROR (Default is INFO)
```
