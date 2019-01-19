## UnifiedLogReader
A parser for Unified logging .tracev3 files.

Tracev3 files are compressed log files which can't be parsed individually on their own due to dependencies on other files. These dependencies are-
* TimeSync files - contains boot uuid and continuous time to actual time mapping
* DSC files - contains most common format strings 
* Uuidtext files - contains format strings

Each has a different format. These files have to be parsed together and pieced together to recreate the log entries. 

_This is a work in progress.._

#### Project Status: alpha, experimental
#### Requirements: 32 bit Python 2.7 with modules lz4, biplist and ipaddress
The modules can easily be installed using `pip install lz4 biplist ipaddress`
