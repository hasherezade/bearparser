bearparser
==========

Portable Executable parsing library<br/>
WARNING: this is an early beta version, some elements are unfinished!<br/>
Please report any bugs and remarks to: hasherezade@op.pl<br/>

Requires:
+ Qt4 Core<br/>
+ cmake http://www.cmake.org/<br/>

How to build (example step-by-step):
===
<pre>
mkdir re-bear
git clone https://github.com/hasherezade/bearparser.git
mkdir build
cd build
cmake -G [some generator] ../bearparser/
make
</pre>
Done!
You can test it running the commander:<br/>
<pre>
./commander/bearcommander [optional: path to exe]<br/>
</pre>

bearcommander
===
<b>WARNING: Commander is <u>very</u> basic tool, used only for the purpose of testing the library capabilities.<br/>
It's not a fully functional tool - or at least not yet!</b>
Sample usage:<br/>
<pre>
hshrzd@kali:~/mytest/build$ ./commander/bearcommander
Starting...
Path to executable: /home/hshrzd/vm_shared/corkami_samples/exe/cfbogus.exe
Type: PE
Buffering...
Parsing executable...
$ info
Bit mode: 	32
Entry point: 	0x1000v
Raw size: 	0x400
Virtual size: 	0x2000
Raw align.: 	0x200
Virtual align.:	0x1000
Contains:
[ 0] DOS Hdr
[ 1] File Hdr
[ 2] Optional Hdr
[ 3] Data Directory
[ 4] Section Hdrs
[ 5] Imports
[12] LdConfig
</pre>
Use <i>dump</i> command to see the details of particular structure,<br/>
i.e.<br/> 
<i>dump 12</i> dumps LdConfig
