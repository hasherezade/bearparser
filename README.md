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
