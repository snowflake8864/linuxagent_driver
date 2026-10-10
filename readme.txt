ctags -R --languages=C,C++ --exclude=*.py --exclude=*.js
find . -name "*.[ch]" -o  -name "*.cpp" -o  -name "*.hpp" >cscope.files
cscope -qbR
