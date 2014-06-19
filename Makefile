all: big_dog_guard.cpp
	g++ big_dog_guard.cpp -o big_dog_guard -I/usr/include/tcl8.5 -ltcl8.5 -g -Wall

install: big_dog_guard
	cp big_dog_guard /root/big_dog_guard/
