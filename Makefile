format:
	astyle --style=otbs --indent=spaces=2 *.c

build:
	gcc stderr_in_color.c -D_GNU_SOURCE -Wall -fPIC -ldl -shared -o stderr-in-color.so
