.PHONY: all
all: depick

depick: main.o
	g++ $< -o $@

%.o: %.cpp
	g++ -c -g3 $< -o $@