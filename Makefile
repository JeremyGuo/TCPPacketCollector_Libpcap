objects = collector.o mdata.o mqueue.o localstorage.o

main: ${objects} mdb.o
	gcc ./src/main.c -c -o ./build/main.o
	gcc ./build/*.o -o ./build/main -lpthread -lpcap -lrt

main2: ${objects} mdb2.o
	gcc ./src/main.c -c -o ./build/main.o -DMDB2 -g
	gcc ./build/*.o -o ./build/main -lpthread -lpcap -lrt -DMDB2 -g

localstorage.o: ./src/localstorage.c
	gcc ./src/localstorage.c -c -o ./build/localstorage.o -g

collector.o: ./src/collector.c
	gcc ./src/collector.c -c -o ./build/collector.o -g

mqueue.o: ./src/mqueue.c
	gcc ./src/mqueue.c -c -lpthread -o ./build/mqueue.o -g

mdata.o: ./src/mdata.c
	gcc ./src/mdata.c -c -o ./build/mdata.o -g

mdb.o: ./src/mdb.c
	gcc ./src/mdb.c -c -o ./build/mdb.o -g

mdb2.o: ./src/mdb2.c
	gcc ./src/mdb2.c -c -o ./build/mdb2.o -g

clean:
	rm -rf ./build/*
