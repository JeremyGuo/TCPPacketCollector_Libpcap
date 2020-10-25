objects = collector.o mdata.o mqueue.o localstorage.o

main: ${objects} mdb.o
	gcc ./src/main.c -c -o ./build/main.o
	gcc ./build/*.o -o ./build/main -lpthread -lpcap -lrt

main2: ${objects} mdb2.o
	gcc ./src/main.c -c -o ./build/main.o -DMDB2
	gcc ./build/*.o -o ./build/main -lpthread -lpcap -lrt -DMDB2

localstorage.o: ./src/localstorage.c
	gcc ./src/localstorage.c -c -o ./build/localstorage.o

collector.o: ./src/collector.c
	gcc ./src/collector.c -c -o ./build/collector.o

mqueue.o: ./src/mqueue.c
	gcc ./src/mqueue.c -c -o ./build/mqueue.o

mdata.o: ./src/mdata.c
	gcc ./src/mdata.c -c -o ./build/mdata.o

mdb.o: ./src/mdb.c
	gcc ./src/mdb.c -c -o ./build/mdb.o

mdb2.o: ./src/mdb2.c
	gcc ./src/mdb2.c -c -o ./build/mdb2.o

clean:
	rm -rf ./build/*