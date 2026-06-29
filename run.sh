gcc -o a.out src/main.c src/report_utils.c src/report.c src/route.c src/sniff.c src/storage.c src/utils.c src/llm.c src/sniper.c -lpcap -lcurl
./a.out
rm a.out