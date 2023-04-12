
if [ ! -d libebpf ]; then
	git clone https://github.com/IoTAccessControl/libebpf.git
fi

rm -rf *.c
rm -rf *.h

cp libebpf/src/*.c .
cp libebpf/src/*.h .
cp libebpf/inc/*.h .