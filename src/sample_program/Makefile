asm: test_source.cpp
	g++ -S -o test_source.s test_source.cpp

out: test_source_metered.s result_wrapper.cpp
	g++ -g -o work_enclave.out test_source_metered.s result_wrapper.cpp
