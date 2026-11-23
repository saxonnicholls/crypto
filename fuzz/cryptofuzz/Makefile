# Builds the snicholls-crypto Cryptofuzz module, from cryptofuzz/modules/snicholls-crypto/ (fuzz/cryptofuzz/build.sh
# copies it there). The library is header-only: SNICHOLLS_CRYPTO_PATH is a checkout, with its core submodule.

all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++20 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp module.h
	test $(SNICHOLLS_CRYPTO_PATH)
	$(CXX) $(CXXFLAGS) -I $(SNICHOLLS_CRYPTO_PATH)/include -I $(SNICHOLLS_CRYPTO_PATH)/third_party/core/include \
	    -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
