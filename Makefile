LIBUV_BRANCH=v1.7.1
LIBH2O_BRANCH=v1.3.1

letsbuildthis:
	python waf configure
	python waf build

clean:
	python waf clean

libh2o_build:
	cd deps/h2o && cmake . -DCMAKE_INCLUDE_PATH=../libuv/include -DLIBUV_LIBRARIES=1
	cd deps/h2o && make libh2o
	cp deps/h2o/libh2o.a .
.PHONY : libh2o_build

libh2o_fetch:
	if test -e deps/h2o; \
	then cd deps/h2o && rm -f CMakeCache.txt && git pull origin $(LIBH2O_BRANCH) ; \
	else git clone https://github.com/h2o/h2o deps/h2o; \
	fi
	cd deps/h2o && git checkout $(LIBH2O_BRANCH)
.PHONY : libh2o_fetch

libh2o: libh2o_fetch libh2o_build
.PHONY : libh2o

libh2o_vendor:
	rm -rf deps/h2o/.git > /dev/null
.PHONY : libh2o_vendor

libuv_build:
	cd deps/libuv && sh autogen.sh
	cd deps/libuv && ./configure
	cd deps/libuv && make
	cp deps/libuv/.libs/libuv.a .
.PHONY : libuv_build

libuv_fetch:
	if test -e deps/libuv; \
	then cd deps/libuv && git pull origin $(LIBUV_BRANCH); \
	else git clone https://github.com/libuv/libuv deps/libuv; \
	fi
	cd deps/libuv && git checkout $(LIBUV_BRANCH)
.PHONY : libuv_fetch

libuv: libuv_fetch libuv_build
.PHONY : libuv

libuv_vendor:
	rm -rf deps/libuv/.git > /dev/null
.PHONY : libuv_vendor


