#
# To run the demos when linked with a shared library (default) ensure
# that libcrypto is on the library path. For example:
#
#    LD_LIBRARY_PATH=../.. ./x25519


# 2024-1-16
# 定义了四个任务all、x25519、clean和test
# 可以使用make all / x25519 / clean /test 等命令来make
#  其中定义了依赖关系all依赖于x25519，test依赖于all
TESTS = x25519

CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lcrypto

all: $(TESTS) #定义了一个名称为all的伪目标，该伪目标依赖于$(TESTS)

# x25519 是目标，表示我们要构建的可执行文件或目标文件的名称。
# x25519.o 是依赖项，表示构建 x25519 目标所需的源文件或中间目标文件。
# 如果x25519目标不存在，或者它的任何依赖项（例如 x25519.o）的修改时间比 x25519 更新，那么需要执行后面的命令
x25519: x25519.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS) 
# $(CC)代表的是编译器
# $@代表的是当前规则的目标（在此处为X25519）
# $@代表当前规则的依赖项（在此处为x25519.o）

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
test: all
	@echo "\nKeyExchange tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		LD_LIBRARY_PATH=../.. ./$$tst; \
	done
