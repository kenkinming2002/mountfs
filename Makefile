CFLAGS+=$(shell pkg-config --cflags fuse3)
LDLIBS+=$(shell pkg-config --libs fuse3)

all: mountfs
