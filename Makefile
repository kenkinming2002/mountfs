PKG_CONFIG ?= pkg-config

CFLAGS+=$(shell $(PKG_CONFIG) --cflags fuse3)
LDLIBS+=$(shell $(PKG_CONFIG) --libs fuse3)

all: mountfs
