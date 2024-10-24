CBINDGEN ?= cbindgen
CARGO ?= cargo
TARGET ?=
PROFILE ?= release
DESTINATION ?= .
CARGO_TARGET_DIR ?= ../../target

CARGO_OUTPUT_DIR := $(CARGO_TARGET_DIR)/$(TARGET)/$(PROFILE)
CARGOFLAGS += --target-dir $(CARGO_TARGET_DIR)

ifeq ($(PROFILE), release)
	CARGOFLAGS += --release
endif

ifneq ($(TARGET),)
	CARGOFLAGS += --target
	CARGOFLAGS += $(TARGET)
endif

.PHONY: clean

# copy the library to the final destination, and strip the _ffi part
$(DESTINATION)/libmaybenot.a: $(CARGO_OUTPUT_DIR)/libmaybenot_ffi.a
	cp $^ $@

# generate maybenot.h
maybenot.h: src/*.rs Cargo.toml cbindgen.toml
	${CBINDGEN} -o maybenot.h

# build the static library
$(CARGO_OUTPUT_DIR)/libmaybenot_ffi.a: maybenot.h src/*.rs Cargo.toml cbindgen.toml
	RUSTFLAGS="-C metadata=maybenot-ffi" ${CARGO} build $(CARGOFLAGS)

clean:
	rm -f $(DESTINATION)/libmaybenot.a
	${CARGO} clean $(CARGOFLAGS)
