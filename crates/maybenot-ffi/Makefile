CARGO ?= cargo
TARGET ?=
PROFILE ?= release
DESTINATION ?= .

CARGOFLAGS += --locked
TARGET_DIR := ../../target/$(TARGET)/$(PROFILE)

ifeq ($(PROFILE), release)
	CARGOFLAGS += --release
endif

ifneq ($(TARGET),)
	CARGOFLAGS += --target
	CARGOFLAGS += $(TARGET)
endif

.PHONY: clean

# copy the library to the final destination, and strip the _ffi part
$(DESTINATION)/libmaybenot.a: $(TARGET_DIR)/libmaybenot_ffi.a
	cp $^ $@

# build the static library
$(TARGET_DIR)/libmaybenot_ffi.a: src/*.rs Cargo.toml
	RUSTFLAGS="-C metadata=maybenot-ffi" ${CARGO} build $(CARGOFLAGS)

clean:
	rm -f $(DESTINATION)/libmaybenot.a
	cargo clean
