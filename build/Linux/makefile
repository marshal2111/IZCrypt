
SRC_DIR := ../../src/cpp
IDIR := ../../src/h
OBJ_DIR := obj
LIB_DIR := lib

LIB := $(LIB_DIR)/izcrypt
SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))
# DEPS := $(wildcard $(IDIR)/*.h) 

CPPFLAGS := -Ih -Ih/cipher -Ih/cipher/mode -MMD -MP
LDFLAGS  := -Llib

.PHONY: all clean

all: $(LIB) 

$(LIB): $(OBJ) lib.a
	gcc $(LDFLAGS) $^ -o $@

	
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	gcc $(CPPFLAGS) -c $< -o $@ 

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@
	
lib.a: $(OBJ)
	ar rcs $@ $^
	
# main.o: main.c
# 	gcc -c $< -o $@
# 
# lib.a: lib1.o lib2.o
# 	ar rcs $@ $^
# 
# lib1.o: lib1.c lib1.h
# 	gcc -c -o $@ $<
# 
# lib2.o: lib2.c lib2.h
# 	gcc -c -o $@ $<

clean:
	@$(RM) -rv $(LIB_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
