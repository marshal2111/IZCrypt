
SRC_DIR := ../../src/cpp
IDIR := ../../src/h
OBJ_DIR := obj
LIB_DIR := lib

LIB := $(LIB_DIR)/izcrypt.a
SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

CPPFLAGS := -Ih -Ih/cipher -Ih/cipher/mode -MMD -MP
LDFLAGS  := -Llib

.PHONY: all clean

all: $(LIB) | $(LIB_DIR)

$(LIB): $(OBJ)
	ar rcs $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	gcc $(CPPFLAGS) -c $< -o $@ 

$(LIB_DIR) $(OBJ_DIR):
	mkdir -p $@
	
clean:
	@$(RM) -rv $(LIB_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
