
modname = mod_token_auth

MODULES   := core
SRC_DIR   := $(addprefix src/,$(MODULES))
BUILD_DIR := $(addprefix build/,$(MODULES))

SRC       := $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ       := $(patsubst src/%.c,build/%.o,$(SRC))

INCLUDES  := $(addprefix -I,$(SRC_DIR)) -I/usr/include/apache2 -I/usr/include/apr-1.0 

.PHONY: all checkdirs

all: checkdirs $(OBJ)
	@#echo $(BUILD_DIR)
	@#echo $(SRC_DIR)
	@#echo $(SRC)
	@#echo $(OBJ)
	@#echo $(INCLUDES)
	@#sudo apxs -i -a -l cryptoc -l ssl -l crypto -Wc,-Wall -I . -n $(modname) -c src/core/mod_token_auth.c $(OBJ)
	@echo "Building the Apache2 module..."
	@#@sudo apxs -i -a -l cryptoc -l ssl -l crypto -Wc,-Wall $(INCLUDES) -n $(modname) -c src/core/mod_token_auth.c $(OBJ)
	@sudo apxs -i -a -l cryptoc -l ssl -l crypto -Wc,-Wall $(INCLUDES) -n $(modname) -c $(SRC)
	@echo "Success! All done. Module $(modname) built successfully"

checkdirs: $(BUILD_DIR)
	
$(BUILD_DIR):
	@mkdir -p $@

#$(builddir)/%.o: %.c *.h
#	@gcc -O -c $(INCLUDES) -Wall -o $$@ $$<

define make-goal
$1/%.o: $(patsubst build/%,src/%,$1)/%.c
	@echo $1
	@echo $1/%.o and $(patsubst build/%,src/%,$1)%.c
	@gcc -std=c99 -std=gnu99 -O $(INCLUDES) -Wall -fPIC -o $$@ -c $$<
endef

$(foreach bdir,$(BUILD_DIR),$(eval $(call make-goal,$(bdir))))

#build/core/%.o: src/core/%.c
#	@gcc -std=c99 -std=gnu99 -O $(INCLUDES) -fPIC -Wall -o $@ -c $<

.PHONY: clean 
clean:
	@echo "Cleaning build directory..."
	@rm -rf $(builddir) || true


