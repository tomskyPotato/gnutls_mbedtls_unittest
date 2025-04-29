# Makefile für die Automatisierung von Build und Run mit gcc

# Compiler und Flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lm

# Verzeichnisse
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = binary

# Dateien
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
EXECUTABLE = $(BIN_DIR)/program

# Standardziel
all: 
	$(EXECUTABLE)

	# Verzeichnisse erstellen
	$(OBJ_DIR):
		mkdir $(OBJ_DIR)

	$(BIN_DIR):
		mkdir $(BIN_DIR)

	# Linken
	$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
		$(CC) $(OBJECTS) $(LDFLAGS) -o $@

	# Objektdateien erstellen
	$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
		$(CC) $(CFLAGS) -c $< -o $@

# Ausführen
run: 
	$(EXECUTABLE)
	./$(EXECUTABLE)

# Aufräumen
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Phony-Ziele
.PHONY: all run clean