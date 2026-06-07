ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
.SHELLFLAGS := /C
EXT = .exe
WIN_LIBS = -lbcrypt -ladvapi32
MKDIR = if not exist $@ mkdir $@
CLEAN_OBJ = if exist $(subst /,\,$(BUILD_DIR))\*.o del /F /Q $(subst /,\,$(BUILD_DIR))\*.o >nul 2>nul & exit /b 0
CLEAN_DEP = if exist $(subst /,\,$(BUILD_DIR))\*.d del /F /Q $(subst /,\,$(BUILD_DIR))\*.d >nul 2>nul & exit /b 0
CLEAN_LIB = if exist $(subst /,\,$(DIST_DIR))\*.a del /F /Q $(subst /,\,$(DIST_DIR))\*.a >nul 2>nul & exit /b 0
CLEAN_EXE = if exist $(subst /,\,$(DIST_DIR))\*.exe del /F /Q $(subst /,\,$(DIST_DIR))\*.exe >nul 2>nul & exit /b 0
CLEAN_RMDIR = if exist $(subst /,\,$(1)) rmdir /S /Q $(subst /,\,$(1)) >nul 2>nul & exit /b 0
else
SHELL := /bin/sh
.SHELLFLAGS := -c
EXT =
WIN_LIBS =
MKDIR = mkdir -p $@
CLEAN_OBJ = rm -f $(BUILD_DIR)/*.o
CLEAN_DEP = rm -f $(BUILD_DIR)/*.d
CLEAN_LIB = rm -f $(DIST_DIR)/*.a
CLEAN_EXE = rm -f $(DIST_DIR)/*
CLEAN_RMDIR = rm -rf $(1)
endif

SRC_DIR = src
INC_DIR = include
DEMO_DIR = demo
BUILD_DIR = build
DIST_DIR = dist

SRCS = $(filter-out $(SRC_DIR)/crypto.c, $(wildcard $(SRC_DIR)/*.c))
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

LIBRARY = $(DIST_DIR)/libmycrypto.a
CLI_SRC = $(SRC_DIR)/crypto.c
CLI_EXE = $(DIST_DIR)/crypto$(EXT)
DEMO_SRC = $(DEMO_DIR)/demo.c
DEMO_EXE = $(BUILD_DIR)/demo$(EXT)

CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -O2 -I$(INC_DIR) -MMD -MP
ARFLAGS = rcs

ARCH := $(shell uname -m 2>nul || echo unknown)
ifneq (,$(filter x86_64 amd64,$(ARCH)))
  RDRAND_FLAG = -mrdrnd
else
  RDRAND_FLAG =
endif

LIBS = -L$(DIST_DIR) -lmycrypto $(WIN_LIBS)

all: $(LIBRARY) $(CLI_EXE) $(DEMO_EXE)

$(LIBRARY): $(OBJS) | $(DIST_DIR)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/rand_util.o: $(SRC_DIR)/rand_util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RDRAND_FLAG) -c $< -o $@

$(CLI_EXE): $(CLI_SRC) $(LIBRARY) | $(BUILD_DIR) $(DIST_DIR)
	$(CC) $(CFLAGS) -MF $(BUILD_DIR)/crypto.d $< $(LIBS) -o $@

$(DEMO_EXE): $(DEMO_SRC) $(LIBRARY) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -MF $(BUILD_DIR)/demo.d $< $(LIBS) -o $@

-include $(wildcard $(BUILD_DIR)/*.d)

$(BUILD_DIR) $(DIST_DIR):
	$(MKDIR)

clean:
	$(CLEAN_OBJ)
	$(CLEAN_DEP)
	$(CLEAN_LIB)
	$(CLEAN_EXE)
	$(call CLEAN_RMDIR,$(BUILD_DIR))
	$(call CLEAN_RMDIR,$(DIST_DIR))

.PHONY: all clean
