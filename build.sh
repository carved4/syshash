#!/bin/bash

# Syshash C Implementation Build Script
# Requires: mingw64 with gcc and nasm

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_NAME="syshash"
SOURCE_FILE="main.c"
BUILD_DIR="build"

echo -e "${BLUE}=== Syshash C Implementation Build Script ===${NC}"
echo -e "${BLUE}Building for Windows x64 using mingw64...${NC}"

# Check if we have the required tools
echo -e "${YELLOW}Checking for required tools...${NC}"

if ! command -v gcc &> /dev/null; then
    echo -e "${RED}ERROR: gcc not found. Please install mingw64.${NC}"
    exit 1
fi

if ! command -v nasm &> /dev/null; then
    echo -e "${RED}ERROR: nasm not found. Please install nasm.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ gcc found: $(gcc --version | head -n1)${NC}"
echo -e "${GREEN}✓ nasm found: $(nasm --version)${NC}"

# Create build directory
echo -e "${YELLOW}Creating build directory...${NC}"
mkdir -p "$BUILD_DIR"

# Check if source file exists
if [ ! -f "$SOURCE_FILE" ]; then
    echo -e "${RED}ERROR: Source file '$SOURCE_FILE' not found!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Source file found: $SOURCE_FILE${NC}"

# Compiler flags
CFLAGS="-std=c11 -Wall -Wextra -O2 -m64"
LDFLAGS="-lkernel32 -lntdll -ladvapi32 -static-libgcc"

# Debug build option
if [[ "$1" == "debug" ]]; then
    echo -e "${YELLOW}Building DEBUG version...${NC}"
    CFLAGS="$CFLAGS -g -DDEBUG -O0"
    OUTPUT_NAME="${OUTPUT_NAME}_debug"
else
    echo -e "${YELLOW}Building RELEASE version...${NC}"
    CFLAGS="$CFLAGS -DNDEBUG -s"
    LDFLAGS="$LDFLAGS -Wl,--strip-all"
fi

# Build command
BUILD_CMD="gcc $CFLAGS $SOURCE_FILE -o $BUILD_DIR/${OUTPUT_NAME}.exe $LDFLAGS"

echo -e "${YELLOW}Compiling...${NC}"
echo -e "${BLUE}Command: $BUILD_CMD${NC}"

# Execute build
if $BUILD_CMD 2>&1; then
    echo -e "${GREEN}✓ Build successful!${NC}"
    echo -e "${GREEN}✓ Executable created: $BUILD_DIR/${OUTPUT_NAME}.exe${NC}"
    
    # Get file size
    FILE_SIZE=$(stat -c%s "$BUILD_DIR/${OUTPUT_NAME}.exe" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ File size: $FILE_SIZE bytes${NC}"
    
    echo ""
    echo -e "${GREEN}Build completed successfully!${NC}"
else
    echo -e "${RED}✗ Build failed!${NC}"
    exit 1
fi 