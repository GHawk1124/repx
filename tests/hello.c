// A simple C test program for repx attestation testing.
//
// This program reads an input file, transforms it, and writes an output file.
// It exercises the key syscalls that repx traces: open, read, write, close,
// execve (when launched), and exit.
//
// Usage:
//   gcc -o hello hello.c
//   echo "Hello World" > input.txt
//   ./hello input.txt output.txt
//
// The program:
//   1. Opens and reads the input file
//   2. Transforms the content (converts to uppercase)
//   3. Writes the transformed content to the output file
//   4. Exits with code 0 on success

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    // Read input file.
    FILE *in = fopen(input_path, "r");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    char buf[MAX_SIZE];
    size_t n = fread(buf, 1, sizeof(buf) - 1, in);
    buf[n] = '\0';
    fclose(in);

    // Transform: convert to uppercase.
    for (size_t i = 0; i < n; i++) {
        buf[i] = toupper((unsigned char)buf[i]);
    }

    // Write output file.
    FILE *out = fopen(output_path, "w");
    if (!out) {
        perror("fopen output");
        return 1;
    }

    fwrite(buf, 1, n, out);
    fclose(out);

    printf("Transformed %zu bytes: %s -> %s\n", n, input_path, output_path);
    return 0;
}
