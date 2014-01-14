#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_MESSAGE_SIZE 100
#define DIGEST_SIZE 128
#define BYTE_LENGTH 8
#define BYTE_SHIFT 3
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c)))) 

typedef char bool;
#define false (char)0
#define true (char)1

void MD5(uint8_t *msg, size_t len);
void print_usage();
void MD5_password(char *message, char *input_file, char *output_file);
void MD5_hash(char *message, char *input_file, char *output_file);
FILE *open_input_file(char *input_file);
FILE *open_output_file(char *output_file);
void print_hash(char *message);
void write_hash(FILE *fp, char *messag);
