/*
 * Author: Brian Bowden
 * 1/13/14
 */

#include "MD5.h"

const uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
                        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
                        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
                        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
                        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
                        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
                        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
                        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
                        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
                        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
                        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
                        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
                        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
                        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
                        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
                        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// These variables will contain the hash
uint32_t h0, h1, h2, h3;
 
bool vflag;

int main(int argc, char **argv) {
    bool pflag = false, mflag = false, fflag = false, oflag = false; 
    vflag = false;
    char *message = NULL, *input_file = NULL, *output_file = NULL;
    int c;

    while((c = getopt(argc, argv, "pm:f:ov")) != -1) {
        switch(c) {
            case 'p':
                pflag = true;
                break;
            case 'm':
                mflag = true;
                message = optarg;
                break;
            case 'f':
                fflag = true;
                input_file = optarg;
                break;
            case 'o':
                oflag = true;
                break;
            case 'v':
                vflag = true;
                break;
            case '?':
                print_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    // Either the message or file flag must be set
    if (!mflag && !fflag) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    // Both flags cannot be set at the same time
    if (mflag && fflag) {
        printf("Error: Cannot run in both message and file mode.\n");
        exit(EXIT_FAILURE);
    }

    // Checks to ensure that a message or input file was given
    if ((mflag && message == NULL) || (fflag && input_file == NULL)) {
        printf("Error: No message or file name was given.\n");
        exit(EXIT_FAILURE);
    }

    // Uses output.txt as the name of the output file
    if (oflag) {
        output_file = "output.txt";
    }

    if (pflag)
        MD5_password(message, input_file, output_file);
    else
        MD5_hash(message, input_file, output_file);
 
    return EXIT_SUCCESS;
}

/*
 * Prints out how to use the MD5 executable.
 */
void print_usage() {
    printf("usage: ./MD5 [-p] [-m message] [-f filename] [-o] [-v]\n"
           "       -p Runs file in password recovery mode.\n"
           "       -m Runs where a given message is hashed or password is recovered.\n"
           "       -f Runs where a given file is hashed or recovered.\n"
           "       -o Runs in output mode, where the results are put in output.txt.\n"
           "       -v Only used for output mode, writes the password used for the hash.\n");
}

/*
 * 
 */
void MD5_password(char *message, char *input_file, char *output_file) {
    bool input = false, output = false;
    FILE *in, *out;
    if (input_file != NULL) {
        input = true;
        in = open_input_file(input_file);
    }
    if (output_file != NULL) {
        output = true;
        out = open_output_file(output_file);
    }

    if (!input) {
        //if (message[0] == '0' && (message[1] == 'x' || message[1] == 'X'))
        if (!output)
            print_hash(message);
        else {
            write_hash(out, message);
            fclose(out);
        }
    }
    else {
        int line_size = DIGEST_SIZE + 3
        char buf[line_size];
        char *msg = (char *) malloc(sizeof(char) * line_size);
        while (fgets(buf, line_size, in) != NULL) {
            sscanf(buf, "%131[^\n\r]\n", msg);
            
            if (!output)
                print_hash(msg);
            else
                write_hash(out, msg);
        }

        // cleanup memory
        free(msg);
        fclose(in);
        if (output)
            fclose(out);

    }
}

void MD5_hash(char *message, char *input_file, char *output_file) {
    bool input = false, output = false;
    FILE *in = NULL, *out = NULL;
    if (input_file != NULL) {
        input = true;
        in = open_input_file(input_file);
    }
    if (output_file != NULL) {
        output = true;
        out = open_output_file(output_file);
    }

    if (!input) {
        size_t len = strlen(message);
        MD5((uint8_t *) message, len);
        if (!output)
            print_hash(message);
        else {
            write_hash(out, message);
            fclose(out);
        }
    }
    else {
        char buf[MAX_MESSAGE_SIZE];
        char *msg = (char *) malloc(sizeof(char) * MAX_MESSAGE_SIZE);
        while (fgets(buf, MAX_MESSAGE_SIZE, in) != NULL) {
            sscanf(buf, "%100[^\n\r]\n", msg);
            // handles the case where the line is the empty string
            if (strlen(buf) == 1)
                msg[0] = '\0';
            size_t len = strlen(msg);
            MD5((uint8_t *) msg, len);
            if (!output)
                print_hash(msg);
            else
                write_hash(out, msg);
        }

        // cleanup memory
        free(msg);
        fclose(in);
        if (output)
            fclose(out);
    }
}

FILE *open_input_file(char *input_file) {
    FILE *fp;
    fp = fopen(input_file, "r");
    if (fp == NULL) {
        printf("Couldn't open file %s for reading.\n", input_file);
        exit(EXIT_FAILURE);
    }
    return fp;
}

FILE *open_output_file(char *output_file) {
    FILE *fp;
    fp = fopen(output_file, "w");
    if (fp == NULL) {
        printf("Couldn't open file %s for writing.\n", output_file);
        exit(EXIT_FAILURE);
    }
    return fp;
}

void write_hash(FILE *out, char *message) {
    uint8_t *p;
    p = (uint8_t *)&h0;
    if (vflag)
        fprintf(out, "0x");
    fprintf(out, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h1;
    fprintf(out, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h2;
    fprintf(out, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h3;
    fprintf(out, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
    
    if (message != NULL && vflag)
        fprintf(out, " - \"%s\"\n", message);
    else
        fprintf(out, "\n");

}

void print_hash(char *message) {
    uint8_t *p;
    p = (uint8_t *)&h0;
    if (vflag) 
        printf("0x");
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h1;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h2;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
 
    p = (uint8_t *)&h3;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
    
    if (message != NULL && vflag)
        printf(" - \"%s\"\n", message);
    else
        printf("\n");
}

void MD5(uint8_t *msg, size_t len) {
    uint8_t *new_msg = NULL;
 
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    int adj_len;
    for(adj_len = ((len << BYTE_SHIFT) + 1); adj_len % 512 != 448; adj_len++);
    adj_len >>= BYTE_SHIFT;
 
    new_msg = (uint8_t *) calloc(adj_len + 64, 1);
    memcpy(new_msg, msg, len);
    new_msg[len] = 128;
 
    uint32_t bits_len = len << BYTE_SHIFT;
    memcpy(new_msg + adj_len, &bits_len, 4);
 
    uint32_t offset, a, b, c, d, f, g, i, tmp;
    for(offset = 0; offset < adj_len; offset += (512 >> BYTE_SHIFT)) {
        uint32_t *w = (uint32_t *) (new_msg + offset);
 
        // Initialize hash value for this chunk:
        a = h0; b = h1; c = h2; d = h3;
 
        for(i = 0; i < 64; i++) {
             if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
 
            tmp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), s[i]);
            a = tmp;
        }
 
        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
 
    // cleanup
    free(new_msg);
}
