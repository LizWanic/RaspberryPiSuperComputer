// Functions base64_cleanup(), build_decoding_table(), base64_decode()
// taken from : http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

/*  This program is used for SHA1 password cracking. It is build as a demonstration for parallel
 *  computing on Hamming for CS3200 course. This code is the modified parallel code.
 *  It takes some arguments:
 *      -f filename     the name of the file containing the SHA1 password. It is optional and the default
 *                      is 'htpasswd-brute'
 *      -min n          where n is the password length. The argument is -min because I wanted to include
 *                      multiple password length support, but the time was not enough.
 *      -c naA          is the option for the available characters to create the passwords.
 *                      n is for numbers
 *                      a for lower-case letters
 *                      A for upper-case letters
 *                      Any combination is available
 *      -v 1            outputs some extra information. User for some debugging issues.
 */

//#define DEBUG 1

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>
#include <math.h>
#include <mpi.h>

#define MAX_ROWS 1000000
#define SEND_USER_TAG 2001
#define SEND_DATA_TAG 2002
#define SEND_DONE_TAG 2000
#define SEND_CRACKED_TAG 3000
#define RETURN_DATA_TAG 2003

int gen(int, int, char*, char*, const char*, int, unsigned char**, int, int*, long int*, char**, void*, int, int);
int check_digests(unsigned char*, unsigned char**, char*, int, int *, char**, void*);
void read_file(FILE*, int*, char**, unsigned char**, char*);
void allocate_charset(int, char*);
int calc_charset(int*, char*);
void base64_cleanup();
void build_decoding_table();
unsigned char *base64_decode(const char *, size_t, size_t *);
void showhelp();


static unsigned const char base16[] = "0123456789ABCDEF";
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;


int main(int argc, char** argv){
    int ierr;
    int my_id, root, proc_num;
    MPI_Status status;
    void* data[100];

    int pass_length_min = 4;
    int v = 0;
    int charset = 1;
    int charset_length = 10;
    char filename[] = "htpasswd-brute";

    // Check for arguments
    if(argc > 1){
        for(int a = 1;a < argc;a = a + 2){
            if(strcmp(argv[a], "-min") == 0){
                pass_length_min = atoi(argv[a + 1]);
            }
            else if(strcmp(argv[a], "-v") == 0){
                v = atoi(argv[a + 1]);
            }
            else if(strcmp(argv[a], "-f") == 0){
                strcpy(filename, argv[a + 1]);
            }
            else if(strcmp(argv[a], "-c") == 0){
                charset_length = calc_charset(&charset, argv[a+1]);
            }
        }
    }
    else{
        showhelp();
        return -1;
    }

    setlocale(LC_NUMERIC, "");

    char passwd[pass_length_min + 1];
    char cracked_passwd[pass_length_min + 1];
    char chars[charset_length + 1];
    char* names[50];
    char line[100];
    unsigned char* digests[21];
    int cracked = 0;
    long int passwd_space_checked = 0;
    int j = 0;
    int user;
    clock_t start, diff;
    FILE* f;

    // Check for file
    f = fopen(filename, "r");
    if(f == NULL){
        return -1;
    }

    ierr = MPI_Init(&argc, &argv);
    root = 0;
    ierr = MPI_Comm_rank(MPI_COMM_WORLD, &my_id);
    ierr = MPI_Comm_size(MPI_COMM_WORLD, &proc_num);

    allocate_charset(charset, chars);

    read_file(f, &j, names, digests, line);

    base64_cleanup();
    fclose(f);

    if(my_id == 0){

        printf("%d users found. ", j);
        printf("Password length set to: %d\n", pass_length_min);
        printf("%ld Different characters to be used: %s\n", strlen(chars), chars);
        printf("Total passwords to calculate: %'.f\n", pow(strlen(chars), pass_length_min));
        printf("Starting timer...\n");

        start = clock();

        printf("%d processes started.\n", proc_num);
        int returned = 0;

        while(returned < proc_num - 1) {
                int ierr = MPI_Recv(data, 1, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

                if (status.MPI_TAG == SEND_DONE_TAG) {
                    returned++;
                }
                else if (status.MPI_TAG == SEND_CRACKED_TAG) {
                    cracked++;
                }

            if(cracked == j){
                break;
            }
        }
        if(cracked == j){
            printf("All passwords found...\n");
            MPI_Abort(MPI_COMM_WORLD, 0);
        }

        diff = clock() - start;

        int msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken %d hours, %d minutes, %d seconds and %d milliseconds.\n",
               msec/3600000 ,(msec%3600000)/60000, (msec%60000)/1000, msec%1000);

    }
    else{

        gen(pass_length_min, pass_length_min, passwd, chars, base16, v,
            digests, j, &cracked, &passwd_space_checked, names, data, my_id, proc_num);

        printf("ID %d - %'ld passwords checked.\n", my_id, passwd_space_checked);
        int done = -1;
        ierr = MPI_Send( &done, 1 , MPI_INT, 0, SEND_DONE_TAG, MPI_COMM_WORLD);

    }
    MPI_Finalize();
    return 0;
}


int gen(int init_len, int len, char* passwd, char* char_set, const char* base16,
        int v, unsigned char** digests, int population, int* cracked, long int* checked,
        char** names, void* data, int my_id, int proc_num){

    int i;

    if(len == 0){
        unsigned char hash[SHA_DIGEST_LENGTH];
        size_t l = sizeof(passwd);
        *(passwd + init_len) = '\0';

        SHA1(passwd, l, hash);

        *cracked =+ check_digests(hash, digests, passwd, population, cracked, names, data);
        *checked = *checked + 1;

    }
    else if(len == 1){
        for (i = my_id - 1; i < strlen(char_set); i = i + (proc_num - 1)) {
            *(passwd + (init_len - len)) = *(char_set + i);
            gen(init_len, len - 1, passwd, char_set, base16, v, digests, population, cracked, checked, names, data, my_id, proc_num);
        }
    }
    else{
#ifdef DEBUG
        if(len == 8) {

            for (i = 0; i < strlen(char_set); i++) {
                if(v == 1)
                    if(len == init_len)
                        printf("Id %d Checking %c%.*s\n", my_id, *(char_set + i), init_len - 1, "***************************");

                *(passwd + (init_len - len)) = *(char_set + i);
                gen(init_len, len - 1, passwd, char_set, base16, v, digests, population, cracked, checked, names, data, my_id, proc_num);
            }
        }
        else if(len == 7){
            for (i = 13; i < strlen(char_set); i++) {
                *(passwd + (init_len - len)) = *(char_set + i);
                gen(init_len, len - 1, passwd, char_set, base16, v, digests, population, cracked, checked, names, data, my_id, proc_num);
            }
        }
        else {
#endif
        for (i = 0; i < strlen(char_set); i++) {
            if(v == 1)
                if(len == init_len)
                    printf("Id %d Checking %c%.*s\n", my_id, *(char_set + i), init_len - 1, "***************************");

            *(passwd + (init_len - len)) = *(char_set + i);
            gen(init_len, len - 1, passwd, char_set, base16, v, digests, population, cracked, checked, names, data, my_id, proc_num);// == 1)
        }
#ifdef DEBUG
        }
#endif
    }
    return 0;
}


int check_digests(unsigned char *hash, unsigned char** digests, char* passwd, int population, int* cracked, char** names, void* data){
    int pos = 0;
    int ierr;

    for(pos = 0;pos < population;pos++){
        if(memcmp(*(digests + pos), hash, SHA_DIGEST_LENGTH) == 0){
            printf("Password for entry %d is %s\n", pos, passwd);

            ierr = MPI_Send( &cracked, 1 , MPI_INT, 0, SEND_CRACKED_TAG, MPI_COMM_WORLD);
            return 1;
        }
    }
    return 0;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    // Taken from : http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        int sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        int sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        int sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        int sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        int triple = (sextet_a << 3 * 6)
                     + (sextet_b << 2 * 6)
                     + (sextet_c << 1 * 6)
                     + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}


void allocate_charset(int val, char* chars){

    int dummy;

    if(val == 1){
        for(dummy=48;dummy<58;dummy++){
            *(chars + dummy - 48) = dummy;
        }
        *(chars + 10) = '\0';
    }
    else if(val == 2){
        for(dummy=97;dummy<123;dummy++){
            *(chars + dummy - 97) = dummy;
        }
        *(chars + 26) = '\0';
    }
    else if(val == 3){
        for(dummy=48;dummy<58;dummy++){
            *(chars + dummy - 48) = dummy;
        }
        for(dummy=97;dummy<123;dummy++){
            *(chars + dummy - 97 + 10) = dummy;
        }
        *(chars + 36) = '\0';
    }
    else if(val == 4) {
        for (dummy = 65; dummy < 91; dummy++) {
            *(chars + dummy - 65) = dummy;
        }
        *(chars + 26) = '\0';
    }
    else if(val == 5){
        for(dummy=48;dummy<58;dummy++){
            *(chars + dummy - 48) = dummy;
        }
        for(dummy=65;dummy<91;dummy++){
            *(chars + dummy - 65 + 10) = dummy;
        }
        *(chars + 36) = '\0';
    }
    else if(val == 6){
        for(dummy=65;dummy<91;dummy++){
            *(chars + dummy - 65) = dummy;
        }
        for(dummy=97;dummy<123;dummy++){
            *(chars + dummy - 97 + 26) = dummy;
        }
        *(chars + 52) = '\0';

    }
    else if(val == 7){
        for(dummy=48;dummy<58;dummy++){
            *(chars + dummy - 48) = dummy;
        }
        for(dummy=65;dummy<91;dummy++){
            *(chars + dummy - 65 + 10) = dummy;
        }
        for(dummy=97;dummy<123;dummy++){
            *(chars + dummy - 97 + 36) = dummy;
        }
        *(chars + 62) = '\0';

    }

}


int calc_charset(int* val, char* arg){

    // n = 1, a = 2, A = 4

    if(strcmp(arg, "n") == 0){
        *val = 1;
        return 10;
    }
    if(strcmp(arg, "a") == 0){
        *val = 2;
        return 26;
    }
    if(strcmp(arg, "na") == 0 || strcmp(arg, "an") == 0){
        *val = 3;
        return 36;
    }
    if(strcmp(arg, "A") == 0){
        *val = 4;
        return 26;
    }
    if(strcmp(arg, "nA") == 0 || strcmp(arg, "An") == 0){
        *val = 5;
        return 36;
    }
    if(strcmp(arg, "Aa") == 0 || strcmp(arg, "aA") == 0){
        *val = 6;
        return 52;
    }
    if(strcmp(arg, "naA") == 0 || strcmp(arg, "anA") == 0 ||
       strcmp(arg, "nAa") == 0 || strcmp(arg, "nAa") == 0 ||
       strcmp(arg, "Ana") == 0 || strcmp(arg, "Ana") == 0){
        *val = 7;
        return 62;
    }
}



void read_file(FILE* f, int* j, char** names, unsigned char** digests, char* line){
    int my_id;
    int ierr = MPI_Comm_rank(MPI_COMM_WORLD, &my_id);

    char hash_string[41];
    char *rem;

    if(my_id == 0) {
        printf("Opening file...\n");
        printf("-----------------------------------------------------------------------------------------------------------------------\n");
    }

    while (fgets(line, 100, f) != NULL) {

        char *pos;
        if ((pos = strchr(line, '\n')) != NULL)
            *pos = '\0';

        rem = strchr(line, ':');

        *rem = '\0';
        rem++;

        *(names + *j) = line;

        rem = strchr(rem, '}');
        rem++;

        size_t hash_size;
        *(digests + *j) = base64_decode(rem, strlen(rem), &hash_size);
        if(my_id == 0) {
            for (int i = 0; i < 20; ++i) {
                hash_string[2 * i] = base16[(*(digests + *j))[i] / 16];
                hash_string[2 * i + 1] = base16[(*(digests + *j))[i] % 16];
            }
            hash_string[40] = '\0';
            printf("Entry: %-2d Username: %-12s Base64: %s  Base16: %s\n", *j, *(names + *j), rem, (hash_string));
        }
        (*j)++;
    }
    *(digests + *j) = '\0';
    if(my_id == 0) {
        printf("-----------------------------------------------------------------------------------------------------------------------\n");
    }
}


void showhelp(){
    printf("Need more arguments.\n");
    printf("Usage:\n");
    printf("brute [-f filename] [-min 000] [-max 000] [-c naA] [-v 1]\n\n");
    printf("\t-f filename\tThe file containing the SHA1 passwords (default: htpasswd-brute)\n");
    printf("\t-min\t\tThe minimum password length to crack. (default: 4)\n");
//    printf("\t-max\t\tThe maximum password length to crack. (default: equal to minimum)\n");
    printf("\t-c naA\t\tCombination of n, a, A. (default: numbers)\n");
    printf("\t\t\t\tn for numbers\n");
    printf("\t\t\t\ta for lower-case letters\n");
    printf("\t\t\t\tA for upper-case letters\n");
    printf("\t-v 1\t\tOption to show some progress on the password space.\n\n");
}