#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>


#define SHA1_DIGEST_SIZE 20
#define MAX_USERNAME 256
#define MAX_PASSWORD 256
#define NUM_ITERATIONS 100000


typedef struct {
    char* username;
    char* password;
} user_t;


static char username[MAX_USERNAME];
static int is_authenticated = 0;
int num_users = 0;
user_t* users;


void setup_buffering() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
}


int get_int() {
    int x;
    scanf("%d", &x);
    getchar();
    return x;
}


void digest_password(char* password, uint8_t* out_buf) {
    int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, out_buf, &hash_len);
    for (int i = 1; i < NUM_ITERATIONS; ++i) {
        EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
        EVP_DigestUpdate(mdctx, out_buf, hash_len);
        EVP_DigestFinal_ex(mdctx, out_buf, &hash_len);
    }
    EVP_MD_CTX_free(mdctx);
}


void init_users() {
    num_users = 2;
    users = calloc(sizeof(user_t), num_users);
    users[0].username = strdup("guest");
    users[0].password = strdup("guest");
    users[1].username = strdup("admin");
    users[1].password = strdup("different password in remote");
}


void* check_authentication(void* arg) {
    // start with optimism
    is_authenticated = 1;
    char* correct_password = NULL;
    uint8_t* password_hash = (uint8_t*)arg;
    for (int i = 0; i < num_users; ++i) {
        char curr_hash[SHA1_DIGEST_SIZE];
        digest_password(users[i].password, curr_hash);
        if (!strcmp(username, users[i].username) && !memcmp(password_hash, curr_hash, SHA1_DIGEST_SIZE)) {
            // found user
            return NULL;
        }
    }
    // failed to auth
    is_authenticated = 0;
    puts("Auth failed");
    return NULL;
}


void login_user() {
    char password[MAX_PASSWORD];
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    uint8_t* hash = calloc(SHA1_DIGEST_SIZE, sizeof(uint8_t));
    digest_password(password, hash);

    pthread_t t1;
    pthread_create(&t1, NULL, check_authentication, hash);
    pthread_detach(t1);
}


void admin_panel() {
    puts("Welcome admin!");
    printf("Enter command: ");
    char command[256];
    fgets(command, sizeof(command), stdin);
    system(command);
    puts("Thanks!");
}


void run_marathon() {
    if (!strcmp(username, "admin") && is_authenticated) {
        admin_panel();
        return;
    } else if (!is_authenticated) {
        puts("You are not authenticated!");
        return;
    }
    unsigned int seconds = ((unsigned int)rand()) % 10;
    printf("%s runs for %d seconds\n", username, seconds);
    sleep(seconds);
    printf("%s is no where close to finishing the marathon!\n", username);
}


void signup_user() {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    if (!strncmp(username, "admin", 5)) {
        puts("DON'T EVEN TRY!!!!!!");
        return;
    }
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    num_users++;
    users = realloc(users, sizeof(user_t) * num_users);
    users[num_users - 1].username = strdup(username);
    users[num_users - 1].password = strdup(password);
}


void print_menu() {
    puts("1. login");
    puts("2. sign up");
    puts("3. run a marathon");
    printf("> ");
}


int main() {
    setup_buffering();
    init_users();
    puts("Welcome to the marathon!");
    while (1) {
        print_menu();
        int action = get_int();
        switch (action) {
            case 1:
                login_user();
                break;
            case 2:
                signup_user();
                break;
            case 3:
                run_marathon();
                break;
            default:
                puts("Invalid action");
                break;
        }
    }
}