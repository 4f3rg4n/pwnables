#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "processor.h"
#include "game.h"


#define MAX_USERNAME_LEN 100
#define MAX_PASSWORD_LEN 100
#define MAX_WEAPON_LENGTH 1024
#define NUM_WEAPONS 4

typedef struct {
    int health;
    int attack;
    int defense;
} Warrior;

typedef struct {
    int health;
    int attack;
} Monster;

typedef struct {
    char* name;
    int attack;
    int defense;
} Weapon;

char* weapons[NUM_WEAPONS];

static int logged_in = 0;
static char logged_username[MAX_USERNAME_LEN + 1];
static Warrior player = {0, 0, 0};


uint8_t* serialize_warrior(Warrior warrior) {
    uint8_t* buffer = calloc(1, sizeof(Warrior));
    memcpy(buffer, &warrior, sizeof(Warrior));
    return buffer;
}


Warrior deserialize_warrior(uint8_t* buffer) {
    Warrior warrior = {0, 0, 0};
    memcpy(&warrior, buffer, sizeof(Warrior));
    return warrior;
}

void create_weapon(int index, char* name, int attack, int defense) {
    if (index >= NUM_WEAPONS) {
        return;
    }
    weapons[index] = strdup(name);
    uint8_t buffer[sizeof(attack) + sizeof(defense)];
    memcpy(buffer, &attack, sizeof(attack));
    memcpy(buffer + sizeof(defense), &defense, sizeof(defense));
    int storage_id = send_request("storage", "store", "sb", name, buffer, sizeof(buffer));
    if (results[storage_id].error_code == FAILURE) {
        puts("Saving failed");
        exit(1);
    }
    release_id(storage_id);
}


void add_weapon_to_player(int weapons_idx) {
    int storage_id = send_request("storage", "load", "s", weapons[weapons_idx]);
    if (results[storage_id].error_code == FAILURE || results[storage_id].length != 8) {
        puts("Reading weapon failed");
        exit(1);
    }
    int attack, defense;
    memcpy(&attack, results[storage_id].result_data, sizeof(attack));
    memcpy(&defense, results[storage_id].result_data + sizeof(attack), sizeof(defense));
    player.attack += attack;
    player.defense += defense;
}


void load_warrior_data(char* username) {
    char* key = calloc(strlen("warrior_") + strlen(username) + 1, sizeof(char));
    strcpy(key, "warrior_");
    strncat(key, username, strlen(username));
    int storage_id = send_request("storage", "load", "s", key);
    if (results[storage_id].error_code == FAILURE) {
        // load default warrior
        player.health = 100;
        player.attack = 10;
        player.defense = 20;
        return;
    }
    if (results[storage_id].length != sizeof(Warrior)) {
        puts("Invalid warrior serialized length");
        exit(1);
    }
    player = deserialize_warrior((uint8_t*)&results[storage_id].result_data);
    
    release_id(storage_id);
}


void save_warrior_data(char* username) {
    char* key = calloc(strlen("warrior_") + strlen(username) + 1, sizeof(char));
    strcpy(key, "warrior_");
    strncat(key, username, strlen(username));
    int storage_id = send_request("storage", "store", "sb", key, serialize_warrior(player), sizeof(Warrior));
    if (results[storage_id].error_code == FAILURE) {
        puts("Saving failed");
        exit(1);
    }
    release_id(storage_id);
}


void authenticate_user() {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    int auth_status_id = send_request("auth", "login", "ss", username, password);
    if (request_successful(auth_status_id)) {
        printf("Login successful!\n");
        strncpy(logged_username, username, MAX_USERNAME_LEN);
        load_warrior_data(logged_username);
        logged_in = 1;
        return;
    }
    printf("Login failed!\n");
    logged_in = 0;
}


static void register_user() {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    int auth_status_id = send_request("auth", "register", "ss", username, password);
    if (request_successful(auth_status_id)) {
        printf("Register successful!\n");
        return;
    }
    printf("Register failed!\n");
}


void forgot_password() {
    if (logged_in != 1) {
        puts("Not logged in!");
        return;
    }
    char password[MAX_PASSWORD_LEN];

    printf("Enter new password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    int auth_status_id = send_request("auth", "forgot_password", "s", password);
    if (request_successful(auth_status_id)) {
        printf("Forgot password successful!\n");
        return;
    }
    printf("Forgot password failed!\n");
}


static void delete_user() {
    char username[MAX_PASSWORD_LEN];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    if (!strcmp(username, logged_username)) {
        puts("Can't delete logged in user");
        return;
    }

    int auth_status_id = send_request("auth", "del_user", "s", username);
    if (request_successful(auth_status_id)) {
        printf("Delete user successful!\n");
        return;
    }
    printf("Delete user failed!\n");
}


void logout_user() {
    int auth_status_id = send_request("auth", "logout", "");
    if (request_successful(auth_status_id)) {
        printf("logout successful!\n");
        logged_in = 0;
        memset(logged_username, 0, sizeof(logged_username));
        return;
    }
    printf("logout failed!\n");
}


void print_login_menu() {
    puts("Choose an action: ");
    puts("(a)uthenticate");
    puts("(r)egister");
    puts("(d)elete user");
    puts("(f)orgot password");
    puts("(l)ogout");
    printf("> ");
}


void login_menu() {
    print_login_menu();
    char action;
    scanf(" %c", &action);
    getchar();
    switch (action) {
        case 'a':
            authenticate_user();
            break;
        case 'r':
            register_user();
            break;
        case 'd':
            delete_user();
            break;
        case 'f':
            forgot_password();
            break;
        case 'l':
            logout_user();
            break;
        default:
            puts("Invalid choice");
            break;
    }
}


void print_menu() {
    puts("Choose an action:");
    puts("(f)ight monster");
    puts("(r)eset game");
    puts("(v)iew weapon");
    puts("(s)ave progress");
    puts("(l)ogin menu");
    puts("(q)uit ");
    printf("> ");
}


void fight_monster(Warrior *player) {
    Monster monster = {50, 10};
    int original_health = player->health;
    printf("A monster appears! It has %d health and %d attack.\n", monster.health, monster.attack);

    while (monster.health > 0 && player->health > 0) {
        printf("You attack the monster!\n");
        monster.health -= player->attack;

        if (monster.health <= 0) {
            player->health = original_health;
            player->attack++;
            player->defense++;
            if (((uint32_t)rand()) % 10 == 0) {
                // add a random weapon
                uint32_t idx = ((uint32_t)rand()) % NUM_WEAPONS;
                printf("You got the %s!\n", weapons[idx]);
                add_weapon_to_player(idx);
            }
            printf("You defeated the monster!\n");
            return;
        }

        sleep(0.5);
        printf("The monster attacks you!\n");
        player->health -= (monster.attack - player->defense);
        if (player->health <= 0) {
            printf("You have been defeated by the monster!\n");
            player->health = 0;
            return;
        }
        printf("Your health: %d, Monster's health: %d\n", player->health, monster.health);
        sleep(0.5);
    }
}


void view_weapon() {
    char weapon_name[MAX_WEAPON_LENGTH];
    printf("Enter weapon name: ");
    fgets(weapon_name, sizeof(weapon_name), stdin);
    weapon_name[strcspn(weapon_name, "\n")] = 0;

    int storage_id = send_request("storage", "load", "s", weapon_name);
    if (results[storage_id].error_code == FAILURE) {
        puts("No such weapon");
        return;
    }
    if (results[storage_id].length != 8) {
        puts("Invalid Weapon serialized length");
        exit(1);
    }
    int attack, defense;
    memcpy(&attack, results[storage_id].result_data, sizeof(attack));
    memcpy(&defense, results[storage_id].result_data + sizeof(attack), sizeof(defense));
    puts("Weapon details: ");
    printf("Name: %s, attack: %d, defense: %d\n", weapon_name, attack, defense);
    release_id(storage_id);
}


void reset_game() {
    player.health = 100;
    player.attack = 10;
    player.defense = 20;
}


void init_weapons() {
    create_weapon(0, "Destroyer Mace", 10, 0);
    create_weapon(1, "Black Shield", 0, 20);
    create_weapon(2, "End Sword", 20, 5);
    create_weapon(3, "Flaming Axe Of Hell", 50, 0);
}


void game_loop() {
    init_weapons();
    printf("Welcome to the game!\n");
    char action;
    while (1) {
        if (!logged_in) {
            login_menu();
            continue;
        }
        print_menu();
        scanf(" %c", &action);
        getchar();

        switch (action) {
            case 'f':
                fight_monster(&player);
                break;
            case 'r':
                reset_game();
                break;
            case 'v':
                view_weapon();
                break;
            case 's':
                save_warrior_data(logged_username);
                puts("Progress saved.");
                break;
            case 'q':
                puts("Goodbye!");
                return;
            case 'l':
                login_menu();
                break;
            default:
                puts("Invalid choice");
                break;
        }
    }
}
