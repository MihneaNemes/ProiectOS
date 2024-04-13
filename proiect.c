#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_PATH_LENGTH 1024
#define MAX_METADATA_LENGTH 512

struct EntryMetadata {
    char name[MAX_PATH_LENGTH];
    char type;
    time_t last_modified;
    int size;
};

void captureMetadata(const char *dir_path, FILE *snapshot_file) {
    struct dirent *entry;
    DIR *dir = opendir(dir_path);

    if (dir == NULL) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

            struct stat file_stat;
            if (stat(full_path, &file_stat) == -1) {
                perror("Unable to get file status");
                continue;
            }

            struct EntryMetadata metadata;
            strcpy(metadata.name, entry->d_name);
            if (S_ISDIR(file_stat.st_mode))
                metadata.type = 'D';
            else if (S_ISREG(file_stat.st_mode))
                metadata.type = 'F';
            else
                continue;

            metadata.last_modified = file_stat.st_mtime;
            metadata.size = file_stat.st_size;

            fprintf(snapshot_file, "%s\t%c\t%lld\t%s\n", metadata.name, metadata.type,
                    (long long)metadata.size, ctime(&metadata.last_modified));

            if (metadata.type == 'D') {
                captureMetadata(full_path, snapshot_file);
            }
        }
    }
    closedir(dir);
}

void updateSnapshot(const char *dir_path, const char *output_dir) {
    char snapshot_path[MAX_PATH_LENGTH];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/Snapshot.txt", output_dir);

    FILE *snapshot_file = fopen(snapshot_path, "a");
    if (snapshot_file == NULL) {
        perror("Unable to open snapshot file for appending");
        return;
    }

    
    fseek(snapshot_file, 0, SEEK_END);
    long file_size = ftell(snapshot_file);
    if (file_size == 0) {
        fprintf(snapshot_file, "The order is: Name, Type, Last Modified, Size\n");
    }
    else {
        fseek(snapshot_file, file_size - 1, SEEK_SET); 
        char last_char = fgetc(snapshot_file);
        if (last_char != '\n') {
            fprintf(snapshot_file, "\n"); 
        }
    }

    captureMetadata(dir_path, snapshot_file);

    fclose(snapshot_file);
    printf("Snapshot for directory %s captured successfully!\n", dir_path);
}


int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 11) {
        printf("Usage: %s -o <output_dir> <dir1> <dir2> ... <dirN>\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_dir = argv[i + 1];
                i++;  
            } else {
                printf("Missing output directory path after -o option.\n");
                return 1;
            }
        } else {
            updateSnapshot(argv[i], output_dir);
        }
    }

    return 0;
}
