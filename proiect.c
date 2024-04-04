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

            fprintf(snapshot_file, "%s\t%c\t%ld\t%lld\n", metadata.name, metadata.type, 
                    (long)metadata.last_modified, (long long)metadata.size);

            if (metadata.type == 'D') {
                captureMetadata(full_path, snapshot_file);
            }
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    char snapshot_path[MAX_PATH_LENGTH];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/Snapshot.txt", argv[1]);
    FILE *snapshot_file = fopen(snapshot_path, "w");
    if (snapshot_file == NULL) {
        perror("Unable to create snapshot file");
        return 1;
    }

    fprintf(snapshot_file, "The order is: Name, Type, Last Modified, Size\n");
    captureMetadata(argv[1], snapshot_file);

    fclose(snapshot_file);
    printf("Snapshot captured successfully!\n");

    return 0;
}


