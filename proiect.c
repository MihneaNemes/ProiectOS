#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define MAX_PATH_LENGTH 1024
#define MAX_METADATA_LENGTH 512

struct EntryMetadata {
    char name[MAX_PATH_LENGTH];
    char type;
    time_t last_modified;
    int size;
};

void captureFileMetadata(const char *file_path, char *snapshot_content) {
    struct stat file_stat;
    if (stat(file_path, &file_stat) == -1) {
        perror("Unable to get file status");
        return;
    }

    char type = 'F';
    char time_str[MAX_METADATA_LENGTH];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&file_stat.st_mtime));

    char entry_str[MAX_METADATA_LENGTH];
    snprintf(entry_str, sizeof(entry_str), "%s\t%c\t%d\t%s\n", file_path, type,
             (int)file_stat.st_size, time_str);

    strcat(snapshot_content, entry_str);
}

void captureDirMetadata(const char *dir_path, char *snapshot_content) {
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

            if (S_ISDIR(file_stat.st_mode)) {
                captureDirMetadata(full_path, snapshot_content);
            } else {
                captureFileMetadata(full_path, snapshot_content);
            }
        }
    }
    closedir(dir);
}

void updateSnapshot(const char *dir_path, const char *output_dir) {
    char snapshot_path[MAX_PATH_LENGTH];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/Snapshot_%s.txt", output_dir, dir_path);

    int snapshot_fd = open(snapshot_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (snapshot_fd == -1) {
        perror("Unable to open snapshot file for appending");
        return;
    }

    off_t file_size = lseek(snapshot_fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("Unable to determine snapshot file size");
        close(snapshot_fd);
        return;
    }

    char header[] = "The order is: Name, Type, Size, Last Modified\n";
    if (file_size == 0) {
        write(snapshot_fd, header, strlen(header));
    } else {
        lseek(snapshot_fd, file_size - 1, SEEK_SET);
        char last_char;
        read(snapshot_fd, &last_char, 1);
        if (last_char != '\n') {
            char newline = '\n';
            write(snapshot_fd, &newline, 1);
        }
    }

    char snapshot_content[MAX_METADATA_LENGTH] = "";
    captureDirMetadata(dir_path, snapshot_content);
    write(snapshot_fd, snapshot_content, strlen(snapshot_content));

    close(snapshot_fd);
    printf("Snapshot for directory %s captured successfully!\n", dir_path);
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 12) {
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
