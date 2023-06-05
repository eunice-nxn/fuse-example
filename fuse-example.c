#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "cJSON.h"

static const char *filepath = "/file";
static const char *filename = "file";
static const char *filecontent = "I'm the content of the only file available there\n";

#define TAB(DEPTH) 				\
	for ( int j = 0 ; j < (DEPTH) ; j++ )	\
		printf("\t");		     	\

static int getattr_callback(const char *path, struct stat *stbuf) {
  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    return 0;
  }

  if (strcmp(path, filepath) == 0) {
    stbuf->st_mode = S_IFREG | 0777;
    stbuf->st_nlink = 1;
    stbuf->st_size = strlen(filecontent);
    return 0;
  }

  return -ENOENT;
}

static int readdir_callback(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi) {
  (void) offset;
  (void) fi;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  filler(buf, filename, NULL, 0);

  return 0;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  return 0;
}

static int read_callback(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi) {

  if (strcmp(path, filepath) == 0) {
    size_t len = strlen(filecontent);
    if (offset >= len) {
      return 0;
    }

    if (offset + size > len) {
      memcpy(buf, filecontent + offset, len - offset);
      return len - offset;
    }

    memcpy(buf, filecontent + offset, size);
    return size;
  }

  return -ENOENT;
}

static struct fuse_operations fuse_example_operations = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
  .readdir = readdir_callback,
};

typedef struct entry {
	int inode;
	char * type;
	char * name;
	char * data;
	struct entry_list * e_list;
} ENTRY;

typedef struct entry_list {
	int num_of_items;
	ENTRY ** items;
} ENTRY_LIST;


ENTRY * new_entry () {
	ENTRY * new_e = (ENTRY *) malloc (sizeof(ENTRY));
	new_e->inode = 0;
	new_e->type = NULL;
	new_e->name = NULL;
	new_e->data = NULL;
	new_e->e_list = NULL;
	return new_e;
}

ENTRY_LIST * new_entry_list() {
	ENTRY_LIST * new_e_list = (ENTRY_LIST *) malloc (sizeof(ENTRY_LIST));
	new_e_list->num_of_items = 0;
	new_e_list->items = NULL;
	return new_e_list;
}

cJSON * read_json_file(char * file_name) {

	FILE * fp = fopen(file_name, "r");
        if ( fp == NULL ) {
                printf("Error : unable to open the file\n");
                return NULL;
        }

        char buffer[1024];
        int len = fread(buffer, 1, sizeof(buffer), fp);
        fclose(fp);

        cJSON * json = cJSON_Parse(buffer);
        if ( json == NULL ) {
                const char * error_ptr = cJSON_GetErrorPtr();
                if ( error_ptr != NULL ) {
                        printf("Error : %s\n", error_ptr);
                }
                cJSON_Delete(json);
                return NULL;
        }

	return json;
}

ENTRY_LIST * parse_json(cJSON * root) {
	if ( !cJSON_IsArray(root) ) {
		return NULL;
	}

	int size = cJSON_GetArraySize(root);
	ENTRY_LIST * e_list = new_entry_list();
	e_list->num_of_items = size;
	e_list->items = (ENTRY **) malloc ( size * sizeof(ENTRY *) );

	cJSON * iterator;
	int i = 0;
	cJSON_ArrayForEach(iterator, root) {

		ENTRY * item = new_entry();

		cJSON * inode = cJSON_GetObjectItem(iterator, "inode"); 
		cJSON * type = cJSON_GetObjectItem(iterator, "type");
		cJSON * name = cJSON_GetObjectItem(iterator, "name");
		if(inode != NULL && cJSON_IsNumber(inode)) {
			item->inode = inode->valueint;
		}
		if(type != NULL && cJSON_IsString(type)) {
			item->type = type->valuestring;

			if(strcmp(type->valuestring, "reg") == 0) {
				cJSON * data = cJSON_GetObjectItem(iterator, "data");
				if(data != NULL && cJSON_IsString(data)) {
					item->data = data->valuestring;
				}
			}

			if(strcmp(type->valuestring, "dir") == 0) {
				cJSON * entries = cJSON_GetObjectItem(iterator, "entries");
				if(entries != NULL && cJSON_IsArray(entries)) {
					item->e_list = parse_json(entries);
				}
			}
		}
		if(name != NULL && cJSON_IsString(name)) {
			item->name = name->valuestring;
		}

		*(e_list->items + i) = item;
		i++;
	}

	return e_list;
}

void print_entry(ENTRY_LIST * e_list, int depth) {


	for ( int i = 0 ; (i < e_list->num_of_items) && (e_list->items[i] != NULL) ; i++ ) {
		TAB(depth);
		printf("{\n");
		if (e_list->items[i]->name != NULL) {
			TAB(depth + 1);
			printf("name: %s \n", e_list->items[i]->name);
		}
		TAB(depth + 1);
		printf("inode: %d \n", e_list->items[i]->inode );
		if (e_list->items[i]->type != NULL) { 
			TAB(depth + 1);
			printf("type: %s,\n", e_list->items[i]->type);
			if (strcmp(e_list->items[i]->type, "reg") == 0) {
				TAB(depth + 1);
				printf("data: %s \n", e_list->items[i]->data);
			} else if (strcmp(e_list->items[i]->type, "dir") == 0) {
				print_entry(e_list->items[i]->e_list, depth + 1);
			}
		}
		TAB(depth);
		printf("}\n");
	}

}

int main(int argc, char *argv[])
{
	cJSON * root = read_json_file("data.json");
	if(root == NULL) {
		printf("error: read_json_file");
		return -1;
	}

	ENTRY_LIST * e_list = parse_json(root);
	if(e_list == NULL) {
		printf("error: parse_json");
		return -1;
	}

	print_entry(e_list, 0);
  	return fuse_main(argc, argv, &fuse_example_operations, NULL);
}
