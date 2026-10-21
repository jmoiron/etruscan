#ifndef ETRUSCAN_H
#define ETRUSCAN_H

#include <stddef.h>
#include <stdint.h>

/* All functions return a heap-allocated JSON string; release with etruscan_free. */
char *etruscan_read_file(const char *path, const char *opts_json);
char *etruscan_read_bytes(const uint8_t *data, size_t len, const char *name, const char *opts_json);
char *etruscan_write_file(const char *src, const char *dst, const char *edits_json, const char *opts_json);
char *etruscan_version(void);
void etruscan_free(char *p);

#endif
