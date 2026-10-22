#ifndef ETRUSCAN_H
#define ETRUSCAN_H

#include <stddef.h>
#include <stdint.h>

/* Reads return a buffer of *out_len bytes (CBOR, or a JSON {"error":...}); release with
 * etruscan_free_buf. The other calls return a JSON string; release with etruscan_free. */
uint8_t *etruscan_read_file(const char *path, const char *opts_json, size_t *out_len);
uint8_t *etruscan_read_bytes(const uint8_t *data, size_t len, const char *name, const char *opts_json, size_t *out_len);
uint8_t *etruscan_read_binary_file(const char *path, const char *opts_json, size_t *out_len);
uint8_t *etruscan_read_binary_bytes(const uint8_t *data, size_t len, const char *name, const char *opts_json, size_t *out_len);
void etruscan_free_buf(uint8_t *p, size_t len);
char *etruscan_write_file(const char *src, const char *dst, const char *edits_json, const char *opts_json);
char *etruscan_version(void);
void etruscan_free(char *p);

#endif
