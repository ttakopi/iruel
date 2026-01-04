#ifndef _PIPE_H
#define _PIPE_H

#include <stdint.h>
#include "fs.h"

int pipe_create(file_t **read_file, file_t **write_file);

#endif
