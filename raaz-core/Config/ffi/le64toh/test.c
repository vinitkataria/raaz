#include <stdint.h>
#include <endian.h>

uint64_t le64(uint64_t arg)
{
    return le64toh (arg);
}
