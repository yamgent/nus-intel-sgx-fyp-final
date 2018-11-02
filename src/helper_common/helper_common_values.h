#ifndef HELPER_COMMON_VALUES_H
#define HELPER_COMMON_VALUES_H

/*
 * the meter writer found usage of register 15 in the original 
 * assembly, which is forbidden because register 15 is reserved 
 * for metering, and user must forbid the use of register 15 by
 * including the following line at the top of the orignal cpp
 * code before compiling into assembly:
 *
 *      register int instruction_counter asm("r15");
 */
#define HCV_SOURCE_USES_REGISTER_15 0x9999

#define IV_SIZE 12

#define RET_SUCCESS 0
#define RET_ERROR 1

#endif
