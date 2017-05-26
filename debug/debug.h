#pragma once

#pragma pack(push, 1)

enum breakpoint_type_t {
	BPT_E = 1,
    BPT_R = 2,
    BPT_W = 4,
    BPT_RW = BPT_R | BPT_W,
};

enum m68k_register_t
{
  /* Real registers */
    M68K_REG_D0,		/* Data registers */
    M68K_REG_D1,
    M68K_REG_D2,
    M68K_REG_D3,
    M68K_REG_D4,
    M68K_REG_D5,
    M68K_REG_D6,
    M68K_REG_D7,
    M68K_REG_A0,		/* Address registers */
    M68K_REG_A1,
    M68K_REG_A2,
    M68K_REG_A3,
    M68K_REG_A4,
    M68K_REG_A5,
    M68K_REG_A6,
    M68K_REG_A7,
    M68K_REG_PC,		/* Program Counter */
    M68K_REG_SR,		/* Status Register */
    M68K_REG_SP,		/* The current Stack Pointer (located in A7) */
    M68K_REG_USP,		/* User Stack Pointer */
    M68K_REG_ISP,		/* Interrupt Stack Pointer */
    M68K_REG_MSP,		/* Master Stack Pointer */
    M68K_REG_SFC,		/* Source Function Code */
    M68K_REG_DFC,		/* Destination Function Code */
    M68K_REG_VBR,		/* Vector Base Register */
    M68K_REG_CACR,		/* Cache Control Register */
    M68K_REG_CAAR,		/* Cache Address Register */

                        /* Assumed registers */
                        /* These are cheat registers which emulate the 1-longword prefetch
                        * present in the 68000 and 68010.
                        */
    M68K_REG_PREF_ADDR,	/* Last prefetch address */
    M68K_REG_PREF_DATA,	/* Last prefetch data */

    /* Convenience registers */
    M68K_REG_PPC,		/* Previous value in the program counter */
    M68K_REG_IR,		/* Instruction register */
    M68K_REG_CPU_TYPE	/* Type of CPU being run */
};

typedef struct {
    int length;
    enum breakpoint_type_t type;
    uint32 address;
} breakpoint_local_t;

enum event_type_t {
    DBG_EVT_STARTED = 1,
    DBG_EVT_PAUSED,
    DBG_EVT_STOPPED,

    DBG_EVT_MARK_API
};

typedef struct {
    enum event_type_t type;
    uint32 pc;

    union {
        breakpoint_local_t bpt;
        char msg[256];
        int exit_code;
    };
} debugger_event_t;

enum request_type_t {
    REQ_GET_REGS = 1,
    REQ_SET_REGS,

    REQ_GET_REG,
    REQ_SET_REG,

    REQ_READ_MEM,
    REQ_WRITE_MEM,

    REQ_ADD_BREAK,
    REQ_DEL_BREAK,

    REQ_PAUSE,
    REQ_RESUME,
    REQ_STOP,

    REQ_STEP_INTO,
    REQ_STEP_OVER,
};

enum status_type_t {
    STATUS_OK = 1,
    STATUS_ERROR,
};

typedef struct {
    int index;
    uint32 value;
} reg_val_t;

typedef struct {
    int size;
    uint32 address;
    uint8 buffer[1024];
} mem_buffer_t;

typedef struct {
    union {
        uint32 regs[M68K_REG_IR - M68K_REG_D0 + 1];
        mem_buffer_t mem;
        reg_val_t reg;
        breakpoint_local_t bpt;
    };

    enum request_type_t type;
} request_t;

typedef struct {
    union {
        uint regs[M68K_REG_IR - M68K_REG_D0 + 1];
        mem_buffer_t mem;
        reg_val_t reg;
        char error_msg[256];
    };

    enum status_type_t status;
} response_t;

#pragma pack(pop)
