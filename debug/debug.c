#include "debug.h"

#include <zmq.h>

#define m68ki_cpu m68k
#define MUL (7)

#ifndef BUILD_TABLES
#include "m68ki_cycles.h"
#endif

#include "m68kconf.h"
#include "m68kcpu.h"
#include "m68kops.h"

extern void log_info(char *format, ...);
extern void log_debug(char *format, ...);
extern void log_error(char *format, ...);

static void *sock_ctx, *evt_sock, *msg_sock;
static request_t msg_req;
static response_t msg_resp;
static debugger_event_t dbg_event;

static int boot_found;
static int debugger_active = 0, paused = 0, trace = 0, reset = 0, resetting = 0;
static int step_over = 0;
static uint32 step_over_addr = 0;

static void process_commands();

static uint8 *memory_map = NULL;

enum {
    MAP_E = 1,
    MAP_R = 2,
    MAP_W = 4,
    MAP_EF = 8,
};

typedef struct breakpoint_s {
    struct breakpoint_s *next, *prev;
    int length;
    enum breakpoint_type_t type;
    unsigned int address;
} breakpoint_t;

static breakpoint_t *first_bp = NULL;

breakpoint_t *add_breakpoint(enum breakpoint_type_t type, uint address, int length) {
    breakpoint_t *bp = (breakpoint_t *)malloc(sizeof(breakpoint_t));

    bp->type = type;
    bp->address = address;
    bp->length = length;

    if (first_bp) {
        bp->next = first_bp;
        bp->prev = first_bp->prev;
        first_bp->prev = bp;
        bp->prev->next = bp;
    }
    else {
        first_bp = bp;
        bp->next = bp;
        bp->prev = bp;
    }

    return bp;
}

void delete_breakpoint(breakpoint_t * bp) {
    if (bp == first_bp) {
        if (bp->next == bp) {
            first_bp = NULL;
        }
        else {
            first_bp = bp->next;
        }
    }

    bp->next->prev = bp->prev;
    bp->prev->next = bp->next;

    free(bp);
}

breakpoint_t *next_breakpoint(breakpoint_t *bp) {
    return bp->next != first_bp ? bp->next : 0;
}

breakpoint_t *find_breakpoint(uint address, enum breakpoint_types type) {
    breakpoint_t *p;

    for (p = first_bp; p; p = next_breakpoint(p)) {
        if ((p->address == address) && (p->type & type))
            return p;
    }

    return 0;
}

void delete_breakpoints() {
    while (first_bp != NULL) delete_breakpoint(first_bp);
}

void init_memory_map() {
    int i;

    for (i = 0; i < MAXROMSIZE; ++i) {
        memory_map[i] &= ~MAP_E;
        memory_map[i] &= ~MAP_EF;
        memory_map[i] &= ~MAP_R;
        memory_map[i] &= ~MAP_W;
    }
}

void mark_map(uint address, int mask) {
    if (address >= 0 && address < MAXROMSIZE)
        memory_map[address] |= mask;
}

int is_map_marked(uint address, int mask) {
    return (memory_map[address] & mask) != 0;
}

int is_socket_available(void *socket, short events) {
    struct zmq_pollitem_t pfd[1];
    int rc;

    pfd[0].socket = socket;
    pfd[0].events = events;

    rc = zmq_poll(pfd, 1, 100);

    if (rc <= 0)
        return 0;

    return (pfd[0].revents & ZMQ_POLLIN) || (pfd[0].revents & ZMQ_POLLOUT);
}

void send_sock_msg(void *socket, const void *buf, size_t size) {
    if (!is_socket_available(socket, ZMQ_POLLOUT))
        return;

    zmq_send(socket, buf, size, 0);
}

int recv_sock_msg(void *socket, void *buf, size_t size, int flags) {
    int rc;
    
    if (!is_socket_available(socket, ZMQ_POLLIN))
        return 0;

    rc = zmq_recv(socket, buf, size, flags);

    if (rc == -1 && zmq_errno() == EAGAIN)
        return 0;

    if (rc == -1) {
        /*  Any error here is unexpected. */
        log_error("zmq_recv: %s\n", zmq_strerror(zmq_errno()));
        return 0;
    }

    return 1;
}

int start_server(int port_num) {
    char evt_conn_str[256], msg_conn_str[256];

    /*  Create the socket. */
    sock_ctx = zmq_ctx_new();

    evt_sock = zmq_socket(sock_ctx, ZMQ_PAIR);
    if (evt_sock == NULL) {
        log_error("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        return (-1);
    }
    msg_sock = zmq_socket(sock_ctx, ZMQ_PAIR);
    if (msg_sock == NULL) {
        log_error("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        return (-1);
    }

    snprintf(evt_conn_str, sizeof(evt_conn_str), "tcp://*:%d", port_num + 0);
    snprintf(msg_conn_str, sizeof(msg_conn_str), "tcp://*:%d", port_num + 1);

    if (zmq_bind(evt_sock, evt_conn_str) < 0) {
        log_error("zmq_bind: %s\n", zmq_strerror(zmq_errno()));
        zmq_close(evt_sock);
        return (-1);
    }
    if (zmq_bind(msg_sock, msg_conn_str) < 0) {
        log_error("zmq_bind: %s\n", zmq_strerror(zmq_errno()));
        zmq_close(msg_sock);
        return (-1);
    }

    log_debug("Debugger started. Waiting for connection...\n");

    for (;;) {
        if (is_socket_available(evt_sock, ZMQ_POLLIN | ZMQ_POLLOUT) &&
            is_socket_available(msg_sock, ZMQ_POLLIN | ZMQ_POLLOUT)) {
            log_debug("Debugging connection established.\n");
            break;
        }
    }

    return (1);
}

void stop_server() {
    zmq_close(evt_sock);
    zmq_close(msg_sock);
}

void activate_debugger() {
    debugger_active = 1;
}

int is_debugger_active() {
    return debugger_active;
}

void deactivate_debugger() {
    debugger_active = 0;
}

void start_debugger(int port_num) {
    if (debugger_active)
        return;

    memory_map = (uint8 *)malloc(MAXROMSIZE);
    if (memory_map == NULL) {
        log_error("Error allocating memory map.\n");
        return;
    }

    init_memory_map();

    if (start_server(port_num) == -1) {
        log_error("Unable to start debug server.\n");
        return;
    }
    
    activate_debugger();
}

void resume_debugger() {
    trace = 0;
    paused = 0;
}

void detach_debugger() {
    delete_breakpoints();
    init_memory_map();
    resume_debugger();
    deactivate_debugger();

    dbg_event.type = DBG_EVT_STOPPED;
    send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));
}

void stop_debugger() {
    detach_debugger();

    if (memory_map != NULL) {
        free(memory_map);
        memory_map = NULL;
    }

    stop_server();
    log_debug("Debugger stopped.\n");
}

void pause_debugger() {
    trace = 0;
    paused = 1;

    dbg_event.type = DBG_EVT_PAUSED;
    dbg_event.pc = m68k_get_reg(M68K_REG_PC);
    send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));
}

int is_debugger_paused() {
    return paused;
}

void debug_vsync() {
    if (!debugger_active || resetting)
        return;

    if (reset) {
        resetting = 1;

        switch (reset)
        {
        case 1: gen_reset(0); break;
        case 2: gen_reset(1); break;
        }
        reset = resetting = 0;
        return;
    }

    process_commands();
}

void process_debug() {
    uint pc, sp;
    int handled_ida_event = 0;

    if (!debugger_active || reset || resetting)
        return;

    pc = m68k_get_reg(M68K_REG_PC);
    sp = m68k_get_reg(M68K_REG_SP);

    if (!boot_found) {
        if (pc == m68k_read_immediate_32(4)) {
            boot_found = 1;
            paused = 1;

            dbg_event.type = DBG_EVT_STARTED;
            send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));
        }
    }

    if (trace) {
        trace = 0;
        paused = 1;

        dbg_event.type = DBG_EVT_STEP;
        dbg_event.pc = pc;
        send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));

        handled_ida_event = 1;
    }

    if (!paused) {
        if (step_over) {
            if (pc == step_over_addr) {
                step_over = 0;
                step_over_addr = 0;

                paused = 1;
            }
        }

        if (DebugCheckBP(pc, BPT_E, 1)) {
            handled_ida_event = 1;
        }
        else if (paused) {
            dbg_event.type = DBG_EVT_PAUSED;
            dbg_event.pc = pc;
            send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));

            handled_ida_event = 1;
        }
    }

    mark_map(pc, MAP_E);

    uint opc = m68ki_read_imm_16();

#define SET_TARGET_RESTORE_PC() mark_map(REG_PC, MAP_EF); m68k_op_rts_32()

    // jsr
    if ((opc & 0xFFF8) == 0x4E90) {
        m68k_op_jsr_32_ai();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFF8) == 0x4EA8) {
        m68k_op_jsr_32_di();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFF8) == 0x4EB0) {
        m68k_op_jsr_32_ix();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x4EB8) {
        m68k_op_jsr_32_aw();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x4EB9) {
        m68k_op_jsr_32_al();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x4EBA) {
        m68k_op_jsr_32_pcdi();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x4EBB) {
        m68k_op_jsr_32_pcix();
        SET_TARGET_RESTORE_PC();
    }
    // bsr
    else if ((opc & 0xFF00) == 0x6100) {
        m68k_op_bsr_8();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x6100) {
        m68k_op_bsr_16();
        SET_TARGET_RESTORE_PC();
    }
    else if ((opc & 0xFFFF) == 0x61FF) {
        m68k_op_bsr_32();
        SET_TARGET_RESTORE_PC();
    }

#undef SET_TARGET_RESTORE_PC

    REG_PC = pc;
    REG_SP = sp;

    if (boot_found && !handled_ida_event && paused) {
        dbg_event.type = DBG_EVT_PAUSED;
        dbg_event.pc = pc;
        send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));
    }

    while (paused) {
        process_commands();
    }
}

static void process_commands() {
    int i, rc;
    breakpoint_t *bp;

    if (!recv_sock_msg(msg_sock, &msg_req, sizeof(msg_req), ZMQ_DONTWAIT))
        return;

    switch (msg_req.type)
    {
    case REQ_GET_REGS:
    {
        for (i = 0; i < (M68K_REG_IR - M68K_REG_D0 + 1); ++i)
            msg_resp.regs[i] = m68k_get_reg(i);
    }
    break;
    case REQ_SET_REGS:
    {
        for (i = 0; i < (M68K_REG_IR - M68K_REG_D0 + 1); ++i)
            m68k_set_reg(i, msg_req.regs[i]);
    }
    break;
    case REQ_GET_REG:
        msg_resp.reg.index = msg_req.reg.index;
        msg_resp.reg.value = m68k_get_reg(msg_req.reg.index);
        break;
    case REQ_SET_REG:
        m68k_set_reg(msg_req.reg.index, msg_req.reg.value);
        break;
    case REQ_READ_MEM:
    {
        msg_resp.mem.size = msg_req.mem.size;
        msg_resp.mem.type = msg_req.mem.type;

        uint8 *ptr;
        switch (msg_req.mem.type)
        {
        case MEM_Z80:
            ptr = zram;
            break;
        case MEM_VRAM:
            ptr = vram;
            break;
        case MEM_CRAM:
            ptr = cram;
            break;
        default: // MEM_VSRAM:
            ptr = vsram;
            break;
        }

        switch (msg_req.mem.type)
        {
        case MEM_M68K:
            for (i = 0; i < msg_req.mem.size; ++i)
            {
                cpu_memory_map *temp = &m68ki_cpu.memory_map[((msg_req.mem.address + i) >> 16) & 0xff];

                if (temp->read8) msg_resp.mem.buffer[i] = (*temp->read8)(ADDRESS_68K(msg_req.mem.address + i));
                else msg_resp.mem.buffer[i] = READ_BYTE(temp->base, (msg_req.mem.address + i) & 0xffff);
            }
            break;
        default:
            memcpy(msg_resp.mem.buffer, ptr, msg_req.mem.size);
            break;
        }
    }
    break;
    case REQ_WRITE_MEM:
    {
        msg_resp.mem.size = msg_req.mem.size;
        msg_resp.mem.type = msg_req.mem.type;

        uint8 *ptr;
        switch (msg_req.mem.type)
        {
        case MEM_Z80:
            ptr = zram;
            break;
        case MEM_VRAM:
            ptr = vram;
            break;
        case MEM_CRAM:
            ptr = cram;
            break;
        default: // MEM_VSRAM:
            ptr = vsram;
            break;
        }

        switch (msg_req.mem.type)
        {
        case MEM_M68K:
            for (i = 0; i < msg_req.mem.size; ++i)
            {
                cpu_memory_map *temp = &m68ki_cpu.memory_map[((msg_req.mem.address + i) >> 16) & 0xff];

                if (temp->write8) (*temp->write8)(ADDRESS_68K(msg_req.mem.address + i), msg_req.mem.buffer[i]);
                else WRITE_BYTE(temp->base, (msg_req.mem.address + i) & 0xffff, msg_req.mem.buffer[i]);
            }
            break;
        default:
            memcpy(ptr, msg_req.mem.buffer, msg_req.mem.size);
            break;
        }
    }
    break;
    case REQ_ADD_BREAK:
        add_breakpoint(msg_req.bpt.type, msg_req.bpt.address, msg_req.bpt.length);
        return;
    case REQ_DEL_BREAK:
        if (bp = find_breakpoint(msg_req.bpt.address, msg_req.bpt.type))
            delete_breakpoint(bp);
        return;
    case REQ_PAUSE:
        pause_debugger();
        return;
    case REQ_RESUME:
        resume_debugger();
        return;
    case REQ_DETACH:
        detach_debugger();
        return;
    case REQ_STEP_INTO:
        if (paused) {
            trace = 1;
            paused = 0;
        }
        return;
    case REQ_STEP_OVER:
    {
        if (!paused)
            return;

        uint pc = m68k_get_reg(M68K_REG_PC);
        uint sp = m68k_get_reg(M68K_REG_SP);
        uint opc = m68ki_read_imm_16();

#define STEP_OVER_PC() m68k_op_rts_32(); step_over = 1; step_over_addr = REG_PC

        // jsr
        if ((opc & 0xFFF8) == 0x4E90) {
            m68k_op_jsr_32_ai();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFF8) == 0x4EA8) {
            m68k_op_jsr_32_di();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFF8) == 0x4EB0) {
            m68k_op_jsr_32_ix();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFFF) == 0x4EB8) {
            m68k_op_jsr_32_aw();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFFF) == 0x4EB9) {
            m68k_op_jsr_32_al();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFFF) == 0x4EBA) {
            m68k_op_jsr_32_pcdi();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFFF) == 0x4EBB) {
            m68k_op_jsr_32_pcix();
            STEP_OVER_PC();
        }
        // bsr
        else if ((opc & 0xFFFF) == 0x6100) {
            m68k_op_bsr_16();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFFFF) == 0x61FF) {
            m68k_op_bsr_32();
            STEP_OVER_PC();
        }
        else if ((opc & 0xFF00) == 0x6100) {
            m68k_op_bsr_8();
            STEP_OVER_PC();
        }

#undef STEP_OVER_PC

        // just one step
        else
            trace = 1;

        REG_PC = pc;
        REG_SP = sp;

        paused = 0;
    }
    return;
    case REQ_SOFT_RESET:
        paused = 0;
        trace = 0;
        reset = 2;
        return;
    case REQ_HARD_RESET:
        paused = 0;
        trace = 0;
        reset = 1;
        return;
    case REQ_GET_MAP_IDC:
    {
        static const char idc_header_1[] = "#include <idc.idc>\r\n\r\n";
        static const char idc_header_2[] = "static main(void) {\r\n";
        static const char idc_make_func_1[] = "\tMakeFunction(0x";
        static const char idc_make_func_2[] = ",BADADDR);\r\n";
        static const char idc_make_code_1[] = "\tMakeCode(0x";
        static const char idc_make_code_2[] = ");\r\n";
        static const char idc_footer_1[] = "}\r\n";

        FILE *idc = fopen(msg_req.map_idc_file, "wb");

        if (idc == NULL)
        {
            strncpy(msg_resp.error_msg, "Cannot open IDC destination file!", sizeof(msg_resp.error_msg));

            msg_resp.status = STATUS_ERROR;
            send_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp));
            return;
        }
        fprintf(idc, idc_header_1);
        fprintf(idc, idc_header_2);

        for (i = 0; i < MAXROMSIZE; i++) {
            if (is_map_marked(i, MAP_E)) {
                fprintf(idc, "%s%06X%s", idc_make_code_1, i, idc_make_code_2);
            }
        }

        for (i = 0; i < MAXROMSIZE; i++) {
            if (is_map_marked(i, MAP_EF)) {
                fprintf(idc, "%s%06X%s", idc_make_func_1, i, idc_make_func_2);
            }
        }

        fprintf(idc, idc_footer_1);
        fclose(idc);
    }
    break;
    default:
        snprintf(msg_resp.error_msg, sizeof(msg_resp.error_msg), "Unknown request code = %d", msg_req.type);
        msg_resp.status = STATUS_ERROR;
        break;
    }

    send_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp));
}

int DebugCheckBP(uint address, enum breakpoint_type_t type, int length) {
    breakpoint_t *bp;
    uint pc;

    if (!debugger_active || reset)
        return 0;

    pc = m68k_get_reg(M68K_REG_PC);

    for (bp = first_bp; bp; bp = next_breakpoint(bp)) {
        if (!(bp->type & type)) continue;
        if ((address <= (bp->address + bp->length)) && ((address + length) >= bp->address)) {
            dbg_event.type = DBG_EVT_BPT;
            dbg_event.pc = pc;
            dbg_event.bpt.address = address;
            dbg_event.bpt.length = length;
            dbg_event.bpt.type = type;

            send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));

            paused = 1;
            return 1;
        }
    }

    if (type & BPT_R) mark_map(address, MAP_R);
    if (type & BPT_W) mark_map(address, MAP_W);

    return 0;
 }
