#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <diskio.hpp>
#include <auto.hpp>
#include <funcs.hpp>

#include "ida_debmod.h"
#include "ida_plugin.h"

#include "debug.h"

#include <zmq.h>

static void *sock_ctx, *evt_sock, *msg_sock;
static eventlist_t g_events;
static debugger_event_t dbg_event;
static request_t msg_req;
static response_t msg_resp;
static qmutex_t sync;

static const char *const SRReg[] =
{
    "C",
    "V",
    "Z",
    "N",
    "X",
    NULL,
    NULL,
    NULL,
    "I",
    "I",
    "I",
    NULL,
    NULL,
    "S",
    NULL,
    "T"
};

#define RC_GENERAL 1

register_info_t registers[] =
{
    { "D0", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D1", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D2", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D3", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D4", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D5", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D6", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "D7", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },

    { "A0", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A1", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A2", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A3", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A4", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A5", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A6", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "A7", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },

    { "PC", REGISTER_ADDRESS | REGISTER_IP, RC_GENERAL, dt_dword, NULL, 0 },

    { "SR", NULL, RC_GENERAL, dt_word, SRReg, 0xFFFF },

    { "SP", REGISTER_ADDRESS | REGISTER_SP, RC_GENERAL, dt_dword, NULL, 0 },

    { "USP", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "ISP", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "MSP", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "SFC", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "DFC", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "VBR", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "CACR", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "CAAR", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },

    { "PADDR", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "PDATA", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },

    { "PPC", REGISTER_ADDRESS, RC_GENERAL, dt_dword, NULL, 0 },
    { "IR", NULL, RC_GENERAL, dt_word, NULL, 0 },
};

static const char *register_classes[] =
{
    "General Registers",
    NULL
};

static int is_socket_available(void *socket, short events) {
    qmutex_lock(sync);
    
    struct zmq_pollitem_t pfd[1];
    int rc;

    pfd[0].socket = socket;
    pfd[0].events = events;
    pfd[0].fd = -1;
    pfd[0].revents = 0;

    rc = zmq_poll(pfd, 1, 10000);

    qmutex_unlock(sync);

    if (rc <= 0)
        return 0;

    return (pfd[0].revents & ZMQ_POLLIN) || (pfd[0].revents & ZMQ_POLLOUT);
}

static int send_sock_msg(void *socket, const void *buf, size_t size) {
    if (!is_socket_available(socket, ZMQ_POLLOUT))
        return 0;

    qmutex_lock(sync);
    int rc = zmq_send(socket, buf, size, 0);
    qmutex_unlock(sync);
    if (rc == -1) {
        /*  Any error here is unexpected. */
        warning("zmq_send: %s\n", zmq_strerror(zmq_errno()));
        return 0;
    }

    return 1;
}

static int recv_sock_msg(void *socket, void *buf, size_t size, int flags) {
    if (!is_socket_available(socket, ZMQ_POLLIN))
        return 0;

    qmutex_lock(sync);
    int rc = zmq_recv(socket, buf, size, flags);
    qmutex_unlock(sync);
    if (rc == -1 && zmq_errno() == EAGAIN)
        return 0;

    const char *ss = zmq_strerror(zmq_errno());

    if (rc == -1) {
        /*  Any error here is unexpected. */
        //warning("zmq_recv: %s\n", ss);
        return 0;
    }

    return 1;
}

static int pause_debugger()
{
    msg_req.type = REQ_PAUSE;
    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;
    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;
    return 1;
}

static int resume_debugger()
{
    msg_req.type = REQ_RESUME;
    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;
    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;
    return 1;
}

static int debugger_stop()
{
    msg_req.type = REQ_STOP;
    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;
    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;
    return 1;
}

static void close_sockets()
{
    qmutex_lock(sync);

    zmq_close(evt_sock);
    zmq_close(msg_sock);
    zmq_ctx_destroy(sock_ctx);

    qmutex_unlock(sync);
}

// Initialize debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi init_debugger(const char *hostname,
    int port_num,
    const char *password)
{
    sync = qmutex_create();

    close_sockets();

    char evt_conn_str[256], msg_conn_str[256];

    /*  Create the socket. */
    sock_ctx = zmq_ctx_new();

    evt_sock = zmq_socket(sock_ctx, ZMQ_PAIR);
    if (evt_sock == NULL) {
        warning("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        return false;
    }
    msg_sock = zmq_socket(sock_ctx, ZMQ_REQ);
    if (msg_sock == NULL) {
        warning("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        return false;
    }

    qsnprintf(evt_conn_str, sizeof(evt_conn_str), "tcp://*:%d", /*hostname,*/ port_num + 0);
    qsnprintf(msg_conn_str, sizeof(msg_conn_str), "tcp://%s:%d", hostname, port_num + 1);

    if (zmq_bind(evt_sock, evt_conn_str) < 0) {
        warning("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        zmq_close(evt_sock);
        return false;
    }
    if (zmq_connect(msg_sock, msg_conn_str) < 0) {
        warning("zmq_socket: %s\n", zmq_strerror(zmq_errno()));
        zmq_close(msg_sock);
        return false;
    }

    return true;
}

// Terminate debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi term_debugger(void)
{
    close_sockets();
    qmutex_free(sync);

    return true;
}

// Return information about the n-th "compatible" running process.
// If n is 0, the processes list is reinitialized.
// 1-ok, 0-failed, -1-network error
// This function is called from the main thread
static int idaapi process_get_info(int n, process_info_t *info)
{
    return 0;
}

// Start an executable to debug
// 1 - ok, 0 - failed, -2 - file not found (ask for process options)
// 1|CRC32_MISMATCH - ok, but the input file crc does not match
// -1 - network error
// This function is called from debthread
static int idaapi start_process(const char *path,
    const char *args,
    const char *startdir,
    int dbg_proc_flags,
    const char *input_path,
    uint32 input_file_crc32)
{
    g_events.clear();

    return 1;
}

// rebase database if the debugged program has been rebased by the system
// This function is called from the main thread
static void idaapi rebase_if_required_to(ea_t new_base)
{
    ea_t currentbase = new_base;
    ea_t imagebase = inf.startIP;

    if (imagebase != currentbase)
    {
        adiff_t delta = currentbase - imagebase;

        int code = rebase_program(delta, MSF_FIXONCE);
        if (code != MOVE_SEGM_OK)
        {
            msg("Failed to rebase program, error code %d\n", code);
            warning("IDA failed to rebase the program.\n"
                "Most likely it happened because of the debugger\n"
                "segments created to reflect the real memory state.\n\n"
                "Please stop the debugger and rebase the program manually.\n"
                "For that, please select the whole program and\n"
                "use Edit, Segments, Rebase program with delta 0x%08a",
                delta);
        }
    }
}

// Prepare to pause the process
// This function will prepare to pause the process
// Normally the next get_debug_event() will pause the process
// If the process is sleeping then the pause will not occur
// until the process wakes up. The interface should take care of
// this situation.
// If this function is absent, then it won't be possible to pause the program
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi prepare_to_pause_process(void)
{
    return pause_debugger();
}

// Stop the process.
// May be called while the process is running or suspended.
// Must terminate the process in any case.
// The kernel will repeatedly call get_debug_event() and until PROCESS_EXIT.
// In this mode, all other events will be automatically handled and process will be resumed.
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi do_exit_process(void)
{
    return debugger_stop();
}

static void get_event()
{
    if (!recv_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event), 0))
        return;

    debug_event_t ev;
    ev.pid = 1;
    ev.tid = 1;
    ev.handled = true;
    ev.eid = NO_EVENT;
    ev.ea = BADADDR;

    switch (dbg_event.type)
    {
    case DBG_EVT_STARTED:
    {
        ev.eid = PROCESS_START;
        ev.ea = dbg_event.pc;

        qstrncpy(ev.modinfo.name, dbg_event.msg, sizeof(ev.modinfo.name));
        ev.modinfo.base = dbg_event.pc;
        ev.modinfo.size = 0;
        ev.modinfo.rebase_to = dbg_event.pc;

        g_events.enqueue(ev, IN_BACK);
    }
    break;
    case DBG_EVT_PAUSED:
    {
        ev.ea = dbg_event.pc;
        ev.eid = PROCESS_SUSPEND;

        g_events.enqueue(ev, IN_BACK);
    }
    break;
    case DBG_EVT_STOPPED:
    {
        ev.eid = PROCESS_EXIT;
        ev.exit_code = dbg_event.exit_code;

        g_events.enqueue(ev, IN_BACK);

        close_sockets();
    }
    break;
    case DBG_EVT_MARK_API:
    {
        set_cmt(dbg_event.pc, dbg_event.msg, true);
        qsleep(10);
    }
    break;
    }

    //send_sock_msg(evt_sock, &dbg_event, sizeof(dbg_event));
}

// Get a pending debug event and suspend the process
// This function will be called regularly by IDA.
// This function is called from debthread
static gdecode_t idaapi get_debug_event(debug_event_t *event, int timeout_ms)
{
    while (true)
    {
        if (g_events.empty())
            get_event();
        // are there any pending events?
        if (g_events.retrieve(event))
        {
            return g_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        }
        if (g_events.empty())
            break;
    }
    return GDE_NO_EVENT;
}

// Continue after handling the event
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi continue_after_event(const debug_event_t *event)
{
    switch (event->eid)
    {
    case PROCESS_SUSPEND:
    case STEP:
        switch (get_running_notification())
        {
        case dbg_null:
        case dbg_run_to:
            return resume_debugger();
        }
        break;
    case PROCESS_EXIT:
        break;
    }

    return 1;
}

// The following function will be called by the kernel each time
// when it has stopped the debugger process for some reason,
// refreshed the database and the screen.
// The debugger module may add information to the database if it wants.
// The reason for introducing this function is that when an event line
// LOAD_DLL happens, the database does not reflect the memory state yet
// and therefore we can't add information about the dll into the database
// in the get_debug_event() function.
// Only when the kernel has adjusted the database we can do it.
// Example: for imported PE DLLs we will add the exported function
// names to the database.
// This function pointer may be absent, i.e. NULL.
// This function is called from the main thread
static void idaapi stopped_at_debug_event(bool dlls_added)
{
}

// The following functions manipulate threads.
// 1-ok, 0-failed, -1-network error
// These functions are called from debthread
static int idaapi thread_suspend(thid_t tid) // Suspend a running thread
{
    pause_debugger();

    return 1;
}

static int idaapi thread_continue(thid_t tid) // Resume a suspended thread
{
    resume_debugger();

    return 1;
}

static int idaapi set_step_mode(thid_t tid, resume_mode_t resmod) // Run one instruction in the thread
{
    switch (resmod)
    {
    case RESMOD_INTO:    ///< step into call (the most typical single stepping)
        msg_req.type = REQ_STEP_INTO;
        if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
            return -1;
        if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
            return -1;
        break;
    case RESMOD_OVER:    ///< step over call
        msg_req.type = REQ_STEP_OVER;
        if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
            return -1;
        if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
            return -1;
        break;
    }

    return 1;
}

// Read thread registers
//	tid	- thread id
//	clsmask- bitmask of register classes to read
//	regval - pointer to vector of regvals for all registers
//			 regval is assumed to have debugger_t::registers_size elements
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
    if (clsmask & RC_GENERAL)
    {
        msg_req.type = REQ_GET_REGS;
        if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
            return -1;

        if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
            return -1;

        for (int i = 0; i < (M68K_REG_IR - M68K_REG_D0 + 1); ++i)
            values[i].ival = msg_resp.regs[i];

        return 1;
    }

    return 0;
}

// Write one thread register
//	tid	- thread id
//	regidx - register index
//	regval - new value of the register
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi write_register(thid_t tid, int regidx, const regval_t *value)
{
    msg_req.type = REQ_SET_REG;
    msg_req.reg.index = regidx;
    msg_req.reg.value = (uint32)value->ival;

    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;
    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;

    return 1;
}

//
// The following functions manipulate bytes in the memory.
//
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//	0: failed
//	1: new memory layout is returned
// This function is called from debthread
static int idaapi get_memory_info(meminfo_vec_t &areas)
{
    memory_info_t info;

    /*
    msg_req.type = REQ_GET_SEGS;
    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;

    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;

    // Don't remove this loop
    for (int i = 0; i < msg_resp.segs.count; ++i)
    {
        info.startEA = msg_resp.segs.list[i].start;
        info.endEA = msg_resp.segs.list[i].end;
        info.name = msg_resp.segs.list[i].name;

        switch (msg_resp.segs.list[i].type)
        {
        case 1: info.sclass = "DATA"; break;
        case 2: info.sclass = "BSS"; break;
        default: info.sclass = "CODE"; break;
        }

        info.sbase = 0;
        info.perm = 0;
        info.bitness = 1;
        areas.push_back(info);
    }
    */

    static bool first_run = true;

    if (first_run)
    {
        first_run = false;
        return -2;
    }

    info.name = "MEMORY";
    info.startEA = 0x00000000;
    info.endEA = info.startEA + 0xFFFFF + 1;
    info.bitness = 1;
    areas.push_back(info);

    return 1;

    // Don't remove this loop

    /*
    info.name = "DBG_VDP_VRAM";
    info.startEA = BREAKPOINTS_BASE;
    info.endEA = info.startEA + 0x10000;
    info.bitness = 1;
    areas.push_back(info);

    info.name = "DBG_VDP_CRAM";
    info.startEA = info.endEA;
    info.endEA = info.startEA + 0x10000;
    info.bitness = 1;
    areas.push_back(info);

    info.name = "DBG_VDP_VSRAM";
    info.startEA = info.endEA;
    info.endEA = info.startEA + 0x10000;
    info.bitness = 1;
    areas.push_back(info);
    */

    return 1;
}

// Read process memory
// Returns number of read bytes
// 0 means read error
// -1 means that the process does not exist anymore
// This function is called from debthread
static ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
    msg_req.type = REQ_READ_MEM;
    msg_req.mem.address = (uint32)ea;
    msg_req.mem.size = (int)size;

    if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
        return -1;

    if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
        return -1;

    memcpy(buffer, msg_resp.mem.buffer, size);

    return size;
}
// Write process memory
// Returns number of written bytes, -1-fatal error
// This function is called from debthread
static ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
    return 0;
}

// Is it possible to set breakpoint?
// Returns: BPT_...
// This function is called from debthread or from the main thread if debthread
// is not running yet.
// It is called to verify hardware breakpoints.
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
    switch (type)
    {
        //case BPT_SOFT:
    case BPT_EXEC:
    case BPT_READ: // there is no such constant in sdk61
    case BPT_WRITE:
    case BPT_RDWR:
        return BPT_OK;
    }

    return BPT_BAD_TYPE;
}

// Add/del breakpoints.
// bpts array contains nadd bpts to add, followed by ndel bpts to del.
// returns number of successfully modified bpts, -1-network error
// This function is called from debthread
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
    for (int i = 0; i < nadd; ++i)
    {
        ea_t start = bpts[i].ea;
        ea_t end = bpts[i].ea + bpts[i].size - 1;

        msg_req.type = REQ_ADD_BREAK;
        msg_req.bpt.address = (uint32)bpts[i].ea;
        msg_req.bpt.length = (int)bpts[i].size;

        switch (bpts[i].type)
        {
        case BPT_EXEC:
            msg_req.bpt.type = BPT_E;
            break;
        case BPT_READ:
            msg_req.bpt.type = BPT_R;
            break;
        case BPT_WRITE:
            msg_req.bpt.type = BPT_W;
            break;
        case BPT_RDWR:
            msg_req.bpt.type = BPT_RW;
            break;
        }

        bpts[i].code = BPT_OK;

        if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
            continue;
        if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
            continue;
    }

    for (int i = 0; i < ndel; ++i)
    {
        ea_t start = bpts[nadd + i].ea;
        ea_t end = bpts[nadd + i].ea + bpts[nadd + i].size - 1;
        
        msg_req.type = REQ_DEL_BREAK;
        msg_req.bpt.address = (uint32)bpts[i].ea;
        msg_req.bpt.length = (int)bpts[i].size;

        switch (bpts[i].type)
        {
        case BPT_EXEC:
            msg_req.bpt.type = BPT_E;
            break;
        case BPT_READ:
            msg_req.bpt.type = BPT_R;
            break;
        case BPT_WRITE:
            msg_req.bpt.type = BPT_W;
            break;
        case BPT_RDWR:
            msg_req.bpt.type = BPT_RW;
            break;
        }

        bpts[nadd + i].code = BPT_OK;

        if (!send_sock_msg(msg_sock, &msg_req, sizeof(msg_req)))
            continue;
        if (!recv_sock_msg(msg_sock, &msg_resp, sizeof(msg_resp), 0))
            continue;
    }

    return (ndel + nadd);
}

//--------------------------------------------------------------------------
//
//	  DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

debugger_t debugger =
{
    IDD_INTERFACE_VERSION,
    NAME, // Short debugger name
    125, // Debugger API module id
    "m68k", // Required processor name
    DBG_FLAG_REMOTE |
    DBG_FLAG_FAKE_ATTACH |
    DBG_FLAG_CAN_CONT_BPT |
    DBG_FLAG_NEEDPORT |
    DBG_FLAG_DEBTHREAD |
    DBG_FLAG_SAFE |
    DBG_FLAG_NOPASSWORD |
    DBG_FLAG_NOSTARTDIR |
    DBG_FLAG_NOPARAMETERS |
    DBG_FLAG_ANYSIZE_HWBPT,

    register_classes, // Array of register class names
    RC_GENERAL, // Mask of default printed register classes
    registers, // Array of registers
    qnumber(registers), // Number of registers

    0x1000, // Size of a memory page

    NULL, // bpt_bytes, // Array of bytes for a breakpoint instruction
    NULL, // bpt_size, // Size of this array
    0, // for miniidbs: use this value for the file type after attaching

    DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER, // Resume modes

    init_debugger,
    term_debugger,

    process_get_info,

    start_process,
    NULL, // attach_process,
    NULL, // detach_process,
    rebase_if_required_to,
    prepare_to_pause_process,
    do_exit_process,

    get_debug_event,
    continue_after_event,

    NULL, // set_exception_info
    stopped_at_debug_event,

    thread_suspend,
    thread_continue,
    set_step_mode,

    read_registers,
    write_register,

    NULL, // thread_get_sreg_base

    get_memory_info,
    read_memory,
    write_memory,

    is_ok_bpt,
    update_bpts,
    NULL, // update_lowcnds

    NULL, // open_file
    NULL, // close_file
    NULL, // read_file

    NULL, // map_address,

    NULL, // set_dbg_options
    NULL, // get_debmod_extensions
    NULL, // update_call_stack

    NULL, // appcall
    NULL, // cleanup_appcall

    NULL, // eval_lowcnd

    NULL, // write_file

    NULL, // send_ioctl
};