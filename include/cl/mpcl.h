#ifndef VC8_DECOMP_CL_MPCL_H
#define VC8_DECOMP_CL_MPCL_H

#include <windows.h>

// Public PDB: ?thread_print@@YAXPBGZZ (mpcl.obj).
// PBG is const unsigned short*. Original wchar_t typedef spelling is unresolved.
// Caller evidence at 0x40AAAB and 0x40AABF uses differing variadic argument
// counts and caller cleanup; the retail function is a plain return.
void __cdecl thread_print(const unsigned short *, ...);

// ?env_size@@YAIPBG@Z; caller merge_env passes GetEnvironmentStringsW's
// result, uses EAX as a character count, then allocates twice that count + 2.
unsigned int __cdecl env_size(const unsigned short *);

struct worklist_s;
struct source_s;
class ProcessChannel;

// Public action_t identity is recovered. Field identifiers below are
// reconstructed, not PDB spellings. Both action_t constructors corroborate
// fields 0x00..0x10; Queue methods corroborate the intrusive link at 0x14.
struct action_t {
    action_t(int, worklist_s *, int);
    action_t(ProcessChannel *);
    ~action_t();
    int is_last_pass();
    int is_active_pass();
    void send(ProcessChannel *);

    int kind;
    worklist_s *worklist;
    source_s *source;
    int pass;
    int parameter_10; // Semantics unresolved; stores third constructor argument.
    action_t *next;
};

// Queue is the recovered public template identity. Field names are
// reconstructed from its constructor and its intrusive-list operations.
// Win32 critical-section API calls identify lock's canonical type.
template<class T>
class Queue {
public:
    // Remaining declarations are public PDB identities, with corresponding
    // bodies and callers observed in mpcl.obj. Their bodies remain unrecovered.
    Queue(int);
    ~Queue();
    T *try_head_nosync();
    T *head();
    int append_nosync(Queue<T> &);
    int size() const;
    int add_head_nosync(T *);
    void clean();
    int add_tail(T *);
    int add_head(T *);

private:
    // Reconstructed helper name/signature: the tail/sentinel predicate repeats
    // in all three observed queue operations; no out-of-line copy is public.
    bool empty_nosync() const { return tail == &sentinel; }

    int synchronized;
    mutable CRITICAL_SECTION lock;
    T sentinel;
    T *tail;
    int count;
};

int __cdecl NT_err(int);
// Public PDB identities and three-slot base/derived vtables are proven.
// Field identifiers are reconstructed; allocation/stores prove an 8-byte base
// and a 16-byte concrete PipeProcessChannel object.
class ProcessChannel {
public:
    virtual void write(const void *, unsigned long) = 0;
    virtual void read(void *, unsigned long) = 0;
    virtual void close() = 0;
    int read_int();
    unsigned int read_size_t();
    void expect_int(int);
    void kill();
    void read_robust(void *, unsigned long);
    int read_int_robust();
    void expect_int_robust(int);
    void write_string(const unsigned short *);

protected:
    HANDLE process_handle;
};

class PipeProcessChannel : public ProcessChannel {
public:
    virtual void write(const void *, unsigned long);
    virtual void read(void *, unsigned long);
    virtual void close();

private:
    HANDLE write_handle;
    HANDLE read_handle;
};

// Context type/field names are reconstructed, not PDB identities; all 16 bytes
// are proven by the read_thread body's four stores and CreateThread's argument.
struct ProcessChannelReadContext {
    ProcessChannel *channel;
    void *buffer;
    unsigned long size;
    int success;
};

// Public callback identity; actual CreateThread use proves this ABI.
unsigned long __stdcall ProcessChannel_read_thread(void *);

// Public global in mpcl.obj; used by the diagnostic serialization family.
extern HANDLE g_hMutex;

// Public PDB data ?is_server_run@@3HA; loader-zero-initialized int written by
// MP_is_server and read by the server-only paths.
extern int is_server_run;

// Public PDB identities in mpcl.obj. get_mutex is the real inherited-mutex
// loader; MP_get_mutex is its five-byte public wrapper.
void __cdecl close_mutex();
void __cdecl get_mutex();
void __cdecl MP_get_mutex();
int __cdecl MP_is_server();

// Callers pass a wide environment string; the body decodes it with swscanf_s.
HANDLE __cdecl decode_handle(const unsigned short *);

void __cdecl CreatePipe_robust(HANDLE *, HANDLE *, SECURITY_ATTRIBUTES *, unsigned long);

#endif
