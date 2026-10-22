#include "../../include/cl/mpcl.h"
#include <wchar.h>
#include "../../include/cl/util.h"

// mpcl.obj attribution: PDB DBI section contribution contains the public start.
// The original source filename, extension and line positions are unresolved.
// Complete retail CFG at 0x40A25F is a single C3 return with no referents.
// Callers retain variadic arguments although this retail body ignores them.

// FUNCTION: cl 0x40A25F
// SYMBOL: ?thread_print@@YAXPBGZZ
void __cdecl thread_print(const unsigned short *, ...)
{
}

// FUNCTION: cl 0x40A2DC
// SYMBOL: ?env_size@@YAIPBG@Z
// Complete retail CFG: 45 decoded bytes, all local branches, ret 0x40A308.
// Names environment/cursor are reconstructed, not recovered identifiers.
// The final zero is excluded; an empty environment returns zero.
unsigned int __cdecl env_size(const unsigned short *environment)
{
    const unsigned short *cursor = environment;

    while (*cursor) {
        while (*cursor)
            ++cursor;
        ++cursor;
    }
    return cursor - environment;
}

// FUNCTION: cl 0x40A3A1
// SYMBOL: ?try_head_nosync@?$Queue@Uaction_t@@@@QAEPAUaction_t@@XZ
// Complete local CFG: 38 decoded bytes, returns at 0x40A3AB and 0x40A3C6.
template<class T>
T *Queue<T>::try_head_nosync()
{
    if (empty_nosync())
        return 0;

    T *first = sentinel.next;
    sentinel.next = first->next;
    first->next = 0;
    if (tail == first)
        tail = &sentinel;
    --count;
    return first;
}

// FUNCTION: cl 0x40A41B
// SYMBOL: ?append_nosync@?$Queue@Uaction_t@@@@QAEHAAV1@@Z
// Complete local CFG: 61 decoded bytes, ret 4 at 0x40A455; no referents.
template<class T>
int Queue<T>::append_nosync(Queue<T> &other)
{
    int result = 0;
    if (!other.empty_nosync()) {
        tail->next = other.sentinel.next;
        tail = other.tail;
        tail->next = &sentinel;
        other.tail = &other.sentinel;
        other.sentinel.next = &other.sentinel;
        count += other.count;
        other.count = 0;
        result = 1;
    }
    return result;
}

// FUNCTION: cl 0x40A475
// SYMBOL: ?add_head_nosync@?$Queue@Uaction_t@@@@QAEHPAUaction_t@@@Z
// Complete local CFG: 33 decoded bytes, ret 4 at 0x40A493; no referents.
template<class T>
int Queue<T>::add_head_nosync(T *item)
{
    if (empty_nosync())
        tail = item;
    item->next = sentinel.next;
    sentinel.next = item;
    return ++count;
}

// FUNCTION: cl 0x40A458
// SYMBOL: ?size@?$Queue@Uaction_t@@@@QBEHXZ
// Complete CFG: 29 decoded bytes ending in ret 0x40A474. The two calls
// are real EnterCriticalSection/LeaveCriticalSection imports; lock is mutable
// because the const member uses the Win32 synchronization object.
template<class T>
int Queue<T>::size() const
{
    EnterCriticalSection(&lock);
    int result = count;
    LeaveCriticalSection(&lock);
    return result;
}

// FUNCTION: cl 0x40AA29
// SYMBOL: ?add_tail@?$Queue@Uaction_t@@@@QAEHPAUaction_t@@@Z
// Complete CFG: 53 decoded bytes, ret 4 at 0x40AA5B; only the two
// EnterCriticalSection/LeaveCriticalSection IAT operands are external.
template<class T>
int Queue<T>::add_tail(T *item)
{
    EnterCriticalSection(&lock);
    item->next = &sentinel;
    tail->next = item;
    tail = item;
    int result = ++count;
    LeaveCriticalSection(&lock);
    return result;
}

// FUNCTION: cl 0x40AA5E
// SYMBOL: ?add_head@?$Queue@Uaction_t@@@@QAEHPAUaction_t@@@Z
// Complete CFG: 41 decoded bytes, ret 4 at 0x40AA84. The middle call is
// the real add_head_nosync body above, surrounded by the same Win32 imports.
template<class T>
int Queue<T>::add_head(T *item)
{
    EnterCriticalSection(&lock);
    int result = add_head_nosync(item);
    LeaveCriticalSection(&lock);
    return result;
}

// FUNCTION: cl 0x40A3C7
// SYMBOL: ?head@?$Queue@Uaction_t@@@@QAEPAUaction_t@@XZ
// Complete observed CFG: 84 decoded bytes through ret 0x40A41A. Empty
// queues release the lock, Sleep(0), and reacquire it before checking again.
template<class T>
T *Queue<T>::head()
{
    EnterCriticalSection(&lock);
    while (empty_nosync()) {
        LeaveCriticalSection(&lock);
        Sleep(0);
        EnterCriticalSection(&lock);
    }
    T *result = sentinel.next;
    sentinel.next = result->next;
    result->next = 0;
    if (tail == result)
        tail = &sentinel;
    --count;
    LeaveCriticalSection(&lock);
    return result;
}

template action_t *Queue<action_t>::try_head_nosync();
template int Queue<action_t>::append_nosync(Queue<action_t> &);
template int Queue<action_t>::add_head_nosync(action_t *);
template int Queue<action_t>::size() const;
template int Queue<action_t>::add_tail(action_t *);
template int Queue<action_t>::add_head(action_t *);
template action_t *Queue<action_t>::head();

// FUNCTION: cl 0x40A0A2
// SYMBOL: ?read_int@ProcessChannel@@QAEHXZ
int ProcessChannel::read_int()
{
    int result;
    read(&result, sizeof result);
    return result;
}

// FUNCTION: cl 0x40A243
// SYMBOL: ?close@PipeProcessChannel@@UAEXXZ
void PipeProcessChannel::close()
{
    CloseHandle(read_handle);
    CloseHandle(write_handle);
}

// FUNCTION: cl 0x40A2C4
// SYMBOL: ?NT_err@@YAHH@Z
int __cdecl NT_err(int result)
{
    if (!result)
        RaiseException(1, 0, 0, 0);
    return result;
}

// FUNCTION: cl 0x40A8E3
// SYMBOL: ?write@PipeProcessChannel@@UAEXPBXK@Z
void PipeProcessChannel::write(const void *buffer, unsigned long size)
{
    unsigned long written;
    NT_err(WriteFile(write_handle, buffer, size, &written, 0));
}

// FUNCTION: cl 0x40A906
// SYMBOL: ?read@PipeProcessChannel@@UAEXPAXK@Z
void PipeProcessChannel::read(void *buffer, unsigned long size)
{
    unsigned long remaining = size;
    while (remaining > 0) {
        NT_err(ReadFile(read_handle, buffer, remaining, &size, 0));
        remaining -= size;
        buffer = static_cast<char *>(buffer) + size;
    }
}

// FUNCTION: cl 0x40A0B6
// SYMBOL: ?expect_int@ProcessChannel@@QAEXH@Z
void ProcessChannel::expect_int(int expected)
{
    if (expected != read_int())
        RaiseException(1, 0, 0, 0);
}

// FUNCTION: cl 0x40A8A6
// SYMBOL: ?kill@ProcessChannel@@QAEXXZ
void ProcessChannel::kill()
{
    int command = 0x29a;
    write(&command, sizeof command);
    expect_int(0x298);
    WaitForSingleObject(process_handle, INFINITE);
    CloseHandle(process_handle);
}

// DATA: cl 0x41AAF0
// PDB ?g_hMutex@@3PAXA; loader-zero-initialized .data virtual tail.
HANDLE g_hMutex;

// DATA: cl 0x41A2B4
// PDB ?is_server_run@@3HA; loader-zero-initialized int in the .data tail.
int is_server_run;

// FUNCTION: cl 0x409FAE
// SYMBOL: ?close_mutex@@YAXXZ
// Complete 17-byte CFG: conditional CloseHandle of the canonical inherited
// mutex handle, ret 0x409FBE.
void __cdecl close_mutex()
{
    if (g_hMutex)
        CloseHandle(g_hMutex);
}

// FUNCTION: cl 0x409FBF
// SYMBOL: ?MP_is_server@@YAHXZ
// Complete 76-byte CFG with the real GS cookie. A 10-character wide buffer is
// filled by GetEnvironmentVariableW; only a successful read compares against
// the marker and records the canonical is_server_run global.
int __cdecl MP_is_server()
{
    wchar_t value[10];
    int result = GetEnvironmentVariableW(L"MPCL_SERVER_373011", value, 10);
    if (result) {
        result = wcscmp(value, L"bananana") == 0;
        is_server_run = result;
    }
    return result;
}

// FUNCTION: cl 0x40A04C
// SYMBOL: ?ProcessChannel_read_thread@@YGKPAX@Z
// Complete 86-byte stdcall body including the compiler's SEH prolog, the
// __except filter at 0x40A075 and the handler at 0x40A087. The context is the
// real four-field ProcessChannelReadContext described in the header.
unsigned long __stdcall ProcessChannel_read_thread(void *parameter)
{
    ProcessChannelReadContext *context = static_cast<ProcessChannelReadContext *>(parameter);
    __try {
        context->channel->read(context->buffer, context->size);
        context->success = 1;
    } __except (GetExceptionCode() == 1) {
        context->success = 0;
    }
    return 0;
}

// FUNCTION: cl 0x40A0D1
// SYMBOL: ?write_string@ProcessChannel@@QAEXPBG@Z
// Complete 55-byte CFG: wcslen on the wide value, then the size word and the
// string including its terminator through the virtual write slot.
void ProcessChannel::write_string(const unsigned short *value)
{
    unsigned long size = wcslen(value) * sizeof *value;
    write(&size, sizeof size);
    write(value, size + sizeof *value);
}

// FUNCTION: cl 0x40A25A
// SYMBOL: ??3@YAXPAX@Z
// Complete five-byte body: one tail transfer to the canonical util deallocator.
void __cdecl operator delete(void *allocation)
{
    xfree(allocation);
}

// FUNCTION: cl 0x40A346
// SYMBOL: ?decode_handle@@YAPAXPBG@Z
// Complete 30-byte CFG: swscanf_s fills one pointer-width local from the wide
// text; no other referent.
HANDLE __cdecl decode_handle(const unsigned short *value)
{
    HANDLE result;
    swscanf_s(value, L"%p", &result);
    return result;
}

// FUNCTION: cl 0x40A496
// SYMBOL: ?get_mutex@@YAXXZ
// Complete 103-byte CFG with the real GS cookie. The inherited handle arrives
// as a wide environment string; a missing or unparsable value clears the
// canonical global through the real NT_err path.
void __cdecl get_mutex()
{
    if (!g_hMutex) {
        wchar_t value[20];
        NT_err(GetEnvironmentVariableW(L"MPCL_MUTEX_HANDLE", value, 20) != 0);
        if (swscanf_s(value, L"%p", &g_hMutex) != 1)
            g_hMutex = 0;
    }
}

// FUNCTION: cl 0x40A684
// SYMBOL: ?CreatePipe_robust@@YAXPAPAX0PAU_SECURITY_ATTRIBUTES@@K@Z
// Complete 118-byte CFG: retry ERROR_PIPE_BUSY at most five attempts with a
// 250 ms Sleep between attempts; any other failure raises exception code 1.
void __cdecl CreatePipe_robust(HANDLE *read_handle, HANDLE *write_handle,
                               SECURITY_ATTRIBUTES *attributes, unsigned long size)
{
    int attempts = 1;
    while (!CreatePipe(read_handle, write_handle, attributes, size)) {
        if (GetLastError() != ERROR_PIPE_BUSY) {
            RaiseException(1, 0, 0, 0);
        } else {
            if (++attempts > 5) {
                RaiseException(1, 0, 0, 0);
                break;
            }
            Sleep(250);
        }
    }
}

// FUNCTION: cl 0x40A6FA
// SYMBOL: ?MP_get_mutex@@YAXXZ
// Complete five-byte body: one tail transfer to the real loader above.
void __cdecl MP_get_mutex()
{
    get_mutex();
}

// FUNCTION: cl 0x40A7D3
// SYMBOL: ?read_robust@ProcessChannel@@QAEXPAXK@Z
// Complete 164-byte body including the __finally funclet at 0x40A867. The
// reader runs on a created thread while the process handle is the second wait
// target; only the thread handle is owned and closed here.
void ProcessChannel::read_robust(void *buffer, unsigned long size)
{
    HANDLE handles[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    __try {
        ProcessChannelReadContext context = { this, buffer, size, 0 };
        DWORD thread_id;
        handles[0] = CreateThread(0, 0, ProcessChannel_read_thread, &context, 0, &thread_id);
        NT_err(handles[0] != 0);
        handles[1] = process_handle;
        switch (WaitForMultipleObjects(2, handles, FALSE, INFINITE)) {
        case WAIT_OBJECT_0:
            if (context.success)
                break;
        case WAIT_OBJECT_0 + 1:
            RaiseException(1, 0, 0, 0);
            break;
        default:
            RaiseException(1, 0, 0, 0);
        }
    } __finally {
        if (handles[0] != INVALID_HANDLE_VALUE)
            CloseHandle(handles[0]);
    }
}

// FUNCTION: cl 0x40A877
// SYMBOL: ?read_int_robust@ProcessChannel@@QAEHXZ
// Complete 20-byte CFG: robust read of one int into a local, ret 0x40A88A.
int ProcessChannel::read_int_robust()
{
    int result;
    read_robust(&result, sizeof result);
    return result;
}

// FUNCTION: cl 0x40A88B
// SYMBOL: ?expect_int_robust@ProcessChannel@@QAEXH@Z
// Complete 27-byte CFG: compare through the robust reader, ret 4; a mismatch
// raises exception code 1.
void ProcessChannel::expect_int_robust(int expected)
{
    if (expected != read_int_robust())
        RaiseException(1, 0, 0, 0);
}
