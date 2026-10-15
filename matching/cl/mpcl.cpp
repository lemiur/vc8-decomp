#include "../../include/cl/mpcl.h"

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

template action_t *Queue<action_t>::try_head_nosync();
template int Queue<action_t>::append_nosync(Queue<action_t> &);
template int Queue<action_t>::add_head_nosync(action_t *);
template int Queue<action_t>::size() const;
template int Queue<action_t>::add_tail(action_t *);
template int Queue<action_t>::add_head(action_t *);
