// SPDX-FileCopyrightText: Copyright (c) 2022 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#    include <mach/mach_traps.h>
#    include <mach/mach_init.h>
#    include <mach/vm_map.h>
#else
#    include <sys/mman.h>
#endif

namespace oaknut {

class CodeBlock {
public:
    explicit CodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_memory = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#elif defined(__APPLE__) && !defined(TARGET_OS_IPHONE)
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
#elif defined(__APPLE__) && defined(TARGET_OS_IPHONE)
        vm_size_t page_size = 0;
        host_page_size(mach_task_self(), &page_size);
        m_size = ((size + page_size - 1) / page_size) * page_size;
        vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&m_memory), m_size, TRUE); 
        vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_memory), size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
#else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#endif

        if (m_memory == nullptr)
            throw std::bad_alloc{};
    }

    ~CodeBlock()
    {
        if (m_memory == nullptr)
            return;

#if defined(_WIN32)
        VirtualFree((void*)m_memory, 0, MEM_RELEASE);
#elif defined(__APPLE__) && defined(TARGET_OS_IPHONE)
        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(m_memory), m_size);
#else
        munmap(m_memory, m_size);
#endif
    }

    CodeBlock(const CodeBlock&) = delete;
    CodeBlock& operator=(const CodeBlock&) = delete;
    CodeBlock(CodeBlock&&) = delete;
    CodeBlock& operator=(CodeBlock&&) = delete;

    std::uint32_t* ptr() const
    {
        return m_memory;
    }

    void protect()
    {
#if defined(__APPLE__) && !defined(TARGET_OS_IPHONE)
        pthread_jit_write_protect_np(1);
#elif defined(__APPLE__) && defined(TARGET_OS_IPHONE)
        vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_memory), m_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
#endif
        invalidate(m_memory, m_size);
    }

    void unprotect()
    {
#if defined(__APPLE__) && !defined(TARGET_OS_IPHONE)
        pthread_jit_write_protect_np(0);
#elif defined(__APPLE__) && defined(TARGET_OS_IPHONE)
        vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_memory), m_size, 0, VM_PROT_READ | VM_PROT_WRITE);
#endif
    }

    void invalidate(std::uint32_t* mem, std::size_t size)
    {
#if defined(__APPLE__)
        sys_icache_invalidate(mem, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), mem, size);
#else
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));

        const std::uintptr_t end = (std::uintptr_t)mem + size;

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(dsize - 1); addr < end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(isize - 1); addr < end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
#endif
    }

    void invalidate_all()
    {
        invalidate(m_memory, m_size);
    }

protected:
    std::uint32_t* m_memory;
    std::size_t m_size = 0;
};

}  // namespace oaknut
