#pragma once

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <utility>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <Foundation/Foundation.h>

namespace MemX {

    inline bool HeaderIsValid(const mach_header *header) {
        if (!header) return false;
        if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) return false;
        if (header->ncmds == 0 || header->ncmds > 4096) return false;
        if (header->sizeofcmds == 0) return false;
        if (header->sizeofcmds > (4u * 1024u * 1024u)) return false;
        return true;
    }

    inline uintptr_t GetImageBase(const std::string& imageName) {
        if (imageName.empty()) return 0;

        uint32_t count = _dyld_image_count();
        if (count > 8192) count = 8192;

        for (uint32_t i = 0; i < count; ++i) {
            const char* imgName = _dyld_get_image_name(i);
            if (!imgName) continue;
            if (strstr(imgName, imageName.c_str())) {
                const mach_header *header = _dyld_get_image_header(i);
                if (!HeaderIsValid(header)) continue;
                return reinterpret_cast<uintptr_t>(header);
            }
        }
        return 0;
    }

    struct AddrRange {
        uintptr_t start;
        uintptr_t end;
    };

    inline const std::vector<AddrRange>& GetFullAddr() {
        static std::vector<AddrRange> ranges;

        if (!ranges.empty()) {
            return ranges;
        }

        uint32_t imageCount = _dyld_image_count();
        if (imageCount > 8192) imageCount = 8192;

        for (uint32_t i = 0; i < imageCount; ++i) {
            const mach_header* header = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);

            if (!HeaderIsValid(header)) continue;

            const uint8_t* ptr = reinterpret_cast<const uint8_t*>(header);
            const load_command* cmd = nullptr;
            uint32_t ncmds = 0;
            uint32_t sizeofcmds = 0;

            switch (header->magic) {
                case MH_MAGIC_64: {
                    const auto* hdr = reinterpret_cast<const mach_header_64*>(ptr);
                    cmd = reinterpret_cast<const load_command*>(hdr + 1);
                    ncmds = hdr->ncmds;
                    sizeofcmds = hdr->sizeofcmds;
                    break;
                }
                case MH_MAGIC: {
                    const auto* hdr = reinterpret_cast<const mach_header*>(ptr);
                    cmd = reinterpret_cast<const load_command*>(hdr + 1);
                    ncmds = hdr->ncmds;
                    sizeofcmds = hdr->sizeofcmds;
                    break;
                }
                default:
                    continue;
            }

            const uint8_t* cursor = reinterpret_cast<const uint8_t*>(cmd);
            const uint8_t* limit = cursor + sizeofcmds;

            for (uint32_t j = 0; j < ncmds; ++j) {
                if (cursor + sizeof(load_command) > limit) break;

                const load_command* current =
                    reinterpret_cast<const load_command*>(cursor);

                if (current->cmdsize < sizeof(load_command)) break;
                if (cursor + current->cmdsize > limit) break;

                if (current->cmd == LC_SEGMENT_64 &&
                    current->cmdsize >= sizeof(segment_command_64)) {

                    const auto* seg =
                        reinterpret_cast<const segment_command_64*>(current);

                    uintptr_t start = static_cast<uintptr_t>(seg->vmaddr + slide);
                    uintptr_t size = static_cast<uintptr_t>(seg->vmsize);

                    if (size != 0 && start + size > start) {
                        ranges.push_back({start, start + size});
                    }
                }

                cursor += current->cmdsize;
            }
        }

        return ranges;
    }

    inline void ClearAddrRange() {
        static std::vector<AddrRange>& ranges = const_cast<std::vector<AddrRange>&>(GetFullAddr());
        if (ranges.empty()) return;
        ranges.clear();
    }

    inline bool IsValidPointer(uintptr_t addr) {
        if (!addr) return false;

        const auto& ranges = GetFullAddr();

        for (const auto& r : ranges) {
            if (addr >= r.start && addr < r.end) {
                return true;
            }
        }
        return false;
    }

    inline bool IsValidRange(uintptr_t addr, size_t len) {
        if (!addr || len == 0) return false;

        uintptr_t end = addr + len;
        if (end < addr) return false;

        const auto& ranges = GetFullAddr();

        for (const auto& r : ranges) {
            if (addr >= r.start && end <= r.end) {
                return true;
            }
        }
        return false;
    }

    inline bool _read(uintptr_t addr, void* buffer, size_t len) {
        if (!buffer || len == 0) return false;
        if (!IsValidRange(addr, len)) return false;

        vm_size_t got = 0;

        kern_return_t kr = vm_read_overwrite(
            mach_task_self(),
            (vm_address_t)addr,
            (vm_size_t)len,
            (vm_address_t)buffer,
            &got
        );

        return kr == KERN_SUCCESS && got == len;
    }

    template <typename T>
    inline T Read(uintptr_t address) {
        T data{};
        _read(address, &data, sizeof(T));
        return data;
    }

    inline std::string ReadString(void* address, size_t max_len) {
        if (!address || max_len == 0) return "";
        if (!IsValidPointer(reinterpret_cast<uintptr_t>(address))) return "Invalid Pointer!!";

        std::vector<char> chars(max_len + 1, '\0');

        if (_read(reinterpret_cast<uintptr_t>(address), chars.data(), max_len)) {
            return std::string(chars.data(), strnlen(chars.data(), max_len));
        }
        return "";
    }

    template <typename T>
    inline void Write(uintptr_t address, const T& value) {
        if (!IsValidRange(address, sizeof(T))) return;

        vm_write(
            mach_task_self(),
            (vm_address_t)address,
            (vm_address_t)(uintptr_t)&value,
            (vm_size_t)sizeof(T)
        );
    }
}
