#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

bool fill_from_getrandom(uint8_t* out, size_t outlen)
{
#ifdef SYS_getrandom
    while (outlen > 0) {
        const long result = syscall(
            SYS_getrandom,
            out,
            outlen,
            0
        );

        if (result > 0) {
            out += static_cast<size_t>(result);
            outlen -= static_cast<size_t>(result);
            continue;
        }

        if (result < 0 && errno == EINTR) {
            continue;
        }

        return false;
    }

    return true;
#else
    (void)out;
    (void)outlen;
    return false;
#endif
}

bool fill_from_urandom(uint8_t* out, size_t outlen)
{
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    while (outlen > 0) {
        const ssize_t result = read(fd, out, outlen);

        if (result > 0) {
            out += static_cast<size_t>(result);
            outlen -= static_cast<size_t>(result);
            continue;
        }

        if (result < 0 && errno == EINTR) {
            continue;
        }

        close(fd);
        return false;
    }

    close(fd);
    return true;
}

} // namespace

extern "C" void randombytes(uint8_t* out, size_t outlen)
{
    if (outlen == 0) {
        return;
    }

    if (out == nullptr) {
        std::abort();
    }

    if (fill_from_getrandom(out, outlen)) {
        return;
    }

    if (fill_from_urandom(out, outlen)) {
        return;
    }

    std::abort();
}
