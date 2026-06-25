#include "clipboard.hpp"
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <stdexcept>
#include <sodium.h>

static std::string last_value;
static std::mutex last_value_mutex;

enum class ClipboardBackend {
    Wayland,
    Xclip,
    Xsel
};

static void clear_string(std::string& s) {
    if (!s.empty()) {
        sodium_memzero(&s[0], s.size());
        s.clear();
    }
}

static bool env_is_set(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr && value[0] != '\0';
}

static bool command_available(const char* command) {
    std::string check = std::string("command -v ") + command +
                        " >/dev/null 2>&1";
    return std::system(check.c_str()) == 0;
}

static bool select_backend(ClipboardBackend& backend) {
    const bool have_wayland =
        command_available("wl-copy") && command_available("wl-paste");
    const bool have_xclip = command_available("xclip");
    const bool have_xsel = command_available("xsel");

    if (env_is_set("WAYLAND_DISPLAY") && have_wayland) {
        backend = ClipboardBackend::Wayland;
        return true;
    }

    if (env_is_set("DISPLAY") && have_xclip) {
        backend = ClipboardBackend::Xclip;
        return true;
    }

    if (env_is_set("DISPLAY") && have_xsel) {
        backend = ClipboardBackend::Xsel;
        return true;
    }

    if (have_wayland) {
        backend = ClipboardBackend::Wayland;
        return true;
    }

    if (have_xclip) {
        backend = ClipboardBackend::Xclip;
        return true;
    }

    if (have_xsel) {
        backend = ClipboardBackend::Xsel;
        return true;
    }

    return false;
}

static const char* write_command(ClipboardBackend backend, bool primary) {
    if (backend == ClipboardBackend::Wayland) {
        return primary
            ? "wl-copy --primary --type text/plain"
            : "wl-copy --type text/plain";
    }

    if (backend == ClipboardBackend::Xsel) {
        return primary
            ? "xsel --primary --input"
            : "xsel --clipboard --input";
    }

    return primary
        ? "xclip -selection primary"
        : "xclip -selection clipboard";
}

static const char* read_command(ClipboardBackend backend, bool primary) {
    if (backend == ClipboardBackend::Wayland) {
        return primary
            ? "wl-paste --primary --no-newline"
            : "wl-paste --no-newline";
    }

    if (backend == ClipboardBackend::Xsel) {
        return primary
            ? "xsel --primary --output"
            : "xsel --clipboard --output";
    }

    return primary
        ? "xclip -o -selection primary"
        : "xclip -o -selection clipboard";
}

static bool write_selection(ClipboardBackend backend, bool primary,
                            const std::string& value) {
    FILE* p = popen(write_command(backend, primary), "w");

    if (!p) {
        return false;
    }

    const size_t written = fwrite(value.data(), 1, value.size(), p);
    const int status = pclose(p);

    return written == value.size() && status == 0;
}

static std::string read_selection(ClipboardBackend backend, bool primary) {
    FILE* p = popen(read_command(backend, primary), "r");

    if (!p) {
        return "";
    }

    char buf[1024];
    std::string out;
    size_t n = 0;

    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) {
        out.append(buf, n);
    }

    if (pclose(p) != 0) {
        clear_string(out);
        return "";
    }

    return out;
}

void copy_to_clipboard(const std::string& s) {
    ClipboardBackend backend;

    if (!select_backend(backend)) {
        throw std::runtime_error(
            "clipboard backend not found: install xclip, xsel or wl-clipboard"
        );
    }

    {
        std::lock_guard<std::mutex> lock(last_value_mutex);
        clear_string(last_value);
        last_value = s;
    }

    if (!write_selection(backend, false, s)) {
        std::lock_guard<std::mutex> lock(last_value_mutex);
        clear_string(last_value);
        throw std::runtime_error("cannot write to clipboard");
    }

    // PRIMARY is optional on some desktops, so keep the main clipboard usable.
    write_selection(backend, true, s);

    std::thread([backend, expected_value = std::string(s)]() mutable {
        std::this_thread::sleep_for(std::chrono::minutes(1));

        std::string current_clipboard = read_selection(backend, false);
        std::string current_primary = read_selection(backend, true);

        // Очищаем только если пароль всё ещё там
        if (current_clipboard == expected_value ||
            current_primary == expected_value) {
            write_selection(backend, false, "");
            write_selection(backend, true, "");
        }

        clear_string(current_clipboard);
        clear_string(current_primary);

        {
            std::lock_guard<std::mutex> lock(last_value_mutex);

            if (last_value == expected_value) {
                clear_string(last_value);
            }
        }

        clear_string(expected_value);
    }).detach();
}
