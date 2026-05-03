#include "clipboard.h"
#include <thread>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <sodium.h>

static std::string last_value;
static std::mutex last_value_mutex;

static void clear_string(std::string& s) {
    if (!s.empty()) {
        sodium_memzero(&s[0], s.size());
        s.clear();
    }
}

void copy_to_clipboard(const std::string& s) {
    {
        std::lock_guard<std::mutex> lock(last_value_mutex);
        clear_string(last_value);
        last_value = s;
    }

    // Записываем в CLIPBOARD (Ctrl+V)
    FILE* p1 = popen("xclip -selection clipboard", "w");
    if (p1) {
        fwrite(s.data(), 1, s.size(), p1);
        pclose(p1);
    }

    // Записываем в PRIMARY (Shift+Insert / middle-click)
    FILE* p2 = popen("xclip -selection primary", "w");
    if (p2) {
        fwrite(s.data(), 1, s.size(), p2);
        pclose(p2);
    }

    std::thread([expected_value = std::string(s)]() mutable {
        std::this_thread::sleep_for(std::chrono::minutes(1));

        auto read_selection = [](const char* selection) -> std::string {
            std::string cmd =
                std::string("xclip -o -selection ") + selection;

            FILE* p = popen(cmd.c_str(), "r");
            if (!p) {
                return "";
            }

            char buf[1024];
            std::string out;

            while (fgets(buf, sizeof(buf), p)) {
                out += buf;
            }

            pclose(p);
            return out;
        };

        std::string current_clipboard = read_selection("clipboard");
        std::string current_primary = read_selection("primary");

        // Очищаем только если пароль всё ещё там
        if (current_clipboard == expected_value ||
            current_primary == expected_value) {

            FILE* w1 = popen("xclip -selection clipboard", "w");
            if (w1) {
                pclose(w1);
            }

            FILE* w2 = popen("xclip -selection primary", "w");
            if (w2) {
                pclose(w2);
            }
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
