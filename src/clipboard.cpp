#include "clipboard.h"
#include <thread>
#include <chrono>
#include <cstdio>

static std::string last_value;

void copy_to_clipboard(const std::string& s) {
    last_value = s;

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

    std::thread([]() {
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
        if (current_clipboard == last_value ||
            current_primary == last_value) {

            FILE* w1 = popen("xclip -selection clipboard", "w");
            if (w1) {
                pclose(w1);
            }

            FILE* w2 = popen("xclip -selection primary", "w");
            if (w2) {
                pclose(w2);
            }
        }
    }).detach();
}
