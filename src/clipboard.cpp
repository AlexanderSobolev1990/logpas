#include "clipboard.h"
#include <thread>
#include <chrono>
#include <cstdio>

static std::string last_value;

void copy_to_clipboard(const std::string& s) {
    last_value = s;

    FILE* p = popen("xclip -selection clipboard", "w");
    fwrite(s.data(), 1, s.size(), p);
    pclose(p);

    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        FILE* p = popen("xclip -o -selection clipboard", "r");
        char buf[1024];
        std::string now;
        while (fgets(buf, sizeof(buf), p)) now += buf;
        pclose(p);

        if (now == last_value) {
            FILE* w = popen("xclip -selection clipboard", "w");
            pclose(w);
        }
    }).detach();
}
