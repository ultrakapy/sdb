#include <iostream>
#include <string_view>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <csignal>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <editline/readline.h>

#include <libsdb/process.hpp>
#include <libsdb/error.hpp>

namespace {
  std::atomic<bool> g_sigint{false};

  void sigint_handler(int) {
    g_sigint.store(true, std::memory_order_relaxed);
  }

  void install_sigint_handler() {
    struct sigaction sa{};
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
  }

  std::unique_ptr<sdb::process> attach(int argc, const char** argv) {
    pid_t pid = 0;
    // Passing PID
    if (argc == 3 && argv[1] == std::string_view("-p")) {
      pid = std::atoi(argv[2]);
      return sdb::process::attach(pid);
    } else { // Passing program name
      const char* program_path = argv[1];
      return sdb::process::launch(program_path);
    }
  }

  std::vector<std::string> split(std::string_view str, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {std::string{str}};
    std::string item;

    while (std::getline(ss, item, delimiter)) {
      out.push_back(item);
    }

    return out;
  }

  bool is_prefix(std::string_view str, std::string_view of) {
    if (str.size() > of.size()) return false;
    return std::equal(str.begin(), str.end(), of.begin());
  }

  std::string sig_name(int sig) {
    const char* s = strsignal(sig);
    if (!s) s = "UNKNOWN";
    return std::string(s);
  }

  void print_stop_reason(const sdb::process& process, sdb::stop_reason reason) {
    std::cout << "Process " << process.pid() << ' ';

    switch (reason.reason) {
    case sdb::process_state::exited:
      std::cout << "exited with status "
                << static_cast<int>(reason.info);
      break;
    case sdb::process_state::terminated:
      std::cout << "terminated with signal "
                << sig_name(reason.info);
      break;
    case sdb::process_state::stopped:
      std::cout << "stopped with signal "
                << sig_name(reason.info);
      break;
    }

    std::cout << std::endl;
  }

  bool should_auto_continue(const sdb::stop_reason& r) {
    if (r.reason == sdb::process_state::exited ||
        r.reason == sdb::process_state::terminated) {
      return false;
    }

    if (r.reason == sdb::process_state::stopped) {
      // SIGTRAP for breakpoint or single-step?
      if (r.info == SIGTRAP || r.info == SIGINT)
        return false;

      // Other signals may or may not be auto-forwarded
      return true;
    }

    return false;
  }


  void handle_command(std::unique_ptr<sdb::process>& process, std::string_view line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if (is_prefix(command, "continue")) {
      // Start with a clean slate: no signal to forward yet
      int signal_to_forward = 0;

      while (true) {
        process->resume(signal_to_forward);
        auto reason = process->wait_on_signal();

        // Single check for manual Ctrl+C (via the debugger)
        if (g_sigint.exchange(false)) {
          kill(process->pid(), SIGINT);
          // Wait for the SIGINT we just sent to actually stop the process
          reason = process->wait_on_signal();
          print_stop_reason(*process, reason);
          break; 
        }

        print_stop_reason(*process, reason);

        // Check if the signal received (e.g. SIGINT or SIGTRAP) should return to prompt
        if (!should_auto_continue(reason)) {
          break;
        }

        // If we got here, we are auto-continuing and passing the signal along
        signal_to_forward = reason.info;
      }
    } else {
      std::cerr << "Unknown command\n";
    }
  }

  void main_loop(std::unique_ptr<sdb::process>& process) {
    g_sigint.store(false); // Clear any "stale" interrupts from the prompt

    char* line = nullptr;
    while ((line = readline("sdb> ")) != nullptr) {
      std::string line_str;

      if (line == std::string_view("")) {
        free(line);
        if (history_length > 0) {
          line_str = history_list()[history_length - 1]->line;
        }
      } else {
        line_str = line;
        add_history(line);
        free(line);
      }

      if (!line_str.empty()) {
        try {
          handle_command(process, line_str);
        }
        catch (const sdb::error& err) {
          std::cout << err.what() << '\n';
        }
      }
    }
  }
}

int main(int argc, const char** argv) {
  if (argc == 1) {
    std::cerr << "No arguments given\n";
    return -1;
  }

  install_sigint_handler();

  try {
    auto process = attach(argc, argv);
    main_loop(process);
  }
  catch (const sdb::error& err) {
    std::cout << err.what() << '\n';
  }
}

