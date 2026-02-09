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
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <libsdb/parse.hpp>

namespace {
  // This will trigger a compiler error if atomic<bool> uses a mutex
  static_assert(std::atomic<bool>::is_always_lock_free,
                "std::atomic<bool> must be lock-free for signal safety!");
  // Asynchronous interrupt flag used in SIGINT handler
  std::atomic<bool> g_sigint{false};

  // Signal handler to capture Ctrl+C
  void sigint_handler(int) {
    g_sigint.store(true, std::memory_order_relaxed);
  }

  /*
    RAII guard to manage debugger signal handler lifecycle.
    Captures original SIGINT state and restores it on destruction.
   */
  struct signal_restorer {
    struct sigaction old_sa;

    // Swap to debugger SIGINT handler and save original configuration
    signal_restorer() {
      struct sigaction sa{};
      sa.sa_handler = sigint_handler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;

      if (sigaction(SIGINT, &sa, &old_sa) < 0) {
        sdb::error::send_errno("Failed to install SIGINT handler");
      }
    }

    // Restore original SIGINT configuration
    ~signal_restorer() {
      if (sigaction(SIGINT, &old_sa, nullptr) < 0) {
        // Log failure to restore; avoid throwing in destructor
        std::cerr << "Warning: Failed to restore SIGINT handler\n";
      }
    }
  };

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
    std::string message;
    switch (reason.reason) {
    case sdb::process_state::exited:
      message = fmt::format("exited with status {}",
                            static_cast<int>(reason.info));
      break;
    case sdb::process_state::terminated:
      message = fmt::format("terminated with signal {}",
                            sig_name(reason.info));
      break;
    case sdb::process_state::stopped:
      message = fmt::format("stopped with signal {} at {:#x}",
                            sig_name(reason.info), process.get_pc().addr());
      break;
    }

    fmt::print("Process {} {}\n", process.pid(), message);
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

  void print_help(const std::vector<std::string>& args) {
    if (args.size() == 1) {
      std::cerr << R"(Available commands:
    continue    - Resume the process
    register    - Commands for operating on registers
)";
    }

    else if (is_prefix(args[1], "register")) {
      std::cerr << R"(Available commands:
    read
    read <register>
    read all
    write <register> <value>
)";
    }
    else {
      std::cerr << "No help available on that\n";
    }
  }

  void handle_register_read(sdb::process& process,
                            const std::vector<std::string>& args) {
    auto format = [](auto t) {
                    if constexpr (std::is_floating_point_v<decltype(t)>) {
                return fmt::format("{}", t);
            }
            else if constexpr (std::is_integral_v<decltype(t)>) {
                return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
            }
            else {
                return fmt::format("[{:#04x}]", fmt::join(t, ","));
            }
            };

    if (args.size() == 2 or
        (args.size() == 3 and args[2] == "all")) {
      for (auto& info : sdb::g_register_infos) {
        auto should_print = (args.size() == 3 or
                             info.type == sdb::register_type::gpr)
          and info.name != "orig_rax";
        if (!should_print) continue;
        auto value = process.get_registers().read(info);
        fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
      }
    }
    else if (args.size() == 3) {
      try {
        auto info = sdb::register_info_by_name(args[2]);
        auto value = process.get_registers().read(info);
        fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
      }
      catch (sdb::error& err) {
        std::cerr << "No such register\n";
        return;
      }
    }
    else {
      print_help({ "help", "register" });
    }
  }

  sdb::registers::value parse_register_value(sdb::register_info info, std::string_view text) {
    try {
      if (info.format ==
          sdb::register_format::uint) {
        switch (info.size) {
        case 1: return sdb::to_integral<std::uint8_t>(text, 16).value();
        case 2: return sdb::to_integral<std::uint16_t>(text, 16).value();
        case 4: return sdb::to_integral<std::uint32_t>(text, 16).value();
        case 8: return sdb::to_integral<std::uint64_t>(text, 16).value();
        }
      }
      else if (info.format ==
               sdb::register_format::double_float) {
        return sdb::to_float<double>(text).value();
      }
      else if (info.format ==
               sdb::register_format::long_double) {
        return sdb::to_float<long double>(text).value();
      }
      else if (info.format ==
               sdb::register_format::vector) {
        if (info.size == 8) {
          return sdb::parse_vector<8>(text);
        }
        else if (info.size == 16) {
          return sdb::parse_vector<16>(text);
        }
      }
    }
    catch (...) {}
    sdb::error::send("Invalid format");
  }

  void handle_register_write(sdb::process& process,
                             const std::vector<std::string>& args) {
    if (args.size() != 4) {
      print_help({ "help", "register" });
      return;
    }
    try {
      auto info = sdb::register_info_by_name(args[2]);
      auto value = parse_register_value(info, args[3]);
      process.get_registers().write(info, value);
    }
    catch (sdb::error& err) {
      std::cerr << err.what() << '\n';
      return;
    }
  }

  void handle_register_command(sdb::process& process,
                               const std::vector<std::string>& args) {
    if (args.size() < 2) {
      print_help({ "help", "register" });
      return;
    }

    if (is_prefix(args[1], "read")) {
      handle_register_read(process, args);
    }
    else if (is_prefix(args[1], "write")) {
      handle_register_write(process, args);
    }
    else {
      print_help({ "help", "register" });
    }
  }

  void handle_command(std::unique_ptr<sdb::process>& process, std::string_view line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if (is_prefix(command, "continue")) {
      // Just by declaring this guard, we install our SIGINT handler and save the old one.
      signal_restorer guard;

      // Start with a clean interrupt state
      g_sigint.store(false);

      // Start with no signal to forward yet
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
    } else if (is_prefix(command, "help")) {
      print_help(args);
    } else if (is_prefix(command, "register")) {
      handle_register_command(*process, args);
    } else {
      std::cerr << "Unknown command\n";
    }
  }

  void main_loop(std::unique_ptr<sdb::process>& process) {
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

  try {
    auto process = attach(argc, argv);
    main_loop(process);
  }
  catch (const sdb::error& err) {
    std::cout << err.what() << '\n';
    return -1;
  }
}

