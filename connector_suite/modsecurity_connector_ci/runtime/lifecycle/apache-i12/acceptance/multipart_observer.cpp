/* Apache I12 test-only public-SDK multipart observation; never changes SDK calls. */
#include <modsecurity/transaction.h>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr std::size_t max_files = 16;
constexpr std::size_t max_transactions = 128;
constexpr std::size_t max_records = 4096;
constexpr off_t max_output = 1024 * 1024;
static_assert(std::chrono::steady_clock::is_steady, "multipart timestamps require a monotonic clock");
class Descriptor {
public:
    explicit Descriptor(int value) noexcept : value_(value) {}
    ~Descriptor() { if (value_ >= 0) close(value_); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    int get() const noexcept { return value_; }
private:
    int value_;
};
struct Saved { std::string id; std::vector<std::string> paths; bool complete; };
struct ObserverState {
    std::mutex lock;
    std::map<void *, Saved> saved;
    pid_t owner = 0;
    std::size_t records = 0;
};
ObserverState &observer_state() {
    static ObserverState state;
    return state;
}

std::string json_quoted(std::string_view value) {
    constexpr std::string_view hex = "0123456789abcdef";
    std::ostringstream out; out << '"';
    for (unsigned char c : value.substr(0, 256)) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32 || c >= 127) {
            const std::byte byte{c};
            out << R"(\u00)" << hex[std::to_integer<unsigned>(byte >> 4)]
                << hex[std::to_integer<unsigned>(byte & std::byte{15})];
        }
        else out << c;
    }
    out << '"'; return out.str();
}
std::string fingerprint(const std::string &value) {
    // Correlation only: explicitly not an integrity or cryptographic hash.
    uint64_t hash = UINT64_C(14695981039346656037);
    for (unsigned char c : value) { hash ^= c; hash *= UINT64_C(1099511628211); }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result(16, '0');
    for (std::size_t i = result.size(); i > 0; --i) {
        result[i - 1] = hex[hash & 15];
        hash >>= 4;
    }
    return result;
}
bool private_file(const struct stat &info) {
    return S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
        (info.st_mode & 0777) == 0600 && info.st_nlink == 1;
}
int root_fd(std::string &path) {
    const char *configured = std::getenv("I12_APACHE_MULTIPART_ROOT");
    if (!configured || configured[0] != '/' || strnlen(configured, PATH_MAX) >= PATH_MAX) return -1;
    if (std::array<char, PATH_MAX> canonical{};
        !realpath(configured, canonical.data()) || std::strcmp(canonical.data(), configured)) return -1;
    path = configured;
    if (int fd = open(configured, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); fd >= 0) {
        struct stat info;
        if (fstat(fd, &info) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0700) { close(fd); return -1; }
        Descriptor marker(openat(fd, "multipart.enable", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
        constexpr std::string_view expected = "I12_APACHE_MULTIPART_V1\n";
        std::array<char, expected.size() + 2> text{};
        if (bool admitted = marker.get() >= 0 && !fstat(marker.get(), &info) && private_file(info) &&
            read(marker.get(), text.data(), text.size()) == static_cast<ssize_t>(expected.size()) &&
            std::string_view(text.data(), expected.size()) == expected; !admitted) { close(fd); return -1; }
        return fd;
    }
    return -1;
}
void output(ObserverState &state, int root, const std::string &row) {
    if (state.records >= max_records) return;
    if (Descriptor fd(openat(root, "multipart.jsonl", O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600)); fd.get() >= 0) {
        struct stat info;
        if (!fstat(fd.get(), &info) && private_file(info) && info.st_size <= max_output - static_cast<off_t>(row.size() + 1)) {
            std::string line = row + '\n';
            ssize_t count = write(fd.get(), line.data(), line.size());
            if (count == static_cast<ssize_t>(line.size())) ++state.records;
        }
    }
}
std::string common(const modsecurity::Transaction *key, const std::string &id, const char *kind) {
    const auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    std::ostringstream out;
    out << R"({"kind":)" << json_quoted(kind) << R"(,"transaction_key":")" << key << R"(","transaction_id":)" << json_quoted(id)
        << R"(,"transaction_id_source":"sdk_public_m_id","pid":)" << getpid()
        << R"(,"tid":)" << syscall(SYS_gettid) << R"(,"euid":)" << geteuid()
        << R"(,"monotonic_ns":)" << timestamp;
    return out.str();
}
bool has_path_separator(std::string_view path) {
#if defined(__cpp_lib_string_contains) && __cpp_lib_string_contains >= 202011L
    return path.contains('/');
#else
    return path.find('/') != std::string_view::npos;
#endif
}
std::string path_metadata(int root, const std::string &directory, const std::string &path) {
    std::ostringstream out; out << R"({"path_fingerprint_fnv1a64":)" << json_quoted(fingerprint(path));
    std::string prefix = directory + "/";
    bool inside = path.compare(0, prefix.size(), prefix) == 0;
    std::string leaf = inside ? path.substr(prefix.size()) : "";
    bool accepted = !leaf.empty() && leaf != "." && leaf != ".." && !has_path_separator(leaf);
    out << R"(,"direct_private_child":)" << (accepted ? "true" : "false");
    if (!accepted) return out.str() + R"(,"exists":null,"stat_errno":null})";
    struct stat info = {};
    int result = fstatat(root, leaf.c_str(), &info, AT_SYMLINK_NOFOLLOW);
    int error = result ? errno : 0;
    out << R"(,"stat_result":)" << result << R"(,"stat_errno":)" << error;
    if (result == 0) {
        out << R"(,"exists":true,"regular":)" << (S_ISREG(info.st_mode) ? "true" : "false")
            << R"(,"symlink":)" << (S_ISLNK(info.st_mode) ? "true" : "false")
            << R"(,"device":)" << info.st_dev << R"(,"inode":)" << info.st_ino
            << R"(,"size":)" << info.st_size << R"(,"uid":)" << info.st_uid
            << R"(,"mode":)" << (info.st_mode & 0777) << R"(,"nlink":)" << info.st_nlink;
    } else out << R"(,"exists":)" << (error == ENOENT ? "false" : "null");
    return out.str() + "}";
}
std::string files(int root, const std::string &directory, const std::vector<std::string> &paths) {
    std::ostringstream out; out << '[';
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (i) out << ',';
        out << path_metadata(root, directory, paths[i]);
    }
    out << ']'; return out.str();
}
std::string names(const modsecurity::AnchoredSetVariable &collection) {
    std::ostringstream out; out << '['; std::size_t count = 0;
    for (const auto &[name, value] : collection) {
        if (count == max_files) break;
        if (count) out << ',';
        ++count;
        out << R"({"key_fingerprint_fnv1a64":)" << json_quoted(fingerprint(name))
            << R"(,"value_fingerprint_fnv1a64":)";
        out << (value ? json_quoted(fingerprint(value->getValue())) : "null") << '}';
    }
    return out.str() + ']';
}
Saved snapshot_paths(const modsecurity::Transaction &transaction) {
    Saved snapshot{transaction.m_id, {}, transaction.m_variableFilesTmpNames.size() <= max_files};
    for (const auto &[name, value] : transaction.m_variableFilesTmpNames) {
        if (snapshot.paths.size() == max_files) break;
        if (value) snapshot.paths.push_back(value->getValue());
        else snapshot.complete = false;
    }
    return snapshot;
}
void reset_process(ObserverState &state) {
    if (state.owner != getpid()) { state.saved.clear(); state.records = 0; state.owner = getpid(); }
}
void observation_failed() noexcept {
    // No exception may cross the C ABI, and exception messages may contain
    // request data. A fixed diagnostic leaves failed observation visible.
    constexpr std::string_view message = "apache-multipart-observer: observation failed\n";
    (void)syscall(SYS_write, STDERR_FILENO, message.data(), message.size());
}
}  // namespace

extern "C" void i12_apache_observe_multipart(void *opaque) noexcept {
    int previous_errno = errno;
    try {
        std::string directory;
        Descriptor root(root_fd(directory));
        auto &state = observer_state();
        std::scoped_lock guard(state.lock); reset_process(state);
        if (root.get() >= 0) {
            auto found = state.saved.find(opaque);
            if (opaque && (found != state.saved.end() || state.saved.size() < max_transactions)) {
                const auto *transaction = static_cast<const modsecurity::Transaction *>(opaque);
                Saved snapshot = snapshot_paths(*transaction);
                std::ostringstream row;
                row << common(transaction, snapshot.id, "native_multipart_after_request_body")
                    << R"(,"files_count":)" << transaction->m_variableFiles.size()
                    << R"(,"files_names_count":)" << transaction->m_variableFilesNames.size()
                    << R"(,"files_sizes_count":)" << transaction->m_variableFilesSizes.size()
                    << R"(,"filename_fingerprints":)" << names(transaction->m_variableFiles)
                    << R"(,"filename_fingerprints_complete":)" << (transaction->m_variableFiles.size() <= max_files ? "true" : "false")
                    << R"(,"files_tmpnames_count":)" << transaction->m_variableFilesTmpNames.size()
                    << R"(,"files_combined_size":)" << json_quoted(transaction->m_variableFilesCombinedSize.m_value)
                    << R"(,"native_tmpfile_objects_count":)" << transaction->m_multipartPartTmpFiles.size()
                    << R"(,"path_snapshot_complete":)" << (snapshot.complete ? "true" : "false")
                    << R"(,"max_observed_files":)" << max_files << R"(,"files":)" << files(root.get(), directory, snapshot.paths) << '}';
                if (found != state.saved.end()) found->second = snapshot;
                else state.saved.try_emplace(opaque, snapshot);
                output(state, root.get(), row.str());
            }
        }
    } catch (...) { observation_failed(); }
    errno = previous_errno;
}

extern "C" void i12_apache_observe_multipart_cleanup(void *opaque) noexcept {
    int previous_errno = errno;
    try {
        std::string directory;
        Descriptor root(root_fd(directory));
        auto &state = observer_state();
        std::scoped_lock guard(state.lock); reset_process(state);
        auto found = state.saved.find(opaque);
        if (found != state.saved.end()) {
            if (root.get() >= 0) {
                std::string row = common(static_cast<modsecurity::Transaction *>(opaque), found->second.id, "native_multipart_after_actual_cleanup");
                row += R"(,"dead_transaction_dereferenced":false,"path_snapshot_complete":)";
                row += found->second.complete ? "true" : "false";
                output(state, root.get(), row + R"(,"files":)" + files(root.get(), directory, found->second.paths) + "}");
            }
            state.saved.erase(found);
        }
    } catch (...) { observation_failed(); }
    errno = previous_errno;
}
