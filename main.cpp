#include <alloca.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

#include <cassert>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <algorithm>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>

#ifndef NDEBUG
#define DbgPrint(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define DbgPrint(fmt, ...)
#endif

static void copy_dependency(int dirfd, const char * path);

static void usage(const char *name, int exit_code)
{
    assert(name);
    fprintf(stderr, "\nUsage\n");
    fprintf(stderr, "    %s <root> <path|file> ...\n", name);
    fprintf(stderr, "\nParameters\n");
    fprintf(stderr, "    root    The root directory of the file system for saving the dependencies\n");
    fprintf(stderr, "    path    The dependencies of file at path to be picked\n");
    fprintf(stderr, "    file    The dependencies of file to be picked, PATH will be searched if file does not contain a slash (/).\n");
    fprintf(stderr, "\nExample\n");
    fprintf(stderr, "    %s /usr/bin/ls /usr/bin/echo\n", name);
    fprintf(stderr, "    %s ls echo bash\n", name);
    exit(exit_code);
}

/**
 * @brief 分割字符串
 *
 * @param str   输入字符串
 * @param delim 分割符
 * @return 返回分割后的字符串
 */
static std::tuple<std::string_view, std::string_view> strsep(std::string_view str, char delim)
{
    auto const first = std::find_if(str.begin(), str.end(),
                                    [](char c) { return !std::isspace(c); });
    auto const offset = first - str.begin();
    auto const pos = str.find(delim, offset);
    if (pos == std::string_view::npos) return { str, {} };
    return { str.substr(offset, pos - offset), str.substr(pos + 1) };
}

static void open_pipe(int pipe[2])
{
    auto const flag = 0;
    if (pipe2(pipe, flag) == -1) {
        fprintf(stderr, "pipe2(%p, %d) failed: %m", pipe, flag);
        exit(EXIT_FAILURE);
    }
}

static void child_run(int pipe[2], const char * name)
{
    // 关闭不需要的管道
    close(pipe[0]); // 关闭stdout管道的读端

    // 重定向管道
    dup2(pipe[1], STDOUT_FILENO); // 将管道的写端重定向到stdout

    // 设置环境变量
    setenv("LD_TRACE_LOADED_OBJECTS", "true", 1);

    // 执行命令
    execl(name, name, nullptr);

    // 如果执行到这里，说明执行失败
    fprintf(stderr, "execl(\"%s\", \"%s\", nullptr) failed: %m\n", name, name);
}

static void parse_dependency(std::set<std::string> & deps, const char * buf)
{
    DbgPrint("DBG: input: %s", buf);

    // 以空格分割字符串，取第一个字符串
    auto [first, second] = strsep(buf, ' ');
    if (__glibc_unlikely(first.empty())) return;

    // 跳过linux-vdso.so.1
    if (__glibc_unlikely(first == "linux-vdso.so.1")) return;

    if (__glibc_unlikely(first[0] == '/')) {
        DbgPrint("DBG: output: %.*s\n", static_cast<int>(first.length()), first.data());
    } else {
        // 解析依赖库前面的“=>”符号
        std::tie(first, second) = strsep(second, ' ');
        if (__glibc_unlikely(first != "=>"))
            throw std::runtime_error("invalid format");

        // 解析依赖库的绝对路径
        std::tie(first, second) = strsep(second, ' ');
        if (__glibc_unlikely(first.empty() || first[0] != '/'))
            throw std::runtime_error("invalid format");

        DbgPrint("DBG: output: %.*s\n", static_cast<int>(first.length()), first.data());
    }

    deps.insert(std::string{ first });
}

/**
 * @brief 搜索PATH环境变量
 *
 * @param name 可执行文件名
 * @return 返回可执行文件的绝对路径
 */
static std::string search_env_path(const char * name)
{
    assert(name);

    std::string ret;

    // 如果name中包含斜杠，直接返回
    auto const name_len = strlen(name);
    auto const name_end = name + name_len;
    auto const pos = std::find(name, name_end, '/');
    if (pos != name_end) {
        // 如果name中包含斜杠，直接返回
        ret.assign(name, name_len);
        return ret;
    }

    // 获取PATH环境变量
    auto const env_path = getenv("PATH");
    if (!env_path) {
        fprintf(stderr, "getenv(\"PATH\") failed: %m\n");
        exit(EXIT_FAILURE);
    }

    // 分配内存
    auto const env_path_len = strlen(env_path);
    auto const buf_len = name_len + env_path_len + 2;
    auto const buf = static_cast<char *>(alloca(buf_len));

    for (std::string_view first, second{env_path, env_path_len}; !second.empty(); ) {
        // 以冒号分割PATH环境变量
        std::tie(first, second) = strsep(second, ':');
        if (first.empty()) break;

        // 拼接路径
        auto p = std::copy(first.begin(), first.end(), buf);
        if (p[-1] != '/') *p++ = '/';
        p = std::copy(name, name + name_len, p);
        *p = '\0';

        // 检查文件是否存在
        if (access(buf, F_OK) < 0) continue;

        // 拷贝文件路径
        ret.assign(buf, p - buf);
        break;
    }

    return ret;
}

static void parent_run(std::set<std::string> & deps, int pipe[2], pid_t pid)
{
    // 关闭不需要的管道
    close(pipe[1]); // 关闭stdout管道的写端

    // 打开FILE指针
    auto const mode = "r";
    auto const fp = fdopen(pipe[0], mode);
    if (!fp) {
        fprintf(stderr, "fdopen(%d, %s) failed: %m\n", pipe[0], mode);
        exit(EXIT_FAILURE);
    }

    // 读取数据
    char buf[4096];

    // 读取标准输出
    try {
        while (fgets(buf, sizeof(buf), fp))
            parse_dependency(deps, buf);
    } catch (const std::exception & e) {
        fprintf(stderr, "parse dependency failed: %s\n", e.what());
        exit(EXIT_FAILURE);
    }

    // wait子进程
    int status;
    waitpid(pid, &status, 0);

    // 关闭文件指针
    fclose(fp);

    // 关闭管道
    close(pipe[0]);
}

static void get_dependencies(std::set<std::string> & deps, const char * name)
{
    assert(name);

    // 创建管道
    int pipe[2];
    open_pipe(pipe);

    // 创建子进程
    auto const pid = fork();
    switch (pid) {
    case -1:
        perror("fork");
        exit(EXIT_FAILURE);
    case 0:
        child_run(pipe, name);
    default:
        parent_run(deps, pipe, pid);
    }
}

inline void print_dependencies(const std::set<std::string> & deps)
{
    for (const auto & dep : deps)
        std::cout << dep << std::endl;
}

/**
 * @brief 为方件创建目录
 *
 * @param dirfd 目录文件描述符，子目录在此目录下创建
 * @param path  文件路径
 * @return 返回文件名开始的位置
 */
static const char * create_directory_recursive_for_file(int dirfd, const char * path)
{
    assert(path);

    // 查找最后一个'/'字符
    auto len = strlen(path);
    while (len > 0 && path[len - 1] != '/') --len;
    if (0 == len) return path;

    // 在栈上分配内存
    auto const buf = static_cast<char *>(alloca(len + 1));
    auto cur = buf;

    // 递归创建目录
    for (auto p = path, end = p + len; p < end; ++p) {

        if (__glibc_likely(*p != '/'))
            *cur++ = *p;
        else {
            *cur = 0;
            auto constexpr mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
            if (mkdirat(dirfd, buf, mode) < 0 && errno != EEXIST) {
                fprintf(stderr, "mkdir(\"%s\", %d) failed: %m\n", buf, mode);
                exit(EXIT_FAILURE);
            }

            *cur++ = '/';
        }
    }

    return path + len;
}

/**
 * @brief 打开目录，如果目录不存在则创建
 *
 * @param path 目录路径
 * @return int 目录文件描述符
 */
static int open_directory(const char * path)
{
    assert(path);

    // 为目录路径添加'/'
    auto const len = strlen(path);
    auto const buf = static_cast<char *>(alloca(len + 2));
    memcpy(buf, path, len);
    if (buf[len - 1] == '/') {
        buf[len] = '\0';
    } else {
        buf[len] = '/';
        buf[len + 1] = '\0';
    }

    // 创建目录
    create_directory_recursive_for_file(AT_FDCWD, buf);

    // 打开目录
    auto const flag = O_DIRECTORY | O_RDONLY;
    auto const dirfd = open(buf, flag);
    if (dirfd < 0) {
        fprintf(stderr, "open(\"%s\", %d) failed: %m\n", buf, flag);
        exit(EXIT_FAILURE);
    }

    return dirfd;
}

/**
 * @brief 复制文件
 * 
 * @param dirfd 目标根目录文件描述符
 * @param src   源文件路径，必须是绝对路径
 */
static void copy_file(int dirfd, const char * src)
{
    assert(src && src[0] == '/');

    // 打开源文件
    auto const srcfd = open(src, O_RDONLY);
    if (srcfd < 0) {
        fprintf(stderr, "open(\"%s\", %d) failed: %m\n", src, O_RDONLY);
        exit(EXIT_FAILURE);
    }

    // 获取目标文件属性
    struct stat stat {};
    if (fstat(srcfd, &stat) < 0) {
        fprintf(stderr, "fstat(%d, %p) failed: %m\n", srcfd, &stat);
        exit(EXIT_FAILURE);
    }

    // 创建目标文件的目录结构
    auto const dst = src + 1;
    create_directory_recursive_for_file(dirfd, dst);

    // 创建目标文件
    auto constexpr flag = O_WRONLY | O_CREAT | O_TRUNC;
    auto const mode = stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    auto const dstfd = openat(dirfd, dst, flag, mode);
    if (dstfd < 0) {
        fprintf(stderr, "openat(%d, \"%s\", %d, %d) failed: %m\n", dirfd, dst, flag, mode);
        exit(EXIT_FAILURE);
    }

    // 读取源文件内容
    char buf[4096];
    ssize_t len;
    while ((len = read(srcfd, buf, sizeof(buf))) > 0) {
        if (write(dstfd, buf, len) < 0) {
            fprintf(stderr, "write(%d, %p, %ld) failed: %m\n", dstfd, buf, len);
            exit(EXIT_FAILURE);
        }
    }

    if (len < 0) {
        fprintf(stderr, "read(%d, %p, %lu) failed: %m\n", srcfd, buf, sizeof(buf));
        exit(EXIT_FAILURE);
    }

    // 关闭文件
    close(srcfd);
    close(dstfd);
}

static void copy_symlink(int dirfd, const char * src)
{
    assert(src && src[0] == '/');

    // 获取源链接文件内容长度
    struct stat stat { };
    if (lstat(src, &stat) < 0) {
        fprintf(stderr, "lstat(\"%s\", %p) failed: %m\n", src, &stat);
        exit(EXIT_FAILURE);
    }

    // 读取源链接文件的链接内容
    auto const size = stat.st_size;
    auto const target = static_cast<char *>(alloca(size + 1));
    auto const len = readlink(src, target, size);
    if (len < 0) {
        fprintf(stderr, "readlink(\"%s\", %p, %lu) failed: %m\n", src, target, size);
        exit(EXIT_FAILURE);
    }

    target[len] = 0;

    // 创建目标链接文件的目录结构
    auto const filename = create_directory_recursive_for_file(dirfd, src + 1);

    // 在dirfd下面创建dst链接，链接到与src同名的文件
    auto const dst = src + 1;
    if (symlinkat(target, dirfd, dst) < 0) {
        fprintf(stderr, "symlinkat(\"%s\", %d,\"%s\") failed: %m\n", target, dirfd, dst);
        exit(EXIT_FAILURE);
    }

    // 目标可以软链接或者普通文件，因此递归复制链接目标
    if ('/' == target[0])
        copy_dependency(dirfd, target);
    else {
        // 目标是相对路径，需要转换为绝对路径
        auto const dir_length = filename - src;
        auto const target_abs_path_len = dir_length + len;
        auto const target_abs_path_buf =
            static_cast<char *>(alloca(target_abs_path_len + 1));
        memcpy(target_abs_path_buf, src, dir_length);
        memcpy(target_abs_path_buf + dir_length, target, len);
        target_abs_path_buf[target_abs_path_len] = 0;

        // 复制目标文件
        copy_dependency(dirfd, target_abs_path_buf);
    }
}

/**
 * @brief 复制依赖文件到目标目录
 *
 * @param dirfd 目标目录文件描述符
 * @param path  依赖文件路径
 */
static void copy_dependency(int dirfd, const char * path)
{
    assert(path && path[0] == '/');

    // 获取源文件属性
    struct stat buf {};
    if (fstatat(AT_FDCWD, path, &buf, AT_SYMLINK_NOFOLLOW) < 0) {
        fprintf(stderr, "fstatat(%d, \"%s\", %p, %s) failed: %m\n", AT_FDCWD, path, &buf, "AT_SYMLINK_NOFOLLOW");
        exit(EXIT_FAILURE);
    }

    if (S_ISLNK(buf.st_mode)) {
        copy_symlink(dirfd, path);
    } else if (S_ISREG(buf.st_mode)) {
        copy_file(dirfd, path);
    } else {
        fprintf(stderr, "unsupported file type: %s\n", path);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    // 检查参数
    if (argc < 3)
        usage(argv[0], EXIT_FAILURE);

    // 用于存储依赖库路径
    std::set<std::string> deps;

    // 获取依赖库
    for (int i = 2; i < argc; ++i) {
        // 搜索可执行文件
        auto bin_path = search_env_path(argv[i]);
        if (bin_path.empty()) {
            fprintf(stderr, "can not find %s in PATH\n", argv[i]);
            continue;
        }

        // 将可执行文件路径添加到表中
        auto const [it, ok] = deps.insert(std::move(bin_path));
        if (!ok) continue;

        // 获取依赖库
        get_dependencies(deps, it->c_str());
    }

    // 打开目录
    auto const dirfd = open_directory(argv[1]);

    // 复制依赖库
    for (const auto & dep : deps)
        copy_dependency(dirfd, dep.data());

    // 关闭目录
    close(dirfd);
}