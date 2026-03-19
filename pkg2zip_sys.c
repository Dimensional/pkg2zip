#include "pkg2zip_sys.h"
#include "pkg2zip_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void sys_remove_tree_real_w(const WCHAR* path)
{
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        {
            return;
        }
        sys_error("ERROR: cannot inspect path for removal\n");
    }

    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        if (!DeleteFileW(path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        {
            sys_error("ERROR: cannot remove file\n");
        }
        return;
    }

    {
        WCHAR pattern[MAX_PATH];
        WIN32_FIND_DATAW entry;
        HANDLE find;

        swprintf(pattern, MAX_PATH, L"%ls\\*", path);
        find = FindFirstFileW(pattern, &entry);
        if (find != INVALID_HANDLE_VALUE)
        {
            do
            {
                WCHAR child[MAX_PATH];

                if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0)
                {
                    continue;
                }

                swprintf(child, MAX_PATH, L"%ls\\%ls", path, entry.cFileName);
                sys_remove_tree_real_w(child);
            }
            while (FindNextFileW(find, &entry) != 0);

            FindClose(find);
        }
    }

    if (!RemoveDirectoryW(path) && GetLastError() != ERROR_PATH_NOT_FOUND)
    {
        sys_error("ERROR: cannot remove folder\n");
    }
}

static HANDLE gStdout;
static int gStdoutRedirected;
static UINT gOldCP;

void sys_output_init(void)
{
    gOldCP = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
    gStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD mode;
    gStdoutRedirected = !GetConsoleMode(gStdout, &mode);
}

void sys_output_done(void)
{
    SetConsoleOutputCP(gOldCP);
}

void sys_output(const char* msg, ...)
{
    char buffer[1024];

    va_list arg;
    va_start(arg, msg);
    vsnprintf(buffer, sizeof(buffer), msg, arg);
    va_end(arg);

    if (!gStdoutRedirected)
    {
        WCHAR wbuffer[sizeof(buffer)];
        int wcount = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, sizeof(buffer));

        DWORD written;
        WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), wbuffer, wcount - 1, &written, NULL);
        return;
    }
    fputs(buffer, stdout);
}

void sys_error(const char* msg, ...)
{
    char buffer[1024];

    va_list arg;
    va_start(arg, msg);
    vsnprintf(buffer, sizeof(buffer), msg, arg);
    va_end(arg);

    DWORD mode;
    if (GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode))
    {
        WCHAR wbuffer[sizeof(buffer)];
        int wcount = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, sizeof(buffer));

        DWORD written;
        WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), wbuffer, wcount - 1, &written, NULL);
    }
    else
    {
        fputs(buffer, stderr);
    }

    SetConsoleOutputCP(gOldCP);
    exit(EXIT_FAILURE);
}

static void sys_mkdir_real(const char* path)
{
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);

    if (CreateDirectoryW(wpath, NULL) == 0)
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            sys_error("ERROR: cannot create '%s' folder\n", path);
        }
    }
}

sys_file sys_open(const char* fname, uint64_t* size)
{
    WCHAR path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, fname, -1, path, MAX_PATH);

    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        sys_error("ERROR: cannot open '%s' file\n", fname);
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(handle, &sz))
    {
        sys_error("ERROR: cannot get size of '%s' file\n", fname);
    }
    *size = sz.QuadPart;

    return handle;
}

sys_file sys_create(const char* fname)
{
    WCHAR path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, fname, -1, path, MAX_PATH);

    HANDLE handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        sys_error("ERROR:1: cannot create '%s' file\n", fname);
    }

    return handle;
}

void sys_close(sys_file file)
{
    if (!CloseHandle(file))
    {
        sys_error("ERROR: failed to close file\n");
    }
}

void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size)
{
    DWORD read;
    OVERLAPPED ov;
    ov.hEvent = NULL;
    ov.Offset = (uint32_t)offset;
    ov.OffsetHigh = (uint32_t)(offset >> 32);
    if (!ReadFile(file, buffer, size, &read, &ov) || read != size)
    {
        sys_error("ERROR: failed to read %u bytes from file\n", size);
    }
}

void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size)
{
    DWORD written;
    OVERLAPPED ov;
    ov.hEvent = NULL;
    ov.Offset = (uint32_t)offset;
    ov.OffsetHigh = (uint32_t)(offset >> 32);
    if (!WriteFile(file, buffer, size, &written, &ov) || written != size)
    {
        sys_error("ERROR: failed to write %u bytes to file\n", size);
    }
}

#else

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static void sys_remove_tree_real(const char* path)
{
    struct stat st;

    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT)
        {
            return;
        }
        sys_error("ERROR: cannot inspect '%s' for removal\n", path);
    }

    if (!S_ISDIR(st.st_mode))
    {
        if (unlink(path) != 0 && errno != ENOENT)
        {
            sys_error("ERROR: cannot remove '%s' file\n", path);
        }
        return;
    }

    {
        DIR* dir = opendir(path);
        struct dirent* entry;

        if (dir == NULL)
        {
            sys_error("ERROR: cannot open '%s' folder for removal\n", path);
        }

        while ((entry = readdir(dir)) != NULL)
        {
            char child[1024];

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
            sys_remove_tree_real(child);
        }

        closedir(dir);
    }

    if (rmdir(path) != 0 && errno != ENOENT)
    {
        sys_error("ERROR: cannot remove '%s' folder\n", path);
    }
}

static int gStdoutRedirected;

void sys_output_init(void)
{
    gStdoutRedirected = !isatty(STDOUT_FILENO);
}

void sys_output_done(void)
{
}

void sys_output(const char* msg, ...)
{
    va_list arg;
    va_start(arg, msg);
    vfprintf(stdout, msg, arg);
    va_end(arg);
}

void sys_error(const char* msg, ...)
{
    va_list arg;
    va_start(arg, msg);
    vfprintf(stderr, msg, arg);
    va_end(arg);

    exit(EXIT_FAILURE);
}

static void sys_mkdir_real(const char* path)
{
    if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
    {
        if (errno != EEXIST)
        {
            sys_error("ERROR: cannot create '%s' folder\n", path);
        }
    }
}

sys_file sys_open(const char* fname, uint64_t* size)
{
    int fd = open(fname, O_RDONLY);
    if (fd < 0)
    {
        sys_error("ERROR: cannot open '%s' file\n", fname);
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        sys_error("ERROR: cannot get size of '%s' file\n", fname);
    }
    *size = st.st_size;

    return (void*)(intptr_t)fd;
}

sys_file sys_create(const char* fname)
{
    int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        sys_error("ERROR:2: cannot create '%s' file\n", fname);
    }

    return (void*)(intptr_t)fd;
}

void sys_close(sys_file file)
{
    if (close((int)(intptr_t)file) != 0)
    {
        sys_error("ERROR: failed to close file\n");
    }
}

void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size)
{
    ssize_t read = pread((int)(intptr_t)file, buffer, size, offset);
    if (read < 0 || read != (ssize_t)size)
    {
        sys_error("ERROR: failed to read %u bytes from file\n", size);
    }
}

void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size)
{
    ssize_t wrote = pwrite((int)(intptr_t)file, buffer, size, offset);
    if (wrote < 0 || wrote != (ssize_t)size)
    {
        sys_error("ERROR: failed to read %u bytes from file\n", size);
    }
}

#endif

void sys_mkdir(const char* path)
{
    char* last = strrchr(path, '/');
    if (last)
    {
        *last = 0;
        sys_mkdir(path);
        *last = '/';
    }
    sys_mkdir_real(path);
}

void* sys_realloc(void* ptr, size_t size)
{
    void* result = NULL;
    if (!ptr && size)
    {
        result = malloc(size);
    }
    else if (ptr && !size)
    {
        free(ptr);
        return NULL;
    }
    else if (ptr && size)
    {
        result = realloc(ptr, size);
    }
    else
    {
        sys_error("ERROR: internal error, wrong sys_realloc usage\n");
    }

    if (!result)
    {
        sys_error("ERROR: out of memory\n");
    }

    return result;
}

void sys_vstrncat(char* dst, size_t n, const char* format, ...)
{
    char temp[1024];

    va_list args;
    va_start(args, format);
    vsnprintf(temp, sizeof(temp), format, args);
    va_end(args);

    strncat(dst, temp, n - strlen(dst) - 1);
}

static uint64_t out_size;
static uint32_t out_next;

void sys_output_progress_init(uint64_t size)
{
    out_size = size;
    out_next = 0;
}

void sys_output_progress(uint64_t progress)
{
    if (gStdoutRedirected)
    {
        return;
    }

    uint32_t now = (uint32_t)(progress * 100 / out_size);
    if (now >= out_next)
    {
        sys_output("[*] unpacking... %u%%\r", now);
        out_next = now + 1;
    }
}

int sys_test_dir(const char* const path)
{
    struct stat info;

    int statRC = stat( path, &info );
    if( statRC != 0 )
    {
        if (errno == ENOENT)  { return 0; } 
        if (errno == ENOTDIR) { return 0; } 
        return -1;
    }

    return ( info.st_mode & S_IFDIR ) ? 1 : 0;
}

void sys_remove_tree(const char* path)
{
    if (path == NULL || path[0] == 0)
    {
        return;
    }

#if defined(_WIN32)
    {
        WCHAR wpath[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);
        sys_remove_tree_real_w(wpath);
    }
#else
    sys_remove_tree_real(path);
#endif
}
