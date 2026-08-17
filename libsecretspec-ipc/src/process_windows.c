#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include "internal.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct ss_process {
    HANDLE process;
    HANDLE input;
    HANDLE output;
    HANDLE error;
    bool reaped;
};

static wchar_t *utf8_to_wide(const char *text) {
    int count;
    wchar_t *wide;
    if (text == NULL) return NULL;
    count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (count <= 0) return NULL;
    wide = (wchar_t *)calloc((size_t)count, sizeof(wchar_t));
    if (wide == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, count) != count) {
        free(wide);
        return NULL;
    }
    return wide;
}

static size_t quoted_size(const wchar_t *argument) {
    size_t size = 2;
    size_t slashes = 0;
    const wchar_t *cursor;
    for (cursor = argument; *cursor != L'\0'; cursor++) {
        if (*cursor == L'\\') {
            slashes++;
        } else if (*cursor == L'\"') {
            size += slashes * 2 + 2;
            slashes = 0;
        } else {
            size += slashes + 1;
            slashes = 0;
        }
    }
    return size + slashes * 2 + 1;
}

static wchar_t *append_quoted(wchar_t *output, const wchar_t *argument) {
    size_t slashes = 0;
    const wchar_t *cursor;
    *output++ = L'\"';
    for (cursor = argument; *cursor != L'\0'; cursor++) {
        if (*cursor == L'\\') {
            slashes++;
            continue;
        }
        if (*cursor == L'\"') {
            while (slashes-- != 0) { *output++ = L'\\'; *output++ = L'\\'; }
            *output++ = L'\\';
            *output++ = L'\"';
        } else {
            while (slashes-- != 0) *output++ = L'\\';
            *output++ = *cursor;
        }
        slashes = 0;
    }
    while (slashes-- != 0) { *output++ = L'\\'; *output++ = L'\\'; }
    *output++ = L'\"';
    return output;
}

static wchar_t *build_command_line(const ss_launch *launch) {
    wchar_t **arguments;
    wchar_t *line;
    wchar_t *cursor;
    size_t count = launch->argument_count + 1;
    size_t total = 1;
    size_t index;
    arguments = (wchar_t **)calloc(count, sizeof(wchar_t *));
    if (arguments == NULL) return NULL;
    arguments[0] = utf8_to_wide(launch->executable);
    for (index = 0; index < launch->argument_count; index++) {
        arguments[index + 1] = utf8_to_wide(launch->arguments[index]);
    }
    for (index = 0; index < count; index++) {
        if (arguments[index] == NULL) goto failed;
        total += quoted_size(arguments[index]) + 1;
    }
    line = (wchar_t *)calloc(total, sizeof(wchar_t));
    if (line == NULL) goto failed;
    cursor = line;
    for (index = 0; index < count; index++) {
        if (index != 0) *cursor++ = L' ';
        cursor = append_quoted(cursor, arguments[index]);
        free(arguments[index]);
    }
    *cursor = L'\0';
    free(arguments);
    return line;
failed:
    for (index = 0; index < count; index++) free(arguments[index]);
    free(arguments);
    return NULL;
}

static size_t wide_key_size(const wchar_t *entry) {
    const wchar_t *equals = wcschr(entry, L'=');
    return equals == NULL ? wcslen(entry) : (size_t)(equals - entry);
}

static bool overridden(const wchar_t *entry, wchar_t **overrides, size_t count) {
    size_t entry_size = wide_key_size(entry);
    size_t index;
    for (index = 0; index < count; index++) {
        size_t other_size = wide_key_size(overrides[index]);
        if (entry_size == other_size && _wcsnicmp(entry, overrides[index], entry_size) == 0) return true;
    }
    return false;
}

static wchar_t *build_environment(const ss_launch *launch) {
    wchar_t **overrides;
    wchar_t *inherited = NULL;
    wchar_t *block;
    wchar_t *cursor;
    size_t total = 2;
    size_t index;
    overrides = (wchar_t **)calloc(launch->environment_count, sizeof(wchar_t *));
    if (launch->environment_count != 0 && overrides == NULL) return NULL;
    for (index = 0; index < launch->environment_count; index++) {
        overrides[index] = utf8_to_wide(launch->environment[index]);
        if (overrides[index] == NULL) goto failed;
        total += wcslen(overrides[index]) + 1;
    }
    if (launch->inherit_environment) {
        wchar_t *entry;
        inherited = GetEnvironmentStringsW();
        if (inherited == NULL) goto failed;
        for (entry = inherited; *entry != L'\0'; entry += wcslen(entry) + 1) {
            if (!overridden(entry, overrides, launch->environment_count)) total += wcslen(entry) + 1;
        }
    }
    block = (wchar_t *)calloc(total, sizeof(wchar_t));
    if (block == NULL) goto failed;
    cursor = block;
    if (inherited != NULL) {
        wchar_t *entry;
        for (entry = inherited; *entry != L'\0'; entry += wcslen(entry) + 1) {
            size_t size;
            if (overridden(entry, overrides, launch->environment_count)) continue;
            size = wcslen(entry) + 1;
            memcpy(cursor, entry, size * sizeof(wchar_t));
            cursor += size;
        }
    }
    for (index = 0; index < launch->environment_count; index++) {
        size_t size = wcslen(overrides[index]) + 1;
        memcpy(cursor, overrides[index], size * sizeof(wchar_t));
        cursor += size;
        free(overrides[index]);
    }
    *cursor++ = L'\0';
    *cursor = L'\0';
    free(overrides);
    if (inherited != NULL) FreeEnvironmentStringsW(inherited);
    return block;
failed:
    for (index = 0; index < launch->environment_count; index++) free(overrides[index]);
    free(overrides);
    if (inherited != NULL) FreeEnvironmentStringsW(inherited);
    return NULL;
}

secretspec_ipc_status ss_process_spawn(const ss_launch *launch, ss_process **process_out) {
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    HANDLE child_input = NULL, parent_input = NULL;
    HANDLE parent_output = NULL, child_output = NULL;
    HANDLE parent_error = NULL, child_error = NULL;
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION information;
    SIZE_T attribute_size = 0;
    HANDLE inherited_handles[3];
    bool attribute_ready = false;
    wchar_t *application = NULL;
    wchar_t *command_line = NULL;
    wchar_t *environment = NULL;
    ss_process *process = NULL;
    BOOL created;
    if (process_out == NULL || launch == NULL) return SECRETSPEC_IPC_INVALID_ARGUMENT;
    *process_out = NULL;
    if (!CreatePipe(&child_input, &parent_input, &security, 0) ||
        !CreatePipe(&parent_output, &child_output, &security, 0) ||
        !CreatePipe(&parent_error, &child_error, &security, 0)) goto failed;
    if (!SetHandleInformation(parent_input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(parent_output, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(parent_error, HANDLE_FLAG_INHERIT, 0)) goto failed;
    command_line = build_command_line(launch);
    environment = build_environment(launch);
    if (!launch->discover) application = utf8_to_wide(launch->executable);
    if (command_line == NULL || environment == NULL || (!launch->discover && application == NULL)) goto failed;
    ZeroMemory(&startup, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_input;
    startup.StartupInfo.hStdOutput = child_output;
    startup.StartupInfo.hStdError = child_error;
    inherited_handles[0] = child_input;
    inherited_handles[1] = child_output;
    inherited_handles[2] = child_error;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_size);
    if (startup.lpAttributeList == NULL) goto failed;
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size))
        goto failed;
    attribute_ready = true;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherited_handles, sizeof(inherited_handles),
                                   NULL, NULL)) goto failed;
    ZeroMemory(&information, sizeof(information));
    created = CreateProcessW(application, command_line, NULL, NULL, TRUE,
                             CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW |
                                 EXTENDED_STARTUPINFO_PRESENT,
                             environment, NULL, &startup.StartupInfo, &information);
    if (!created) goto failed;
    CloseHandle(information.hThread);
    CloseHandle(child_input); child_input = NULL;
    CloseHandle(child_output); child_output = NULL;
    CloseHandle(child_error); child_error = NULL;
    process = (ss_process *)calloc(1, sizeof(*process));
    if (process == NULL) {
        TerminateProcess(information.hProcess, 1);
        CloseHandle(information.hProcess);
        goto failed;
    }
    process->process = information.hProcess;
    process->input = parent_input;
    process->output = parent_output;
    process->error = parent_error;
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    free(application); free(command_line); free(environment);
    *process_out = process;
    return SECRETSPEC_IPC_OK;
failed:
    if (startup.lpAttributeList != NULL) {
        if (attribute_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
        free(startup.lpAttributeList);
    }
    if (child_input) CloseHandle(child_input);
    if (parent_input) CloseHandle(parent_input);
    if (parent_output) CloseHandle(parent_output);
    if (child_output) CloseHandle(child_output);
    if (parent_error) CloseHandle(parent_error);
    if (child_error) CloseHandle(child_error);
    free(application); free(command_line); free(environment);
    return SECRETSPEC_IPC_IO;
}

static ptrdiff_t read_handle(HANDLE handle, unsigned char *buffer, size_t size) {
    DWORD read_count = 0;
    DWORD requested = size > MAXDWORD ? MAXDWORD : (DWORD)size;
    if (!ReadFile(handle, buffer, requested, &read_count, NULL)) {
        return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
    }
    return (ptrdiff_t)read_count;
}

ptrdiff_t ss_process_read_stdout(ss_process *process, unsigned char *buffer, size_t size) {
    return process == NULL ? -1 : read_handle(process->output, buffer, size);
}

ptrdiff_t ss_process_read_stderr(ss_process *process, unsigned char *buffer, size_t size) {
    return process == NULL ? -1 : read_handle(process->error, buffer, size);
}

bool ss_process_write_stdin(ss_process *process, const unsigned char *buffer, size_t size) {
    size_t written = 0;
    while (process != NULL && written < size) {
        DWORD count = 0;
        DWORD requested = size - written > MAXDWORD ? MAXDWORD : (DWORD)(size - written);
        if (!WriteFile(process->input, buffer + written, requested, &count, NULL) || count == 0) return false;
        written += count;
    }
    return process != NULL;
}

void ss_process_close_stdin(ss_process *process) {
    if (process != NULL && process->input != NULL) {
        CloseHandle(process->input);
        process->input = NULL;
    }
}

void ss_process_interrupt_io(ss_process *process) {
    (void)process;
}

bool ss_process_wait(ss_process *process, uint64_t deadline_unix_ms) {
    uint64_t now;
    DWORD timeout;
    DWORD result;
    if (process == NULL || process->reaped) return true;
    now = ss_now_unix_ms();
    timeout = deadline_unix_ms <= now ? 0 :
              deadline_unix_ms - now > MAXDWORD ? MAXDWORD : (DWORD)(deadline_unix_ms - now);
    result = WaitForSingleObject(process->process, timeout);
    if (result == WAIT_OBJECT_0) {
        process->reaped = true;
        return true;
    }
    return false;
}

void ss_process_terminate(ss_process *process) {
    if (process == NULL || process->reaped) return;
    (void)TerminateProcess(process->process, 1);
    (void)WaitForSingleObject(process->process, 1000);
    process->reaped = true;
}

void ss_process_free(ss_process *process) {
    if (process == NULL) return;
    ss_process_close_stdin(process);
    ss_process_terminate(process);
    if (process->output) CloseHandle(process->output);
    if (process->error) CloseHandle(process->error);
    if (process->process) CloseHandle(process->process);
    free(process);
}

#endif
