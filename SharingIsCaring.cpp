#include <windows.h>
#include <iostream>

BOOL IsAdmin() {
	// Get administrators group sid
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);

	// Check if current token is a member of the administrators group
	BOOL output = FALSE;
	CheckTokenMembership(NULL, adminGroup, &output);

	// Cleanup and return
	FreeSid(adminGroup);
	return output;
}

void PressKey(DWORD vkCode, BOOL keyUp) {
	INPUT input = { };
	input.type = INPUT_KEYBOARD;
	input.ki.wVk = vkCode;
	if (keyUp) {
		input.ki.dwFlags = KEYEVENTF_KEYUP;
	}
	SendInput(1, &input, sizeof(INPUT));
}
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
		KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
		if (pKeyBoard->vkCode == VK_PAUSE) {
			PressKey(VK_SHIFT, FALSE);
			PressKey('B', FALSE);
			PressKey('B', TRUE);
			PressKey('R', FALSE);
			PressKey('R', TRUE);
			PressKey('U', FALSE);
			PressKey('U', TRUE);
			PressKey('H', FALSE);
			PressKey('H', TRUE);
			PressKey(VK_SHIFT, TRUE);
			PressKey(VK_RETURN, FALSE);
			PressKey(VK_RETURN, TRUE);
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}
int main() {
	HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
	MSG msg = {};
	while (GetMessageW(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	UnhookWindowsHookEx(hHook);
	return 0;
}

int main2() {
	if (IsAdmin()) {
		// Get current token
		HANDLE currentToken = INVALID_HANDLE_VALUE;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentToken);
		if (currentToken == INVALID_HANDLE_VALUE) {
			std::cout << "ERROR: " << GetLastError() << std::endl;
			return 1;
		}

		// Duplicate the current token
		HANDLE currentTokenCopy = INVALID_HANDLE_VALUE;
		DuplicateTokenEx(currentToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &currentTokenCopy);
		CloseHandle(currentToken);

		// Create the named pipe
		HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\TokenPipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 0, 0, NULL);

		// Wait for the client to connect
		ConnectNamedPipe(pipe, NULL);

		// Wait for the client to send us their pid
		DWORD otherPid = 0;
		DWORD bytesRead = 0;
		ReadFile(pipe, &otherPid, sizeof(DWORD), &bytesRead, NULL);

		// Open a handle to the other process
		HANDLE otherProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, otherPid);

		// Create a copy of the copy of the current token for the other process
		HANDLE tokenForOtherProcess = INVALID_HANDLE_VALUE;
		DuplicateHandle(GetCurrentProcess(), currentTokenCopy, GetCurrentProcess(), &tokenForOtherProcess, TOKEN_ALL_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);

		// Send the token to the other process
		DWORD bytesWritten = 0;
		WriteFile(pipe, &tokenForOtherProcess, sizeof(HANDLE), &bytesWritten, NULL);

		// Cleanup and return
		CloseHandle(pipe);
		CloseHandle(currentTokenCopy);
		return 0;
	}
	else {
		// Connect to the pipe
		HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\TokenPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

		// Get our pid
		DWORD pid = GetCurrentProcessId();

		// Send our pid to the other process
		DWORD bytesWritten = 0;
		WriteFile(pipe, &pid, sizeof(DWORD), &bytesWritten, NULL);

		HANDLE token = INVALID_HANDLE_VALUE;
		DWORD bytesRead = 0;
		ReadFile(pipe, &token, sizeof(HANDLE), &bytesRead, NULL);

		// Launch cmd with the token we were given
		STARTUPINFOW si = {};
		GetStartupInfoW(&si);
		PROCESS_INFORMATION pi = { };
		LPCWSTR cCmdLine = L"CMD";
		LPWSTR cmdLine = new WCHAR[lstrlenW(cCmdLine) + 1];
		lstrcpyW(cmdLine, cCmdLine);
		CreateProcessAsUserW(token, NULL, cmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

		// Cleanup and return
		RevertToSelf();
		CloseHandle(pipe);
		CloseHandle(token);
		return 0;
	}
}