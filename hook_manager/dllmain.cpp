#include <Windows.h>
#include <iostream>
#include <cstdint>
#include "hook_manager.hpp"

// todo:
// allow lambdas for hook functions
// make protection raii

namespace placed_hooks
{
	std::shared_ptr<hook::iat_func> iat_hook;
	using terminate_proc_t = bool(*)(HANDLE proc, std::uint32_t exit_code);

	bool h_terminate_proc(HANDLE proc, std::uint32_t exit_code)
	{
		MessageBox(0, L"dont try to close me", L"hooked", 0);
		return true;
	}

	std::shared_ptr<hook::vmt_func> vmt_hook;
	using func_t = void(*)();

	void h_func()
	{
		std::cout << "this plane has been hijacked!" << std::endl;
		vmt_hook->get_ofunc<func_t>()();
	}
}

void init()
{
	//auto module_base = reinterpret_cast<std::uint64_t>(GetModuleHandle(0));
	auto hook_manager = std::make_unique<hook::hook_manager>();

	placed_hooks::iat_hook = hook_manager->register_hook<hook::iat_func>("TerminateProcess", reinterpret_cast<std::uint64_t>(&placed_hooks::h_terminate_proc), GetModuleHandle(L"kernel32.dll"));
	//placed_hooks::vmt_hook = hook_manager->register_hook<hook::vmt_func>(0x4084effbc8, reinterpret_cast<std::uint64_t>(&placed_hooks::h_func), 0);

	//hook::iat_hook->unhook();
	//hook::vmt_hook->unhook();
	//hook_manager->unhook_all();
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
		init();
	return true;
}