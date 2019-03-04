#include <Windows.h>
#include <iostream>
#include <cstdint>
#include "hook_manager.hpp"

namespace hook
{
	std::shared_ptr<hook::abstract_hook> func_hook;
	using func_t = void(*)();

	void h_func()
	{
		std::cout << "this plane has been hijacked!" << std::endl;
		func_hook->get_ofunc<func_t>()();
	}
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		auto module_base = reinterpret_cast<std::uint64_t>(GetModuleHandle(0));
		auto hook_manager = std::make_unique<hook::hook_manager>();

	 	hook::func_hook = hook_manager->register_hook<hook::vmt_hook>(0xd6b7affa38, reinterpret_cast<std::uint64_t>(&hook::h_func), 0);

		//hook::func_hook->unhook();
		//hook_manager->unhook_all();
	}
	return true;
}