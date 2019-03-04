#include <Windows.h>
#include "hook_manager.hpp"

namespace hook
{
	//
	// abstract hook
	//
	abstract_hook::~abstract_hook()
	{
		unhook();
	}
	void abstract_hook::unhook() const
	{ }

	//
	// vmt hook
	//
	vmt_hook::vmt_hook(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_index)
	{
		auto vtable = **reinterpret_cast<std::uint64_t***>(target_class);
		_vtable_func_addr = &vtable[vtable_index];
		_ofunc = *_vtable_func_addr;

		set_page_protection(reinterpret_cast<std::uint64_t>(_vtable_func_addr), sizeof(std::uint64_t), false);
		*_vtable_func_addr = hook_addr;
		set_page_protection(reinterpret_cast<std::uint64_t>(_vtable_func_addr), sizeof(std::uint64_t), true);
	}
	void vmt_hook::unhook() const
	{
		*_vtable_func_addr = _ofunc;
	}
	void vmt_hook::set_page_protection(std::uint64_t address, std::size_t size, bool enable)
	{
		if (enable && _page_prot)
			::VirtualProtect(reinterpret_cast<void*>(address), size, _page_prot, nullptr);
		else
			::VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, reinterpret_cast<DWORD*>(&_page_prot));
	}

	//
	// hook manager
	//
	void hook_manager::unhook_all()
	{
		for (auto &hook : _hooks)
			hook->unhook();
		_hooks.clear();
	}
}