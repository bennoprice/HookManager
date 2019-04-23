#include <Windows.h>
#include "hook_manager.hpp"

namespace hook
{
	//
	// abstract_hook
	//
	abstract_hook::~abstract_hook()
	{
		unhook();
	}

	void abstract_hook::unhook()
	{
		_func->set_addr(_ofunc);
	}

	abstract_hook::func::func(std::uint64_t* addr)
		: _addr(addr)
	{ }

	void abstract_hook::func::set_page_prot(bool enable)
	{
		if (enable && _prot)
		{
			DWORD old_prot;
			::VirtualProtect(_addr, sizeof(std::uint64_t), _prot, &old_prot);
		}
		else
			::VirtualProtect(_addr, sizeof(std::uint64_t), PAGE_READWRITE, reinterpret_cast<DWORD*>(&_prot));
	}

	void abstract_hook::func::set_addr(std::uint64_t addr)
	{
		set_page_prot(false);
		*_addr = addr;
		set_page_prot(true);
	}

	std::uint64_t abstract_hook::func::get_addr() const
	{
		return *_addr;
	}

	//
	// iat_hook
	//
	iat_func::iat_func(std::string_view func_name, std::uint64_t hook_addr, HMODULE module)
	{
		_func = std::make_unique<func>(find_func(func_name, module));
		_ofunc = _func->get_addr();
		_func->set_addr(hook_addr);
	}

	std::uint64_t* iat_func::find_func(std::string_view name, HMODULE module) const
	{
		if (!module)
			module = GetModuleHandle(0);

		auto dos_header = PIMAGE_DOS_HEADER(module);
		auto nt_header = PIMAGE_NT_HEADERS(reinterpret_cast<std::uint8_t*>(module) + dos_header->e_lfanew);
		auto import_desc_base = PIMAGE_IMPORT_DESCRIPTOR(reinterpret_cast<std::uint8_t*>(dos_header) + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (auto *import_desc = import_desc_base; import_desc->Name != 0; ++import_desc)
		{
			for (auto func_idx = 0u; *(func_idx + reinterpret_cast<void**>(import_desc->FirstThunk + reinterpret_cast<std::uint64_t>(module))) != nullptr; ++func_idx)
			{
				char* func_name = reinterpret_cast<char*>(*(func_idx + reinterpret_cast<std::uint64_t*>(import_desc->OriginalFirstThunk + reinterpret_cast<std::uint64_t>(module))) + reinterpret_cast<std::uint64_t>(module) + 0x2);
				if (reinterpret_cast<intptr_t>(func_name) >= 0)
					if (!::strcmp(name.data(), func_name))
						return func_idx + reinterpret_cast<std::uint64_t*>(import_desc->FirstThunk + reinterpret_cast<std::uint64_t>(module));
			}
		}
		return nullptr;
	}

	//
	// vmt_hook
	//
	vmt_func::vmt_func(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_idx)
	{
		auto vtable = **reinterpret_cast<std::uint64_t***>(target_class);
		_func = std::make_unique<func>(&vtable[vtable_idx]);
		_ofunc = _func->get_addr();
		_func->set_addr(hook_addr);
	}

	//
	// hook_manager
	//
	void hook_manager::unhook_all()
	{
		for (auto &hook : _hooks)
			hook->unhook();
		_hooks.clear();
	}
}