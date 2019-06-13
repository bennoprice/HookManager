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
		auto base = reinterpret_cast<std::uint64_t>(module);

		auto dos_header = PIMAGE_DOS_HEADER(base);
		auto nt_header = PIMAGE_NT_HEADERS(base + dos_header->e_lfanew);

		auto section = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto import_table = PIMAGE_IMPORT_DESCRIPTOR(base + section.VirtualAddress);
		for (; import_table->Name; ++import_table)
		{
			auto entry = PIMAGE_THUNK_DATA64(base + import_table->OriginalFirstThunk);
			for (auto idx = 0u; entry->u1.AddressOfData; idx += sizeof(std::uint64_t), ++entry)
			{
				auto import_by_name = PIMAGE_IMPORT_BY_NAME(base + entry->u1.AddressOfData);
				if (!::strcmp(name.data(), reinterpret_cast<const char*>(import_by_name->Name)))
					return reinterpret_cast<std::uint64_t*>(base + import_table->FirstThunk + idx);
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