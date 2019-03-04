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
	void abstract_hook::unhook()
	{ }

	//
	// vmt hook
	//
	vmt_hook::vfunc::vfunc(std::uint64_t* addr)
		: _addr(addr)
	{ }
	void vmt_hook::vfunc::set_page_prot(bool enable)
	{
		if (enable && _prot)
			::VirtualProtect(_addr, _size, _prot, nullptr);
		else
			::VirtualProtect(_addr, _size, PAGE_EXECUTE_READWRITE, &_prot);
	}
	auto& vmt_hook::vfunc::get_addr() const
	{
		return *_addr;
	}

	vmt_hook::vmt_hook(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_index)
	{
		auto vtable = **reinterpret_cast<std::uint64_t***>(target_class);
		_vfunc = std::make_unique<vfunc>(&vtable[vtable_index]);
		_ofunc = _vfunc->get_addr();

		_vfunc->set_page_prot(false);
		_vfunc->get_addr() = hook_addr;
		_vfunc->set_page_prot(true);
	}
	void vmt_hook::unhook()
	{
		_vfunc->set_page_prot(false);
		_vfunc->get_addr() = _ofunc;
		_vfunc->set_page_prot(true);
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