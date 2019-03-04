#pragma once
#include <cstdint>
#include <vector>
#include <memory>

namespace hook
{
	class abstract_hook
	{
	protected:
		std::uint64_t _ofunc;
	public:
		~abstract_hook();
		virtual void unhook() const = 0;

		template <typename T>
		T get_ofunc()
		{
			return reinterpret_cast<T>(_ofunc);
		}
	};

	class vmt_hook : public abstract_hook
	{
	private:
		std::uint32_t _page_prot;
		std::uint64_t* _vtable_func_addr;
		void set_page_protection(std::uint64_t address, std::size_t size, bool enable);
	public:
		vmt_hook(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_index);
		void unhook() const override;
	};

	class hook_manager
	{
	private:
		std::vector<std::shared_ptr<abstract_hook>> _hooks;
	public:
		template <typename hook_type_t, typename ...args_t>
		std::shared_ptr<abstract_hook> register_hook(args_t&&... args)
		{
			auto hook = std::make_shared<hook_type_t>(std::forward<args_t>(args)...);
			_hooks.emplace_back(hook);
			return hook;
		}
		void unhook_all();
	};
}