#pragma once
#include <cstdint>
#include <vector>
#include <memory>

namespace hook
{
	//
	// abstract_hook
	//
	class abstract_hook
	{
	public:
		~abstract_hook() noexcept;
		void unhook();

		template <typename T>
		T get_ofunc()
		{
			return reinterpret_cast<T>(_ofunc);
		}
	protected:
		class func
		{
		public:
			explicit func(std::uint64_t* addr);
			void set_addr(std::uint64_t addr);
			std::uint64_t get_addr() const;
		private:
			void set_page_prot(bool enable);
			std::uint64_t* _addr;
			std::uint32_t _prot;
		};

		std::unique_ptr<func> _func;
		std::uint64_t _ofunc;
	};

	//
	// iat_func
	// swaps a import address table function pointer
	//
	class iat_func : public abstract_hook
	{
	public:
		explicit iat_func(std::string_view func_name, std::uint64_t hook_addr, HMODULE module = 0);
	private:
		std::uint64_t* find_func(std::string_view name, HMODULE module) const;
	};

	//
	// vmt_func
	// swaps a virtual method table function pointer
	//
	class vmt_func : public abstract_hook
	{
	public:
		explicit vmt_func(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_idx);
	};

	//
	// vmt_swap
	// swaps the entire virtual method table
	//
	class vmt_swap : public abstract_hook
	{
	public:
		explicit vmt_swap();
	};

	//
	// hook_manager
	//
	class hook_manager
	{
	public:
		template <typename hook_type_t, typename ...args_t>
		auto register_hook(args_t&&... args)
		{
			auto hook = std::make_shared<hook_type_t>(std::forward<args_t>(args)...);
			_hooks.emplace_back(hook);
			return hook;
		}
		void unhook_all();
	private:
		std::vector<std::shared_ptr<abstract_hook>> _hooks;
	};
}