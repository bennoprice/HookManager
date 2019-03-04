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
		virtual void unhook() = 0;

		template <typename T>
		T get_ofunc()
		{
			return reinterpret_cast<T>(_ofunc);
		}
	};

	class vmt_hook : public abstract_hook
	{
	private:
		class vfunc
		{
		private:
			const std::size_t _size = sizeof(std::uint64_t);
			std::uint64_t* _addr;
			DWORD _prot;
		public:
			explicit vfunc(std::uint64_t* addr);
			void set_page_prot(bool enable);
			auto& get_addr() const;
		};

		std::unique_ptr<vfunc> _vfunc;
	public:
		explicit vmt_hook(std::uint64_t target_class, std::uint64_t hook_addr, std::uint64_t vtable_index);
		void unhook() override;
	};

	class hook_manager
	{
	private:
		std::vector<std::shared_ptr<abstract_hook>> _hooks;
	public:
		template <typename hook_type_t, typename ...args_t>
		auto register_hook(args_t&&... args)
		{
			auto hook = std::make_shared<hook_type_t>(std::forward<args_t>(args)...);
			_hooks.emplace_back(hook);
			return hook;
		}
		void unhook_all();
	};
}