#include "../include/reader.h"

#include "engineprivate.h"

#include <libfilezilla/local_filesys.hpp>

#include <string.h>

reader_factory::reader_factory(std::wstring const& name)
	: name_(name)
{}

reader_factory_holder::reader_factory_holder(reader_factory_holder const& op)
{
	if (op.impl_) {
		impl_ = op.impl_->clone();
	}
}

reader_factory_holder& reader_factory_holder::operator=(reader_factory_holder const& op)
{
	if (this != &op && op.impl_) {
		impl_ = op.impl_->clone();
	}
	return *this;
}

reader_factory_holder::reader_factory_holder(reader_factory_holder && op) noexcept
{
	impl_ = std::move(op.impl_);
	op.impl_.reset();
}

reader_factory_holder& reader_factory_holder::operator=(reader_factory_holder && op) noexcept
{
	if (this != &op) {
		impl_ = std::move(op.impl_);
		op.impl_.reset();
	}

	return *this;
}

reader_factory_holder::reader_factory_holder(std::unique_ptr<reader_factory> && factory)
	: impl_(std::move(factory))
{
}

reader_factory_holder::reader_factory_holder(std::unique_ptr<reader_factory> const& factory)
	: impl_(factory ? factory->clone() : nullptr)
{
}

reader_factory_holder::reader_factory_holder(reader_factory const& factory)
	: impl_(factory.clone())
{
}

reader_factory_holder& reader_factory_holder::operator=(std::unique_ptr<reader_factory> && factory)
{
	if (impl_ != factory) {
		impl_ = std::move(factory);
	}

	return *this;
}

file_reader_factory::file_reader_factory(std::wstring const& file)
	: reader_factory(file)
{
}

std::unique_ptr<reader_factory> file_reader_factory::clone() const
{
	return std::make_unique<file_reader_factory>(*this);
}

uint64_t file_reader_factory::size() const
{
	if (size_) {
		return *size_;
	}
	auto s = fz::local_filesys::get_size(fz::to_native(name_));
	if (s < 0) {
		size_ = aio_base::nosize;
	}
	else {
		size_ = static_cast<uint64_t>(s);
	}
	return *size_;
}

std::unique_ptr<reader_base> file_reader_factory::open(uint64_t offset, CFileZillaEnginePrivate & engine, fz::event_handler * handler, aio_base::shm_flag shm, uint64_t max_size)
{
	auto ret = std::make_unique<file_reader>(name_, engine, handler);

	if (ret->open(offset, max_size, shm) != aio_result::ok) {
		ret.reset();
	}

	return ret;
}

namespace {
void remove_reader_events(fz::event_handler * handler, reader_base const* reader)
{
	if (!handler) {
		return;
	}
	auto event_filter = [&](fz::event_loop::Events::value_type const& ev) -> bool {
		if (ev.first != handler) {
			return false;
		}
		else if (ev.second->derived_type() == read_ready_event::type()) {
			return std::get<0>(static_cast<read_ready_event const&>(*ev.second).v_) == reader;
		}
		return false;
	};

	handler->event_loop_.filter_events(event_filter);
}

void change_event_handler(fz::event_handler * old, fz::event_handler * new_handler, reader_base const* reader)
{
	if (!old) {
		return;
	}

	auto event_filter = [&](fz::event_loop::Events::value_type & ev) -> bool {
		if (ev.first == old && ev.second->derived_type() == read_ready_event::type() && std::get<0>(static_cast<read_ready_event const&>(*ev.second).v_) == reader) {
			ev.first = new_handler;
		}
		return false;
	};

	old->event_loop_.filter_events(event_filter);
}
}

reader_base::reader_base(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler)
	: aio_base(name, engine, handler)
{}

void reader_base::close()
{
	ready_count_ = 0;
	
	remove_reader_events(handler_, this);
}

read_result reader_base::read()
{
	fz::scoped_lock l(mtx_);
	if (error_) {
		return {aio_result::error, fz::nonowning_buffer()};
	}

	if (processing_) {
		ready_pos_ = (ready_pos_ + 1) % buffers_.size();
		if (ready_count_ == buffers_.size()) {
			signal_capacity(l);
		}
		--ready_count_;
	}
	if (ready_count_) {
		called_read_ = true;
		processing_ = true;
		return {aio_result::ok, buffers_[ready_pos_]};
	}
	else if (error_) {
		return {aio_result::error, fz::nonowning_buffer()};
	}
	else {
		handler_waiting_ = true;
		processing_ = false;
		return {aio_result::wait, fz::nonowning_buffer()};
	}
}

uint64_t reader_base::size() const
{
	fz::scoped_lock l(mtx_);
	if (error_) {
		return aio_base::nosize;
	}

	return size_;
}

void reader_base::set_handler(fz::event_handler * handler)
{
	fz::event_handler * h = handler;
	{
		fz::scoped_lock l(mtx_);
		std::swap(h, handler_);
	}
	if (!handler) {
		remove_reader_events(h, this);
	}
	else {
		change_event_handler(h, handler, this);
	}
}




file_reader::file_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler)
	: reader_base(name, engine, handler)
{
}

file_reader::~file_reader()
{
	close();
}

void file_reader::close()
{
	{
		fz::scoped_lock l(mtx_);
		quit_ = true;
		cond_.signal(l);
	}

	thread_.join();
	file_.close();

	reader_base::close();
}

aio_result file_reader::open(uint64_t offset, uint64_t max_size, shm_flag shm)
{
	if (!allocate_memory(shm)) {
		return aio_result::error;
	}

	if (!file_.open(fz::to_native(name_), fz::file::reading, fz::file::existing)) {
		return aio_result::error;
	}

	return seek(offset, max_size);
}

aio_result file_reader::seek(uint64_t offset, uint64_t max_size)
{
	if (error_) {
		return aio_result::error;
	}

	fz::scoped_lock l(mtx_);
	bool change{};
	if (!thread_) {
		change = true;
	}
	else if (called_read_) {
		change = true;
	}
	else if (offset != aio_base::nosize) {
		if (offset != start_offset_) {
			change = true;
		}
		if (max_size != aio_base::nosize && max_size != size_) {
			change = true;
		}
	}
	if (!change) {
		return aio_result::ok;
	}

	if (thread_) {
		quit_ = true;
		cond_.signal(l);
		l.unlock();
		thread_.join();
		l.lock();
		remove_reader_events(handler_, this);
	}

	ready_count_ = 0;
	ready_pos_ = 0;
	processing_ = false;
	quit_ = false;
	handler_waiting_ = false;
	called_read_ = false;

	if (offset != aio_base::nosize) {
		start_offset_ = offset;
	}
	else {
		max_size = size_;
	}

	auto const ofs = static_cast<int64_t>(start_offset_);
	if (file_.seek(ofs, fz::file::begin) != ofs) {
		error_ = true;
		return aio_result::error;
	}

	if (max_size != aio_base::nosize) {
		size_ = max_size;
	}
	else {
		auto s = file_.size();
		if (s < 0) {
			error_ = true;
			return aio_result::error;
		}
		if (static_cast<uint64_t>(s) < start_offset_) {
			error_ = true;
			return aio_result::error;
		}
		size_ = static_cast<int64_t>(s) - start_offset_;
	}

	thread_ = engine_.GetThreadPool().spawn([this]() { entry(); });
	if (!thread_) {
		error_ = true;
		return aio_result::error;
	}

	remaining_ = size_;

	return aio_result::ok;
}

void file_reader::entry()
{
	fz::scoped_lock l(mtx_);
	while (!quit_ && !error_) {
		if (ready_count_ >= buffers_.size()) {
			cond_.wait(l);
			continue;
		}

		fz::nonowning_buffer & b = buffers_[(ready_pos_ + ready_count_) % buffers_.size()];
		b.resize(0);

		size_t to_read = b.capacity();
		if (remaining_ < to_read) {
			to_read = remaining_;
		}
		int read{};
		if (to_read) {
			l.unlock();
			read = file_.read(b.get(to_read), to_read);
			l.lock();

			if (quit_) {
				return;
			}
		}


		if (read >= 0) {
			b.add(read);
			++ready_count_;
			remaining_ -= static_cast<uint64_t>(read);
		}
		else {
			error_ = true;
		}

		if (handler_waiting_) {
			handler_waiting_ = false;
			if (handler_) {
				handler_->send_event<read_ready_event>(this);
			}
		}

		if (read <= 0) {
			break;
		}
	}
}

void file_reader::signal_capacity(fz::scoped_lock & l)
{
	cond_.signal(l);
}


#include <libfilezilla/buffer.hpp>

memory_reader_factory::memory_reader_factory(std::wstring const& name, fz::buffer & data)
	: reader_factory(name)
	, data_(reinterpret_cast<char const*>(data.get()), data.size())
{}

memory_reader_factory::memory_reader_factory(std::wstring const& name, std::string_view const& data)
	: reader_factory(name)
	, data_(data)
{}

std::unique_ptr<reader_base> memory_reader_factory::open(uint64_t offset, CFileZillaEnginePrivate & engine, fz::event_handler * handler, aio_base::shm_flag shm, uint64_t max_size)
{
	auto ret = std::make_unique<memory_reader>(name_, engine, handler, data_);
	if (ret->open(offset, max_size, shm) != aio_result::ok) {
		ret.reset();
	}

	return ret;
}

std::unique_ptr<reader_factory> memory_reader_factory::clone() const
{
	return std::make_unique<memory_reader_factory>(*this);
}


memory_reader::memory_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string_view const& data)
	: reader_base(name, engine, handler)
	, start_data_(data)
	, data_(start_data_)
{
	ready_count_ = buffer_count;
}

std::unique_ptr<memory_reader> memory_reader::create(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string_view const& data, shm_flag shm)
{
	std::unique_ptr<memory_reader> ret(new memory_reader(name, engine, handler, data));
	if (!ret->allocate_memory(shm)) {
		ret.reset();
	}

	return ret;
}

aio_result memory_reader::open(uint64_t offset, uint64_t max_size, shm_flag shm)
{
	if (!allocate_memory(shm)) {
		return aio_result::error;
	}

	processing_ = true;
	ready_count_ = 8;

	return seek(offset, max_size);
}

void memory_reader::signal_capacity(fz::scoped_lock &)
{
	++ready_count_;
	
	size_t c = std::min(data_.size(), buffer_size_);

	auto& b = buffers_[ready_pos_];
	b.resize(c);
	if (c) {
		memcpy(b.get(), data_.data(), c);
		data_ = data_.substr(c);
	}
}

aio_result memory_reader::seek(uint64_t offset, uint64_t max_size)
{
	if (offset != aio_base::nosize) {
		start_offset_ = offset;
	}

	if (start_offset_ > start_data_.size()) {
		error_ = true;
		return aio_result::error;
	}
	size_ = start_data_.size() - start_offset_;
	if (max_size != aio_base::nosize) {
		if (max_size > size_) {
			error_ = true;
			return aio_result::error;
		}
		size_ = max_size;
	}

	data_ = start_data_.substr(start_offset_, size_);
	return aio_result::ok;
}




string_reader::string_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string const& data)
	: reader_base(name, engine, handler)
	, start_data_(data)
	, data_(start_data_)
{
	ready_count_ = buffer_count;
	processing_ = true;
}

string_reader::string_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string && data)
	: reader_base(name, engine, handler)
	, start_data_(std::move(data))
	, data_(start_data_)
{
	ready_count_ = buffer_count;
	processing_ = true;
}

std::unique_ptr<string_reader> string_reader::create(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string const& data, shm_flag shm)
{
	std::unique_ptr<string_reader> ret(new string_reader(name, engine, handler, data));
	if (!ret->allocate_memory(shm)) {
		ret.reset();
	}

	return ret;
}

std::unique_ptr<string_reader> string_reader::create(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, std::string && data, shm_flag shm)
{
	std::unique_ptr<string_reader> ret(new string_reader(name, engine, handler, data));
	if (!ret->allocate_memory(shm)) {
		ret.reset();
	}

	return ret;
}

void string_reader::signal_capacity(fz::scoped_lock &)
{
	++ready_count_;

	size_t c = std::min(data_.size(), buffer_size_);

	auto& b = buffers_[ready_pos_];
	b.resize(c);
	if (c) {
		memcpy(b.get(), data_.data(), c);
		data_ = data_.substr(c);
	}
}


aio_result string_reader::seek(uint64_t offset, uint64_t max_size)
{
	if (offset != aio_base::nosize) {
		start_offset_ = offset;
	}

	if (start_offset_ > start_data_.size()) {
		error_ = true;
		return aio_result::error;
	}
	size_ = start_data_.size() - start_offset_;
	if (max_size != aio_base::nosize) {
		if (max_size > size_) {
			error_ = true;
			return aio_result::error;
		}
		size_ = max_size;
	}

	data_ = start_data_;
	data_ = data_.substr(start_offset_, size_);
	return aio_result::ok;
}




buffer_reader::buffer_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, fz::buffer const& data)
	: reader_base(name, engine, handler)
	, start_data_(data)
	, data_(reinterpret_cast<char const*>(start_data_.get()), start_data_.size())
{
	ready_count_ = buffer_count;
	processing_ = true;
}

buffer_reader::buffer_reader(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, fz::buffer && data)
	: reader_base(name, engine, handler)
	, start_data_(std::move(data))
	, data_(reinterpret_cast<char const*>(start_data_.get()), start_data_.size())
{
	ready_count_ = buffer_count;
	processing_ = true;
}

std::unique_ptr<buffer_reader> buffer_reader::create(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, fz::buffer const& data, shm_flag shm)
{
	std::unique_ptr<buffer_reader> ret(new buffer_reader(name, engine, handler, data));
	if (!ret->allocate_memory(shm)) {
		ret.reset();
	}

	return ret;
}

std::unique_ptr<buffer_reader> buffer_reader::create(std::wstring const& name, CFileZillaEnginePrivate & engine, fz::event_handler * handler, fz::buffer && data, shm_flag shm)
{
	std::unique_ptr<buffer_reader> ret(new buffer_reader(name, engine, handler, data));
	if (!ret->allocate_memory(shm)) {
		ret.reset();
	}

	return ret;
}

void buffer_reader::signal_capacity(fz::scoped_lock &)
{
	++ready_count_;

	size_t c = std::min(data_.size(), buffer_size_);

	auto& b = buffers_[ready_pos_];
	b.resize(c);
	if (c) {
		memcpy(b.get(), data_.data(), c);
		data_ = data_.substr(c);
	}
}


aio_result buffer_reader::seek(uint64_t offset, uint64_t max_size)
{
	if (offset != aio_base::nosize) {
		start_offset_ = offset;
	}

	if (start_offset_ > start_data_.size()) {
		error_ = true;
		return aio_result::error;
	}
	size_ = start_data_.size() - start_offset_;
	if (max_size != aio_base::nosize) {
		if (max_size > size_) {
			error_ = true;
			return aio_result::error;
		}
		size_ = max_size;
	}

	data_ = std::string_view(reinterpret_cast<char const*>(start_data_.get() + start_offset_), size_);
	return aio_result::ok;
}
