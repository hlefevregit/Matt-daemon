/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pool.tpp                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 15:12:56 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 15:50:04 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef POOL_TPP
# define POOL_TPP

#include "pool.hpp"

template <typename TType>
Pool<TType>::Pool() {}

template <typename TType>
Pool<TType>::~Pool() {
	for (size_t i = 0; i < _storage.size(); ++i) {
		if (_isUsed[i]) {
			_clear(i);
		}
		delete[] _storage[i];
	}
}

template <typename TType>
void Pool<TType>::resize(const size_t& numberOfObjectStored) {
	for (size_t i = 0; i < numberOfObjectStored; ++i) {
		unsigned char* rawMemory = new unsigned char[sizeof(TType)];
		_storage.push_back(rawMemory);
		_freeIndices.push(_storage.size() - 1);
		_isUsed.push_back(false);

	}
}

template <typename TType>
template <typename... TArgs>
typename Pool<TType>::Object Pool<TType>::acquire(TArgs&&... p_args) {
	if (_freeIndices.empty()) {
		throw std::runtime_error("No free object available in the pool");
	}

	size_t index = _freeIndices.top();
	_freeIndices.pop();

	void* mem = static_cast<void*>(_storage[index]);

	TType* objPtr = new (mem) TType(std::forward<TArgs>(p_args)...);
	_isUsed[index] = true;

	return Object(this, index, objPtr);
}

template <typename TType>
Pool<TType>::Object::Object(Pool* pool, size_t index, TType* ptr)
	: _pool(pool), _index(index), _ptr(ptr), _isValid(true) {}

template <typename TType>
Pool<TType>::Object::Object(Object&& other) noexcept
	: _pool(other._pool), _index(other._index), _ptr(other._ptr), _isValid(other._isValid) {
	other._isValid = false;
}

template <typename TType>
Pool<TType>::Object::~Object() {
	if (_isValid && _pool && _ptr) {
		_ptr->~TType();
		_pool->_clear(_index);
	}
}

template <typename TType>
typename Pool<TType>::Object& Pool<TType>::Object::operator=(Object&& other) noexcept {
	if (this != &other) {
		if (_isValid && _pool && _ptr) {
			_ptr->~TType();
			_pool->_clear(_index);
		}

		_pool = other._pool;
		_index = other._index;
		_ptr = other._ptr;
		_isValid = other._isValid;

		other._isValid = false;
	}
	return *this;
}

template <typename TType>
TType* Pool<TType>::Object::operator->() {
	if (!_isValid) {
		throw std::runtime_error("Attempt to access an invalid object");
	}
	return _ptr;
}

template <typename TType>
TType& Pool<TType>::Object::operator*() {
	if (!_isValid) {
		throw std::runtime_error("Attempt to access an invalid object");
	}
	return *_ptr;
}

template <typename TType>
const TType* Pool<TType>::Object::operator->() const {
	if (!_isValid) {
		throw std::runtime_error("Attempt to access an invalid object");
	}
	return _ptr;
}

template <typename TType>
const TType& Pool<TType>::Object::operator*() const {
	if (!_isValid) {
		throw std::runtime_error("Attempt to access an invalid object");
	}
	return *_ptr;
}

template <typename TType>
void Pool<TType>::_clear(size_t index) {
	if (index >= _isUsed.size() || !_isUsed[index]) {
		throw std::runtime_error("Invalid index or object not in use");
	}

	_isUsed[index] = false;
	_freeIndices.push(index);
}




#endif