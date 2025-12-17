/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   singleton.tpp                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 18:08:46 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 18:14:58 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "singleton.hpp"

template <typename TType>
TType* Singleton<TType>::_instance = nullptr;

template <typename TType>
TType* Singleton<TType>::instance() {
	if (!_instance) {
		throw std::runtime_error("Singleton instance not created. Call instantiate() first.");
	}
	return _instance;
}


template <typename TType>
template<typename ... TArgs>
void Singleton<TType>::instantiate(TArgs&&... p_args) {
	if (_instance) {
		throw std::runtime_error("Singleton instance already created.");
	}
	_instance = new TType(std::forward<TArgs>(p_args)...);
}


template <typename TType>
void Singleton<TType>::destroy() {
	if (_instance) {
		delete _instance;
		_instance = nullptr;
	}
}

// template <typename TType>
// Singleton<TType>::Singleton() {}

// template <typename TType>
// Singleton<TType>::~Singleton() {}

// template <typename TType>
// Singleton<TType>::Singleton(const Singleton&) {}

// template <typename TType>
// Singleton<TType>& Singleton<TType>::operator=(const Singleton&) { return *this; }
