/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pool.hpp                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 15:03:14 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 16:01:15 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <vector>
#include <stack>
#include <memory>
#include <cstddef>
#include <utility>
#include <stdexcept>

template <typename TType>
class Pool {
	public:
		class Object;
		
		Pool();
		~Pool();

		void resize(const size_t& numberOfObjectStored);
		
		template <typename... TArgs>
		Object acquire(TArgs&&... p_args);
		
		class Object {
			public:
				Object(Pool* pool, size_t index, TType* ptr);
				Object(Object&& other) noexcept;
				~Object();

				Object& operator=(Object&& other) noexcept;

				TType* operator->();
				TType& operator*();
				const TType* operator->() const;
				const TType& operator*() const;

			private:
				Pool* _pool;
				size_t _index;
				TType* _ptr;
				bool _isValid;

				Object(const Object& other);
				Object& operator=(const Object& other);
		};
	private:
		std::vector<unsigned char*> _storage;
		std::stack<size_t> _freeIndices;
		std::vector<bool> _isUsed;

		void _clear(size_t index);
		
		
};

#include "./pool.tpp"