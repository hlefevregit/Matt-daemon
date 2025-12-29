/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   singleton.hpp                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:16:48 by hulefevr          #+#    #+#             */
/*   Updated: 2025/12/17 17:40:09 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stdexcept>

template <typename TType>
class Singleton {
public:
	static TType* instance();
	
	template<typename ... TArgs>
	static void instantiate(TArgs&&... p_args);	

	// Delete copy constructor and assignment operator to prevent copies
	static void destroy();

private:
	static TType* _instance;

	Singleton();
	~Singleton();

	Singleton(const Singleton&) = delete;
	Singleton& operator=(const Singleton&) = delete;
};

#include "singleton.tpp"