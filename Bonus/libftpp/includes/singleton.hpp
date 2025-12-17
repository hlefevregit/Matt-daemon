/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   singleton.hpp                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:16:48 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 18:17:11 by hulefevr         ###   ########.fr       */
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

	Singleton(const Singleton&);
	Singleton& operator=(const Singleton&);
};

#include "singleton.tpp"