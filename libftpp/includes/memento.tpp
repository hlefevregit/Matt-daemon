/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   memento.tpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:24:11 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 17:24:37 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "memento.hpp"

template <typename T>
Memento::Snapshot& Memento::Snapshot::operator<<(const T& data) {
	_buffer << data;
	return *this;
}

template <typename T>
Memento::Snapshot& Memento::Snapshot::operator>>(T& data) {
	_buffer >> data;
	return *this;
}
