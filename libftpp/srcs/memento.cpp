/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   memento.cpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:24:57 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 17:28:40 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */


#include "memento.hpp"

Memento::Snapshot::Snapshot() : _buffer() {}

DataBuffer& Memento::Snapshot::buffer() {
	return _buffer;
}

Memento::Snapshot Memento::save() const {
	Memento::Snapshot snapshot;
	_saveToSnapshot(snapshot);
	return snapshot;
}

void	Memento::load(const Memento::Snapshot& state) 
{
	_loadFromSnapshot(const_cast<Memento::Snapshot&>(state));
}
