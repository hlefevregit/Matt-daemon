/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   memento.hpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:16:15 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 17:28:46 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "data_buffer.hpp"

class Memento {
public:

	class Snapshot {
	public:
		Snapshot();

		template <typename T>
		Snapshot& operator<<(const T& data);
		template <typename T>
		Snapshot& operator>>(T& data);

		DataBuffer& buffer();

	private:
		DataBuffer	_buffer;	
	};
	
	Snapshot	save() const;
	void 		load(const Memento::Snapshot& state);
	
protected:
	virtual void _saveToSnapshot(Memento::Snapshot& snapshot) const = 0;
	virtual void _loadFromSnapshot(Memento::Snapshot& snapshot) = 0;
};

#include "memento.tpp"