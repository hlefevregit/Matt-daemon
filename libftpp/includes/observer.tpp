/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   observer.tpp                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:39:03 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 17:39:30 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "observer.hpp"

template <typename TEvent>
void Observer<TEvent>::subscribe(const TEvent& event, const std::function<void()>& lambda) {
	_observers[event].push_back(lambda);
}

template <typename TEvent>
void Observer<TEvent>::notify(const TEvent& event) {
	auto it = _observers.find(event);
	if (it != _observers.end()) {
		for (const auto& lambda : it->second) {
			lambda();
		}
	}
}

