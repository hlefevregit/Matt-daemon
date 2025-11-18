/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   observer.hpp                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:16:32 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 17:39:08 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once


# include <unordered_map>
# include <vector>
# include <functional>
# include <iostream>

template <typename TEvent>
class Observer {
public:
    void subscribe(const TEvent& event, const std::function<void()>& lambda);
    void notify(const TEvent& event);

private:
    std::unordered_map<TEvent, std::vector<std::function<void()>>> _observers;
};

#include "observer.tpp"