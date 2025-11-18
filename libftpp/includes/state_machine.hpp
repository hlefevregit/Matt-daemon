/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   state_machine.hpp                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 17:17:01 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/07 18:39:59 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <stdexcept>
#include <iostream>

template<typename TState>
class StateMachine {
public:

	StateMachine() : _hasInitialState(false) {}
	StateMachine(const TState& initialState) : _currentState(initialState) {}

	void addState(const TState& state);
	void addTransition(const TState& startState, const TState& finalState, const std::function<void()>& lambda);
	
	void addAction(const TState& state, const std::function<void()>& lambda);
	
	void transitionTo(const TState& state);
	void update();

	TState getCurrentState() const { return _currentState; }
	void setCurrentState(const TState& state) { _currentState = state; };

private:

	TState _currentState;
	bool _hasInitialState;

	template<typename T>
	struct StateHash {
		std::size_t operator()(const std::pair<T,T>& p) const;
	};

	std::unordered_set<TState> _states;
	std::unordered_map<TState, std::function<void()>> _actions;
	std::unordered_map<std::pair<TState,TState>, std::function<void()>, StateHash<TState>> _transitions;
};



#include "state_machine.tpp"