/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   state_machine.tpp                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 18:20:55 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/07 18:40:38 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "state_machine.hpp"

template<typename TState>
void StateMachine<TState>::addState(const TState& state) {
	_states.insert(state);
	if (!_hasInitialState) {
		_currentState = state;
		_hasInitialState = true;
	}
}

template<typename TState>
void StateMachine<TState>::addTransition(const TState& startState, const TState& finalState, const std::function<void()>& lambda) {
	if (_states.find(startState) == _states.end() || _states.find(finalState) == _states.end()) {
		throw std::invalid_argument("Both states must be added to the state machine before adding a transition.");
	}
	_transitions[{startState, finalState}] = lambda;
}

template<typename TState>
void StateMachine<TState>::addAction(const TState& state, const std::function<void()>& lambda) {
	if (_states.find(state) == _states.end()) {
		throw std::invalid_argument("State must be added to the state machine before adding an action.");
	}
	_actions[state] = lambda;
}

template<typename TState>
void StateMachine<TState>::transitionTo(const TState& state) {
    if (_states.find(state) == _states.end()) {
        throw std::invalid_argument("Target state must be added to the state machine before transitioning.");
    }
    
    auto transitionIt = _transitions.find({_currentState, state});
    if (transitionIt != _transitions.end()) {
        transitionIt->second(); // Execute transition action
    } else {
        // ✅ OPTION: Permettre les transitions silencieuses
        std::cout << "No transition action defined (silent transition)." << std::endl;
        // Ou laisser l'exception pour forcer la définition explicite des transitions
        // throw std::runtime_error("No transition defined from current state to target state.");
    }
    _currentState = state; // ✅ Toujours changer d'état
}

template<typename TState>
void StateMachine<TState>::update() {
	auto actionIt = _actions.find(_currentState);
	if (actionIt != _actions.end()) {
		actionIt->second(); // Execute state action
	}
}

template<typename TState>
template<typename T>
std::size_t StateMachine<TState>::StateHash<T>::operator()(const std::pair<T,T>& p) const {
	std::hash<T> hasher;
	return hasher(p.first) ^ (hasher(p.second) << 1);
}

