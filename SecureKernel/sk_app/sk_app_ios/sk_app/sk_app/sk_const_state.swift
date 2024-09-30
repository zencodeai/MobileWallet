//
//  sk_const_state.swift
//  sk_app
//
//  Created by main on 2023-09-19.
//

import Foundation

/*
 {
 "name": "SK_CTX_INV",
 "description": "Invalid state",
 "value": 3215180494,
 "type": "SKRndUInt32"
 },
 */
class SKState: Codable {
    
    let name: String
    let description: String
    let value: Int
    let type: String
}

// States list handler
class SKStates {
    
    // Singleton
    static let shared = SKStates()
    
    // States list
    private var states: [SKState]? = nil
    
    // Private constructor
    private init() {
        if let states = JSONLoader<SKState>.loadUsers(from: "SKState") {
            self.states = states
        } else {
            self.states = nil
        }
    }

    // Get State by code
    func getState(code: Int) -> SKState? {
        return states?.first(where: {$0.value == code})
    }
    
    // Get state list
    func getStates() -> [SKState]? {
        return states
    }
}
