//
//  sk_const_command.swift
//  sk_app
//
//  Created by main on 2023-09-19.
//

import Foundation

/*
 {
     "name": "SK_CMD_STATUS",
     "description": "Get secure kernel status",
     "value": 2161570808,
     "type": "SKRndUInt32"
 },
 */
class SKCommand: Codable {
    
    let name: String
    let description: String
    let value: Int
    let type: String
}

// Commands list handler
class SKCommands {
    
    // Singleton
    static let shared = SKCommands()
    
    // Commands list
    private var commands: [SKCommand]? = nil
    
    // Private constructor
    private init() {
        if let commands = JSONLoader<SKCommand>.loadUsers(from: "SKCommand") {
            self.commands = commands
        } else {
            self.commands = nil
        }
    }

    // Get Command by name
    func getCommand(name: String) -> SKCommand? {
        return commands?.first(where: {$0.name == name})
    }
    
    // Get command list
    func getCommands() -> [SKCommand]? {
        return commands
    }
}

