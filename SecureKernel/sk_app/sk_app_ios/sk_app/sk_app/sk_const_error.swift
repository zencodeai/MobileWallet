//
//  sk_const_error.swift
//  sk_app
//
//  Created by main on 2023-09-19.
//

import Foundation

// Error codes
class SKError: Codable {
    
    let name: String
    let category: String
    let description: String
    let code: Int
    let type: String
}

// Error codes list handler
class SKErrors {
    
    // Singleton
    static let shared = SKErrors()
    
    // Error codes list
    private var errors: [SKError]? = nil
    
    // Private constructor
    private init() {
        if let errors = JSONLoader<SKError>.loadUsers(from: "SKError") {
            self.errors = errors
        } else {
            self.errors = []
        }
    }
    
    // Get Error by code
    func getError(code: Int) -> SKError? {
        return errors?.first(where: {$0.code == code})
    }
    
    // Get error list
    func getErrors() -> [SKError]? {
        return errors
    }    
}
