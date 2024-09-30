//
//  sk_app_errors.swift
//  sk_app
//
//  Created by main on 2023-09-19.
//

import Foundation

// Application-specific errors


enum SKAppErrors: Error {
    
    // File not found in bundle
    case fileNotFoundInBundle
    
    // Runtime error
    case runtimeError(String)
}
