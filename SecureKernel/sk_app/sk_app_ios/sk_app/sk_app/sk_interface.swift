//
//  sk_interface.swift
//  sk_app
//
//  Created by main on 2023-09-29.
//

import Foundation

class SKInterface {
    
    // Serialize an Int (command) and a Data object into a Data object. The command is serialized as a little endian Uint32
    static func serializeCommand(command: Int, data: Data) -> Data {

        // Serialize command as UInt32 little endian
        let commandData = Data(
            bytes: [UInt8(command & 0xff), UInt8((command >> 8) & 0xff), UInt8((command >> 16) & 0xff), UInt8((command >> 24) & 0xff)])

        return commandData + data
    }
    
    // Get the last 4 bytes of data (Data) as an Int error code
    static func deserializeError(data: Data) -> Int {
        
        // Get last 4 bytes of data
        let errorData = data.suffix(4)
        
        // Convert to Int
        let error = Int(errorData.withUnsafeBytes { $0.load(as: UInt32.self) })
        
        return error
    }
    
    // Invoke secure kernel wrapper
    static func invoke(command: Int, data: Data) throws -> Data {
        
        // Serialize command and data
        let commandData = serializeCommand(command: command, data: data)
        
        // Invoke secure kernel wrapper (void)callWithData:(NSData *)inData outData:(NSMutableData **)outData
        // Prepare an optional variable to receive the output data
        var outputData: NSMutableData?

        // Call the method
        SKWrapper.call(with: commandData, outData: &outputData)
        
        // Get result
        let result = outputData as Data?
        
        // 8 bytes error message?
        if result?.count == 8 {
            
            // Get error code
            let error = deserializeError(data: result!)
            
            // Get error description
            let errorEntry = SKErrors.shared.getError(code: error) as SKError?
            
            // Throw excption
            throw SKAppErrors.runtimeError(errorEntry?.description ?? "Unknown error code: \(error)")
        }
        
        // Return result
        return result!
    }

    // Get secure kernel state
    static func getState() throws -> SKState {
        
        // Command
        let command = SKCommands.shared.getCommand(name: "SK_CMD_STATUS")?.value ?? 0
        
        // Invoke
        let result = try invoke(command: command, data: Data())
        
        // Deserialize litle endian UInt32
        let state = result.withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Get state entry
        let stateEntry = SKStates.shared.getState(code: Int(state)) as SKState?
        
        // If state entry is nil, throw exception
        if stateEntry == nil {
            throw SKAppErrors.runtimeError("Unknown state code: \(state)")
        }
        
        return stateEntry!
    }
    
    // Provisioning
    static func provision(token: Data) throws -> Data {
        
        // Command
        let command = SKCommands.shared.getCommand(name: "SK_CMD_PROVISION")?.value ?? 0
        
        // Invoke
        return try invoke(command: command, data: Data())
    }
    
    // Initialize
    static func initialize() throws -> Data {
        
        // Command
        let command = SKCommands.shared.getCommand(name: "SK_CMD_INIT")?.value ?? 0
        
        // Invoke
        return try invoke(command: command, data: Data())
    }
    
    // Online session
    static func onlineSession() throws -> Data {
        
        // Command
        let command = SKCommands.shared.getCommand(name: "SK_CMD_ONLINE")?.value ?? 0
        
        // Invoke
        return try invoke(command: command, data: Data())
    }
    
    // Process data
    static func processData(data: Data) throws -> Data {
        
        // Command
        let command = SKCommands.shared.getCommand(name: "SK_CMD_PROCESS")?.value ?? 0
        
        // Invoke
        return try invoke(command: command, data: data)
    }
}
