//
//  sk_client.swift
//  sk_app
//
//  Created by main on 2023-10-03.
//

import Foundation

// URL safe base64 encoding / decoding
public extension Data {
    init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }

    func base64urlEncodedString() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}

// SK RESTful client
class SKClient {
    
    // Process data until secure kernel done or error
    func process(sessionId: String, dataB64: String) throws -> Void {

        // Decode B64 urlsafe dataB64
        var dataIn = Data(base64urlEncoded: dataB64)!

        // Process data
        var dataOut = try SKInterface.processData(data: dataIn)
        
        // Loop until done
        while dataOut.count != 0 {
            
            
        }
    }
}
