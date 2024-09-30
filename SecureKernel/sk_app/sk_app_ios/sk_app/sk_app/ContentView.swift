//
//  ContentView.swift
//  sk_app
//
//  Created by main on 2023-09-15.
//

import SwiftUI

struct ContentView: View {
    @State private var logs: [String] = []
    @State private var scrollTarget: Int? = nil
    
    var body: some View {
        VStack(spacing: 20) {
            // Buttons
            HStack(spacing: 5) {
                Button(action: {
                    appendLog("Provision button pressed")
                }, label: {
                    Text("Provision")
                })
                
                Button(action: {
                    appendLog("Initialize button pressed")
                }, label: {
                    Text("Initialize")
                })
                
                Button(action: {
                    appendLog("Online button pressed")
                }, label: {
                    Text("Online")
                })
                
                Button(action: {
        
                    do {
                    
                        appendLog("Status button pressed")
                        let sampleBuffer: [UInt8] = Array("Hello, World! This is a test to showcase the hex dump.".utf8)
                        appendLog(hexDump(sampleBuffer))
                        if let errors = SKErrors.shared.getErrors() {
                            for error in errors {
                                appendLog("\(error.name) - \(error.description) - \(error.code)")
                            }
                        } else {
                            
                            appendLog("Failed to load constants")
                        }
                    
                        // Get state
                        let state = try SKInterface.getState()
                        let stateDescription = state.description
                        
                        // Append log
                        appendLog("State: \(stateDescription)")

                    } catch {
                        // Append log
                        appendLog("Failed to get state: \(error)")
                    }
                    
                }, label: {
                    Text("Status")
                })
            } .buttonStyle(.bordered)
            
            // Logs List
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(logs.indices, id: \.self) { index in
                            Text(logs[index])
                                .font(.custom("Courier New", size: 14))
                                .padding(.all, 2)
                                .background(Color.gray.opacity(0.1))
                                .cornerRadius(0) // Square corners
                                .id(index)
                        }
                    }
                    .onChange(of: scrollTarget) { target in
                        withAnimation {
                            proxy.scrollTo(target, anchor: .bottom)
                        }
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.all, 20)
    }
    
    func appendLog(_ message: String) {
        logs.append(message)
        scrollTarget = logs.count - 1
    }
    
    func hexDump(_ buffer: [UInt8]) -> String {
        var result = ""
        let byteCount = buffer.count

        for offset in stride(from: 0, to: byteCount, by: 8) {
            let lineBytes = buffer[offset..<min(offset + 8, byteCount)]
            
            // Print offset
            result += String(format: "%04x ", offset)
            
            // Print hex bytes
            for byte in lineBytes {
                result += String(format: "%02x ", byte)
            }

            // If less than 16 bytes on the last line, pad with spaces
            if lineBytes.count < 8 {
                for _ in 0..<(8 - lineBytes.count) {
                    result += "   " // 3 spaces per missing byte
                }
            }

            // Print printable characters
            result += "|"
            for byte in lineBytes {
                if byte >= 32 && byte <= 126 {
                    result += String(UnicodeScalar(byte))
                } else {
                    result += "."
                }
            }
            result += "|\n"
        }
        
        return result
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
