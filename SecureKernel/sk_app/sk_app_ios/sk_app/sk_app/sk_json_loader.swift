//
//  sk_json_loader.swift
//  sk_app
//
//  Created by main on 2023-09-19.
//

import Foundation

struct JSONLoader<T:Codable> {

    static func loadUsers(from filename: String) -> [T]? {
        guard let url = Bundle.main.url(forResource: filename, withExtension: "json"),
              let data = try? Data(contentsOf: url) else {
            
            // file not found
            return nil
        }

        let decoder = JSONDecoder()
        return try? decoder.decode([T].self, from: data)
    }
}
