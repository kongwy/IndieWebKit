//
//  Revocation.swift
//
//
//  Created by Weiyi Kong on 4/9/2023.
//

import Foundation

public extension IndieAuth {
    static func revocateRequest(_ revocationEndpoint: URL, token: String) -> URLRequest {
        var urlRequest = URLRequest(url: revocationEndpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = [
            "Content-Type"  :   "application/x-www-form-urlencoded",
            "Accept"        :   "application/json",
        ]
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "token", value: token),
        ]
        urlRequest.httpBody = components.url?.query?.data(using: .utf8)
        return urlRequest
    }

    static func revocate(legacy tokenEndpoint: URL, token: String) -> URLRequest {
        var urlRequest = URLRequest(url: tokenEndpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = [
            "Content-Type"  :   "application/x-www-form-urlencoded",
        ]
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "action", value: "revoke"),
            URLQueryItem(name: "token", value: token),
        ]
        urlRequest.httpBody = components.url?.query?.data(using: .utf8)
        return urlRequest
    }
}
