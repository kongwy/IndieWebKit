//
//  Verification.swift
//
//
//  Created by Weiyi Kong on 4/9/2023.
//

import Foundation

public extension IndieAuth {
    static func verifyRequest(_ introspectEndpoint: URL, token: String) -> URLRequest {
        var urlRequest = URLRequest(url: introspectEndpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = [
            "Content-Type"  :   "application/x-www-form-urlencoded",
            "Accept"        :   "application/json",
            "Authorization" :   "Bearer \(token)",
        ]
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "token", value: token),
        ]
        urlRequest.httpBody = components.url?.query?.data(using: .utf8)
        return urlRequest
    }

    @available(iOS 15.0, *)
    static func verify(_ request: URLRequest, using session: URLSession? = nil) async throws -> VerificationResponse {
        let (data, _) = try await send(request, using: session)
        let response = try JSONDecoder().decode(VerificationResponse.self, from: data)
        return response
    }

    static func verifyRequest(legacy tokenEndpoint: URL, token: String) -> URLRequest {
        var urlRequest = URLRequest(url: tokenEndpoint)
        urlRequest.httpMethod = "GET"
        urlRequest.allHTTPHeaderFields = [
            "Authorization" :   "Bearer \(token)",
        ]
        return urlRequest
    }

    @available(iOS 15.0, *)
    static func verify(legacy request: URLRequest, using session: URLSession? = nil) async throws -> VerificationResponse {
        do {
            let (data, _) = try await send(request, using: session)
            let response = try JSONDecoder().decode(VerificationResponse.self, from: data)
            return response
        } catch {
            switch error {
            case let IndieAuthError.invalidHTTPResponse(_, statusCode):
                if [400, 401, 403].contains(statusCode) { return .inactive }
                fallthrough
            default:
                throw error
            }
        }
    }
}
