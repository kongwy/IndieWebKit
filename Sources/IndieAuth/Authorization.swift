//
//  Authorization.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import CommonCrypto
import Foundation

// MARK: - Authorization

public extension IndieAuth {
    static func authorizeRequestURL(_ authorizeEndpoint: URL, with request: AuthorizationRequest) -> URL? {
        var components = URLComponents(url: authorizeEndpoint, resolvingAgainstBaseURL: false)
        var queryItems = [
            URLQueryItem(name: "response_type", value: request.responseType),
            URLQueryItem(name: "client_id", value: request.clientID.absoluteString),
            URLQueryItem(name: "redirect_uri", value: request.redirectURI.absoluteString),
            URLQueryItem(name: "state", value: request.state),
            URLQueryItem(name: "code_challenge", value: request.codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: request.codeChallengeMethod.rawValue),
        ]
        if let scope = request.scope { queryItems.append(URLQueryItem(name: "scope", value: scope)) }
        if let me = request.me { queryItems.append(URLQueryItem(name: "me", value: me)) }
        components?.queryItems = queryItems
        return components?.url
    }

    static func authorizeRequestURL(
        discovery metadata: DiscoveryResponse,
        clientID: URL = IndieAuth.clientID,
        redirectURI: URL = IndieAuth.redirectURI,
        state: String = IndieAuth.generateState(),
        codeVerifier: String = IndieAuth.generateCodeVerifier(),
        scope: String? = nil,
        me: String? = nil
    ) -> URL? {
        return authorizeRequestURL(
            metadata.authorizationEndpoint,
            with: AuthorizationRequest(
                discovery: metadata,
                clientID: clientID,
                redirectURI: redirectURI,
                state: state,
                codeVerifier: codeVerifier,
                scope: scope,
                me: me
            )
        )
    }
}

// MARK: - Redemption

public extension IndieAuth {
    static func redeemRequest(_ endpoint: URL, with request: RedemptionRequest) -> URLRequest {
        var urlRequest = URLRequest(url: endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = [
            "Content-Type"  :   "application/x-www-form-urlencoded",
            "Accept"        :   "application/json",
        ]
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "grant_type", value: request.grantType.rawValue),
            URLQueryItem(name: "code", value: request.code),
            URLQueryItem(name: "client_id", value: request.clientID.absoluteString),
            URLQueryItem(name: "redirect_uri", value: request.redirectURI.absoluteString),
        ]
        if let codeVerifier = request.codeVerifier {
            components.queryItems?.append(URLQueryItem(name: "code_verifier", value: codeVerifier))
        }
        urlRequest.httpBody = components.url?.query?.data(using: .utf8)
        return urlRequest
    }

    @available(iOS 15.0, *)
    static func redeem(_ request: URLRequest, using session: URLSession? = nil) async throws -> RedemptionResponse {
        let (data, _) = try await send(request, using: session)
        let response = try JSONDecoder().decode(RedemptionResponse.self, from: data)
        return response
    }

    static func redeem(
        _ request: URLRequest,
        using session: URLSession? = nil,
        completionHandler: @escaping (RedemptionResponse?, HTTPURLResponse?, Error?) -> Void
    ) {
        send(request, using: session) { data, response, err in
            guard let data, err == nil else {
                completionHandler(nil, response, err)
                return
            }
            do {
                let redemption = try JSONDecoder().decode(RedemptionResponse.self, from: data)
                completionHandler(redemption, response, err)
            } catch {
                completionHandler(nil, response, error)
            }
        }
    }
}

// MARK: - Refreshing

public extension IndieAuth {
    static func refreshRequest(_ tokenEndpoint: URL, with request: RefreshTokenRequest) -> URLRequest {
        var urlRequest = URLRequest(url: tokenEndpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.allHTTPHeaderFields = [
            "Content-Type"  :   "application/x-www-form-urlencoded",
            "Accept"        :   "application/json",
        ]
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "grant_type", value: request.grantType.rawValue),
            URLQueryItem(name: "refresh_token", value: request.refreshToken),
            URLQueryItem(name: "client_id", value: request.clientID),
        ]
        if let scope = request.scope {
            components.queryItems?.append(URLQueryItem(name: "scope", value: scope))
        }
        urlRequest.httpBody = components.url?.query?.data(using: .utf8)
        return urlRequest
    }

    @available(iOS 15.0, *)
    static func refresh(_ request: URLRequest, using session: URLSession? = nil) async throws -> RefreshTokenResponse {
        return try await redeem(request, using: session)
    }

    static func refresh(
        _ request: URLRequest,
        using session: URLSession? = nil,
        completionHandler: @escaping (RefreshTokenResponse?, HTTPURLResponse?, Error?) -> Void
    ) {
        redeem(request, using: session, completionHandler: completionHandler)
    }
}

// MARK: - Utilities

public extension IndieAuth {
    static func generateState(length: Int = stateLength) -> String {
        IndieAuth.generatePasscode(length: length, from: IndieAuth.stateCharSet)
    }

    static func generateCodeVerifier(length: Int? = codeVerifierLength) -> String {
        guard let length, codeVerifierLengthRange.contains(length) else {
            return IndieAuth.generatePasscode(length: Int.random(in: codeVerifierLengthRange), from: IndieAuth.codeVerifierCharSet)
        }
        return IndieAuth.generatePasscode(length: length, from: IndieAuth.codeVerifierCharSet)
    }

    static func s256Encode(_ code: String) -> String {
        let data = code.data(using: .ascii)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        let base64String = Data(hash).base64EncodedString()
        let base64URLString = base64String.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return base64URLString
    }

    fileprivate static func generatePasscode(length: Int, from chars: String) -> String {
        String((0 ... length).compactMap { _ in chars.randomElement() })
    }
}
