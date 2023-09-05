//
//  URL.swift
//
//
//  Created by Weiyi Kong on 7/8/2023.
//

import Foundation

public extension IndieAuth {
    enum URLRule {
        case schemeRequired
        case schemeHTTPOrHTTPSOnly
        case pathRequired
        case pathSingleOrDoubleDotSegmentsNotAllowed
        case fragmentNotAllowed
        case usernamePasswordNotAllowed
        case portNotAllowed
        case hostnameRequired
        case hostnameDomainOnly

        public var description: String {
            switch self {
            case .schemeRequired:
                return "MUST HAVE a scheme."
            case .schemeHTTPOrHTTPSOnly:
                return "Scheme MUST BE HTTP/HTTPS."
            case .pathRequired:
                return "MUST HAVE a path component."
            case .pathSingleOrDoubleDotSegmentsNotAllowed:
                return "MUST NOT CONTAIN single-dot or double-dot path segments."
            case .fragmentNotAllowed:
                return "MUST NOT CONTAIN a fragment component."
            case .usernamePasswordNotAllowed:
                return "MUST NOT CONTAIN a username or password component."
            case .portNotAllowed:
                return "MUST NOT CONTAIN a port."
            case .hostnameRequired:
                return "MUST HAVE a host name."
            case .hostnameDomainOnly:
                return "Host names MUST BE domain names, MUST NOT BE IPv4 or IPv6 addresses."
            }
        }

        public func conformed(by url: URL) -> Bool {
            switch self {
            case .schemeRequired:
                return !(url.scheme?.isEmpty ?? true)
            case .schemeHTTPOrHTTPSOnly:
                return ["http", "https"].contains(url.scheme)
            case .pathRequired:
                return !url.path.isEmpty
            case .pathSingleOrDoubleDotSegmentsNotAllowed:
                return !url.pathComponents.contains(where: { [".", ".."].contains($0) })
            case .fragmentNotAllowed:
                return url.fragment?.isEmpty ?? true
            case .usernamePasswordNotAllowed:
                return (url.user?.isEmpty ?? true) && (url.password?.isEmpty ?? true)
            case .portNotAllowed:
                return url.port == nil
            case .hostnameRequired:
                return !(url.host?.isEmpty ?? true)
            case .hostnameDomainOnly:
                guard let host = url.host else { return false }
                return !host.contains(":") && !host.contains("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") && !host.contains("(([a-fA-F0-9:]+::?)+[a-fA-F0-9]+)|(([^:]+:)\\{7\\}([^:]+))")
            }
        }
    }

    enum URLType: String {
        case userProfileURL
        case clientID

        case authorizationEndpoint
        case tokenEndpoint
        case introspectionEndpoint
        case revocationEndpoint
        case userinfoEndpoint

        case issuer
        case serviceDocumentation

        var description: String {
            switch self {
            case .userProfileURL:
                return "User Profile"
            case .clientID:
                return "Client ID"
            case .authorizationEndpoint:
                return "Authorization Endpoint"
            case .tokenEndpoint:
                return "Token Endpoint"
            case .introspectionEndpoint:
                return "Introspection Endpoint"
            case .revocationEndpoint:
                return "Revocation Endpoint"
            case .userinfoEndpoint:
                return "User Info Endpoint"
            case .issuer:
                return "Issuer"
            case .serviceDocumentation:
                return "Service Documentation"
            }
        }
    }
}
