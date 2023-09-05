//
//  Error.swift
//
//
//  Created by Weiyi Kong on 2/8/2023.
//

import Foundation

public enum IndieAuthError: Error {
    case invalidHTTPResponse(urlString: String, statusCode: Int?)
    case invalidURL(urlString: String, type: IndieAuth.URLType?, reason: IndieAuth.URLRule?)

    case metadataNotFound

    case invalidCodeVerifier

    public var localizedDescription: String {
        switch self {
        case let .invalidHTTPResponse(_, statusCode):
            guard let statusCode else { return "Unknown URL response error." }
            return HTTPURLResponse.localizedString(forStatusCode: statusCode)
        case let .invalidURL(urlString, type, reason):
            return "\(type?.description ?? "") URL violates rule \(reason?.description ?? "unknown"): \(urlString)"
        case .metadataNotFound:
            return "Metadata cannot be found."
        case .invalidCodeVerifier:
            return "Invalid code verifier."
        }
    }

    public var referenceURI: String? {
        switch self {
        case .invalidURL:
            return "https://indieauth.spec.indieweb.org/#user-profile-url"
        case .invalidCodeVerifier:
            return "https://indieauth.spec.indieweb.org/#authorization-request"
        default:
            return nil
        }
    }
}
