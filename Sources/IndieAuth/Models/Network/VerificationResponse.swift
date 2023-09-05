//
//  VerificationResponse.swift
//
//
//  Created by Weiyi Kong on 4/9/2023.
//

import Foundation

public extension IndieAuth {
    struct VerificationResponse: Codable {
        /// (Required) Boolean indicator of whether or not the presented token is currently active.
        public let active: Bool

        /// (Required) The profile URL of the user corresponding to this token.
        public let me: URL?

        /// The client ID associated with this token.
        public let clientID: URL?

        /// A space-separated list of scopes associated with this token.
        public let scope: String?

        /// (Optional) Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire.
        public let exp: TimeInterval?

        /// (Optional) Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued.
        public let iat: TimeInterval?

        enum CodingKeys: String, CodingKey {
            case active
            case me
            case clientID = "client_id"
            case scope
            case exp
            case iat
        }
    }
}

public extension IndieAuth.VerificationResponse {
    static var inactive: IndieAuth.VerificationResponse {
        IndieAuth.VerificationResponse(active: false, me: nil, clientID: nil, scope: nil, exp: nil, iat: nil)
    }
}
