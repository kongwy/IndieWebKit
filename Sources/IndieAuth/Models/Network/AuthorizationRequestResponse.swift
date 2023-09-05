//
//  Authorization.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation

// MARK: - Authorization

public extension IndieAuth {
    struct AuthorizationRequest {
        /// Indicates to the authorization server that an authorization code should be returned as the response.
        public var responseType: String = "code"

        /// The client URL.
        public var clientID: URL

        /// The redirect URL indicating where the user should be redirected to after approving the request.
        public var redirectURI: URL

        /// A parameter set by the client which will be included when the user is redirected back to the client.
        ///
        /// This is used to prevent CSRF attacks. The authorization server MUST return the unmodified state value back to the client.
        public var state: String = generateState()

        /// The code verifier.
        /// All IndieAuth clients _MUST_ use PKCE ([RFC7636](https://www.rfc-editor.org/rfc/rfc7636)) to protect against authorization code injection and CSRF attacks. A non-canonical description of the PKCE mechanism is described below, but implementers should refer to [RFC7636](https://www.rfc-editor.org/rfc/rfc7636) for details.
        ///
        /// Clients use a unique secret per authorization request to protect against authorization code injection and CSRF attacks. The client first generates this secret, which it can later use along with the authorization code to prove that the application using the authorization code is the same application that requested it.
        ///
        /// The client creates a code verifier for each authorization request by generating a random string using the characters `[A-Z]` / `[a-z]` / `[0-9]` / `-` / `.` / `_` / `~` with a minimum length of 43 characters and maximum length of 128 characters. This value is stored on the client and will be used in the authorization code exchange step later.
        ///
        /// > Compatibility: For backwards compatibility, authorization endpoints MAY accept authorization requests without a code challenge if the authorization server wishes to support older clients.
        public var codeVerifier: String = generateCodeVerifier()

        /// The code challenge.
        ///
        /// All IndieAuth clients _MUST_ use PKCE ([RFC7636](https://www.rfc-editor.org/rfc/rfc7636)) to protect against authorization code injection and CSRF attacks. A non-canonical description of the PKCE mechanism is described below, but implementers should refer to [RFC7636](https://www.rfc-editor.org/rfc/rfc7636) for details.
        ///
        /// Clients use a unique secret per authorization request to protect against authorization code injection and CSRF attacks. The client first generates this secret, which it can later use along with the authorization code to prove that the application using the authorization code is the same application that requested it.
        ///
        /// The client creates the code challenge derived from the code verifier by calculating the SHA256 hash of the code verifier and [Base64-URL-encoding](https://datatracker.ietf.org/doc/html/rfc7636#appendix-A) the result.
        ///
        /// ```
        /// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        /// ```
        ///
        /// > Compatibility: For backwards compatibility, authorization endpoints MAY accept authorization requests without a code challenge if the authorization server wishes to support older clients.
        public var codeChallenge: String {
            switch codeChallengeMethod {
            case .s256:
                return s256Encode(codeVerifier)
            case .plain:
                return codeVerifier
            }
        }

        /// The hashing method used to calculate the code challenge.
        public var codeChallengeMethod: PKCEChallengeMethod

        /// (Optional) A space-separated list of scopes the client is requesting, e.g. "profile", or "profile create".
        ///
        /// If the client omits this value, the authorization server _MUST NOT_ issue an access token for this authorization code. Only the user's profile URL may be returned without any scope requested. See [Profile Information](https://indieauth.spec.indieweb.org/#profile-information) for details about which scopes to request to return user profile information.
        public var scope: String?

        /// (Optional) The URL that the user entered.
        public var me: String?
    }
}

public extension IndieAuth.AuthorizationRequest {
    init(
        discovery metadata: IndieAuth.DiscoveryResponse,
        clientID: URL = IndieAuth.clientID,
        redirectURI: URL = IndieAuth.redirectURI,
        state: String = IndieAuth.generateState(),
        codeVerifier: String = IndieAuth.generateCodeVerifier(),
        scope: String? = nil,
        me: String? = nil
    ) {
        self.responseType = metadata.responseTypesSupported.first?.rawValue ?? "code"
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.state = state
        self.codeVerifier = codeVerifier
        self.codeChallengeMethod = metadata.codeChallengeMethodsSupported.contains(.s256) ? .s256 : .plain
        self.scope = scope
        self.me = me
    }
}

public extension IndieAuth {
    struct AuthorizationResponse: Codable {
        /// The authorization code generated by the authorization endpoint.
        ///
        /// The code _MUST_ expire shortly after it is issued to mitigate the risk of leaks, and _MUST_ be valid for only one use. A maximum lifetime of 10 minutes is recommended. See [OAuth 2.0 Section 4.1.2](https://tools.ietf.org/html/rfc6749#section-4.1.2) for additional requirements on the authorization code.
        public let code: String

        /// The state parameter _MUST_ be set to the exact value that the client set in the request.
        ///
        /// Upon the redirect back to the client, the client _MUST_ verify that the `state` parameter in the request is valid and matches the state parameter that it initially created, in order to prevent CSRF attacks. The state value can also store session information to enable development of clients that cannot store data themselves.
        public let state: String

        /// The issuer identifier for client validation.
        ///
        /// Upon the redirect back to the client, the client _MUST_ verify that the iss parameter in the request is valid and matches the issuer parameter provided by the Server Metadata endpoint during Discovery as outlined in [OAuth 2.0 Authorization Server Issuer Identification](https://www.ietf.org/archive/id/draft-ietf-oauth-iss-auth-resp-02.html). Clients _MUST_ compare the parameters using simple string comparison. If the value does not match the expected issuer identifier, clients MUST reject the authorization response and _MUST NOT_ proceed with the authorization grant. For error responses, clients _MUST NOT_ assume that the error originates from the intended authorization server.
        public let iss: String
    }
}

public extension IndieAuth.AuthorizationResponse {
    init?(callback url: URL) {
        guard let queryItems = URLComponents(string: url.absoluteString)?.queryItems,
              let code = queryItems.first(where: { $0.name == "code" })?.value,
              let state = queryItems.first(where: { $0.name == "state" })?.value,
              let iss = queryItems.first(where: { $0.name == "iss" })?.value
        else {
            return nil
        }
        self.code = code
        self.state = state
        self.iss = iss
    }
}

// MARK: - Redemption

public extension IndieAuth {
    struct RedemptionRequest {
        public let grantType: GrantType = .authorizationCode

        /// The authorization code received from the authorization endpoint in the redirect.
        public var code: String

        /// The client's URL, which MUST match the client_id used in the authentication request.
        public var clientID: URL

        /// The client's redirect URL, which MUST match the initial authentication request.
        public var redirectURI: URL

        /// The original plaintext random string generated before starting the authorization request.
        ///
        /// Note that for backwards compatibility, the authorization endpoint _MAY_ allow requests without the `code_verifier`.
        ///
        /// If an authorization code was issued with no `code_challenge` present, then the authorization code exchange _MUST NOT_ include a `code_verifier`, and similarly, if an authorization code was issued with a `code_challenge` present, then the authorization code exchange _MUST_ include a `code_verifier`.
        public var codeVerifier: String?
    }

    struct RedemptionResponse: Codable {
        /// The OAuth 2.0 Bearer Token [RFC6750](https://www.rfc-editor.org/rfc/rfc6750).
        public let accessToken: String?

        /// The canonical user profile URL for the user this access token corresponds to.
        public let me: URL

        /// (Optional) The user's profile information as defined in [Profile Information](https://indieauth.spec.indieweb.org/#profile-information).
        public let profile: Profile?

        /// (Recommended) The lifetime in seconds of the access token.
        public let expiresIn: TimeInterval?

        /// (Optional) The refresh token, which can be used to obtain new access tokens as defined in [Refresh Tokens](https://indieauth.spec.indieweb.org/#refresh-tokens).
        public let refreshToken: String?

        public let tokenType: String?
        public let scope: String?

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case me
            case profile
            case expiresIn = "expires_in"
            case refreshToken = "refresh_token"
            case tokenType = "token_type"
            case scope
        }

        public struct Profile: Codable {
            /// Name the user wishes to provide to the client.
            ///
            /// This is not to be considered by the client to be the full name of the user. Clients are expected to use this as a display name.
            public var name: String

            /// URL of the user's website.
            ///
            /// The `url` is not guaranteed to match the `me` URL, and may even have a different host. For example, a multi-author website may use the website's URL as the `me` URL, but return each specific author's own personal website in the profile data.
            public var url: URL

            /// A photo or image that the user wishes clients to use as a profile image.
            public var photo: URL

            /// The email address a user wishes to provide to the client.
            ///
            /// `Nil` if email scope is not requested.
            public var email: String?
        }
    }
}

// MARK: - Refreshing

public extension IndieAuth {
    struct RefreshTokenRequest {
        public let grantType: GrantType = .refreshToken

        /// The refresh token previously offered to the client.
        public var refreshToken: String

        /// The client ID that was used when the refresh token was issued.
        public var clientID: String

        /// (Optional) The client may request a token with the same or fewer scopes than the original access token. If omitted, is treated as equal to the original scopes granted.
        public var scope: String?
    }

    typealias RefreshTokenResponse = RedemptionResponse
}
