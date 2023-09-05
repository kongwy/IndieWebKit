//
//  OAuth.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation

public extension IndieAuth {
    /// OAuth Authorization Endpoint Response Types
    ///
    /// https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint
    enum AuthorizationResponseType: String, Codable {
        case code
        case idToken = "id_token"
        case token
    }

    /// OAuth Token Endpoint Authentication Methods
    ///
    /// https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method
    enum TokenAuthenticationMethod: String, Codable {
        case none
        case clientSecretPost = "client_secret_post"
        case clientSecretBasic = "client_secret_basic"
        case clientSecretJWT = "client_secret_jwt"
        case privateKeyJWT = "private_key_jwt"
        case tlsClientAuth = "tls_client_auth"
        case selfSignedTLSClientAuth = "self_signed_tls_client_auth"
    }

    /// PKCE Code Challenge Methods
    ///
    /// https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method
    enum PKCEChallengeMethod: String, Codable {
        case plain
        case s256 = "S256"
    }

    /// OAuth 2.0 Grant Types
    ///
    /// https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    enum GrantType: String, Codable {
        case authorizationCode = "authorization_code"
        case implicit
        case password
        case clientCredentials = "client_credentials"
        case refreshToken = "refresh_token"
        case jwt = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        case saml2 = "urn:ietf:params:oauth:grant-type:saml2-bearer"
    }
}
