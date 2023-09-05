//
//  DiscoveryResponse.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation

public extension IndieAuth {
    typealias DiscoveryResponse = Metadata

    /// IndieAuth Server Metadata
    ///
    /// IndieAuth metadata adopts OAuth 2.0 Authorization Server Metadata [RFC8414](https://www.rfc-editor.org/rfc/rfc8414), with the notable difference that discovery of the URL happens via the IndieAuth link relation rather than the `.well-known` discovery method specified by RFC8414. For compatibility with other OAuth 2.0 implementations, use of the `.well-known` path as defined in RFC8414 is _RECOMMENDED_ but optional.
    ///
    /// > Reference: <https://indieauth.spec.indieweb.org/#indieauth-server-metadata>
    struct Metadata: Codable {
        /// The server's issuer identifier. The issuer identifier is a URL that uses the "https" scheme and has no query or fragment components.
        ///
        /// The identifier MUST be a prefix of the indieauth-metadata URL.
        public let issuer: URL

        /// The Authorization Endpoint
        public let authorizationEndpoint: URL

        /// The Token Endpoint
        public let tokenEndpoint: URL

        /// The Introspection Endpoint
        public let introspectionEndpoint: URL

        /// (Optional) JSON array containing a list of client authentication methods supported by this introspection endpoint.
        public let introspectionEndpointAuthMethodsSupported: [TokenAuthenticationMethod]

        /// (Optional) The Revocation Endpoint
        public let revocationEndpoint: URL?

        /// (Optional) JSON array containing the value `.none`.
        ///
        /// If a revocation endpoint is provided, this property should also be provided with the value `[.none]`, since the omission of this value defaults to `client_secret_basic` according to [RFC8414](https://www.rfc-editor.org/rfc/rfc8414).
        public let revocationEndpointAuthMethodsSupported: [TokenAuthenticationMethod]

        /// (Recommended) JSON array containing scope values supported by the IndieAuth server.
        ///
        /// Servers _MAY_ choose not to advertise some supported scope values even when this parameter is used.
        public let scopesSupported: [String]

        /// (Optional) JSON array containing the `response_type` values supported.
        ///
        /// This differs from [RFC8414] in that this parameter is _OPTIONAL_ and that, if omitted, the default is `.code`.
        public let responseTypesSupported: [AuthorizationResponseType]

        /// (Optional) JSON array containing grant type values supported.
        ///
        /// If omitted, the default value differs from [RFC8414](https://www.rfc-editor.org/rfc/rfc8414) and is `.authorization_code`.
        public let grantTypesSupported: [GrantType]

        /// (Optional) URL of a page containing human-readable information that developers might need to know when using the server.
        ///
        /// This might be a link to the IndieAuth spec or something more personal to your implementation.
        public let serviceDocumentation: URL?

        /// JSON array containing the methods supported for PKCE.
        ///
        /// This parameter differs from [RFC8414](https://www.rfc-editor.org/rfc/rfc8414) in that it is not optional as PKCE is _REQUIRED_.
        public let codeChallengeMethodsSupported: [PKCEChallengeMethod]

        /// (Optional) Boolean parameter indicating whether the authorization server provides the _iss_ parameter.
        ///
        /// If omitted, the default value is `false`. As the `iss` parameter is _REQUIRED_, this is provided for compatibility with OAuth 2.0 servers implementing the parameter.
        public let authorizationResponseISSParameterSupported: Bool

        /// (Optional) The User Info Endpoint
        public let userinfoEndpoint: URL?

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)

            issuer = try container.decode(URL.self, forKey: .issuer)
            authorizationEndpoint = try container.decode(URL.self, forKey: .authorizationEndpoint)
            tokenEndpoint = try container.decode(URL.self, forKey: .tokenEndpoint)
            introspectionEndpoint = try container.decode(URL.self, forKey: .introspectionEndpoint)
            introspectionEndpointAuthMethodsSupported = try container.decodeIfPresent([TokenAuthenticationMethod].self, forKey: .introspectionEndpointAuthMethodsSupported) ?? []
            revocationEndpoint = try container.decodeIfPresent(URL.self, forKey: .revocationEndpoint)
            revocationEndpointAuthMethodsSupported = try container.decodeIfPresent([TokenAuthenticationMethod].self, forKey: .revocationEndpointAuthMethodsSupported) ?? [.none]
            scopesSupported = try container.decodeIfPresent([String].self, forKey: .scopesSupported) ?? []
            responseTypesSupported = try container.decodeIfPresent([AuthorizationResponseType].self, forKey: .responseTypesSupported) ?? [.code]
            grantTypesSupported = try container.decodeIfPresent([GrantType].self, forKey: .grantTypesSupported) ?? [.authorizationCode]
            serviceDocumentation = try container.decodeIfPresent(URL.self, forKey: .serviceDocumentation)
            codeChallengeMethodsSupported = try container.decode([PKCEChallengeMethod].self, forKey: .codeChallengeMethodsSupported)
            authorizationResponseISSParameterSupported = try container.decodeIfPresent(Bool.self, forKey: .authorizationResponseISSParameterSupported) ?? false
            userinfoEndpoint = try container.decodeIfPresent(URL.self, forKey: .userinfoEndpoint)
        }

        enum CodingKeys: String, CodingKey {
            case issuer
            case authorizationEndpoint = "authorization_endpoint"
            case tokenEndpoint = "token_endpoint"
            case introspectionEndpoint = "introspection_endpoint"
            case introspectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported"
            case revocationEndpoint = "revocation_endpoint"
            case revocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported"
            case scopesSupported = "scopes_supported"
            case responseTypesSupported = "response_types_supported"
            case grantTypesSupported = "grant_types_supported"
            case serviceDocumentation = "service_documentation"
            case codeChallengeMethodsSupported = "code_challenge_methods_supported"
            case authorizationResponseISSParameterSupported = "authorization_response_iss_parameter_supported"
            case userinfoEndpoint = "userinfo_endpoint"
        }
    }

    struct LegacyDiscoveryResponse {
        public let authorizationEndpoint: URL
        public let tokenEndpoint: URL
    }
}
