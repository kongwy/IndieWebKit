//
//  Discovery.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation
import Fuzi

public extension IndieAuth {
    @available(iOS 15.0, *)
    static func discover(_ url: URL, using session: URLSession? = nil) async throws -> DiscoveryResponse? {
        // TODO: Validate URL

        let (data, _) = try await load(url, using: session)
        let document = try HTMLDocument(data: data)
        return try await discover(document)
    }

    static func discover(
        _ url: URL,
        using session: URLSession? = nil,
        completionHandler: @escaping (DiscoveryResponse?, HTTPURLResponse?, Error?) -> Void
    ) {
        load(url, using: session) { data, response, err in
            guard let data, err == nil else {
                completionHandler(nil, response, err)
                return
            }
            do {
                let document = try HTMLDocument(data: data)
                discover(document, completionHandler: completionHandler)
            } catch {
                completionHandler(nil, response, error)
            }
        }
    }

    @available(iOS 15.0, *)
    static func discover(_ document: HTMLDocument, using session: URLSession? = nil) async throws -> DiscoveryResponse? {
        guard let metadataEndpoint = document.search(link: "indieauth-metadata").first else { return nil }
        let (data, _) = try await load(metadataEndpoint, using: session)
        let metadata = try JSONDecoder().decode(DiscoveryResponse.self, from: data)
        return metadata
    }

    static func discover(
        _ document: HTMLDocument,
        using session: URLSession? = nil,
        completionHandler: @escaping (DiscoveryResponse?, HTTPURLResponse?, Error?) -> Void
    ) {
        guard let metadataEndpoint = document.search(link: "indieauth-metadata").first else {
            completionHandler(nil, nil, IndieAuthError.metadataNotFound)
            return
        }
        load(metadataEndpoint, using: session) { data, response, err in
            guard let data, err == nil else {
                completionHandler(nil, response, err)
                return
            }
            do {
                let metadata = try JSONDecoder().decode(DiscoveryResponse.self, from: data)
                completionHandler(metadata, response, err)
            } catch {
                completionHandler(nil, response, error)
            }
        }
    }

    @available(iOS 15.0, *)
    static func discover(legacy url: URL, using session: URLSession? = nil) async throws -> LegacyDiscoveryResponse? {
        // TODO: Validate URL

        let (data, _) = try await load(url, using: session)
        let document = try HTMLDocument(data: data)
        return discover(legacy: document)
    }

    static func discover(
        legacy url: URL,
        using session: URLSession? = nil,
        completionHandler: @escaping (LegacyDiscoveryResponse?, HTTPURLResponse?, Error?) -> Void
    ) {
        load(url, using: session) { data, response, err in
            guard let data, err == nil else {
                completionHandler(nil, response, err)
                return
            }
            do {
                let document = try HTMLDocument(data: data)
                guard let legacyDiscovery = discover(legacy: document) else {
                    completionHandler(nil, response, IndieAuthError.metadataNotFound)
                    return
                }
                completionHandler(legacyDiscovery, response, err)
            } catch {
                completionHandler(nil, response, error)
            }
        }
    }

    static func discover(legacy document: HTMLDocument) -> LegacyDiscoveryResponse? {
        guard let authorizationEndpoint = document.search(link: "authorization_endpoint").first,
              let tokenEndpoint = document.search(link: "token_endpoint").first else { return nil }
        return LegacyDiscoveryResponse(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint
        )
    }
}
