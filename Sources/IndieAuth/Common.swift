//
//  Common.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation
import Fuzi

// MARK: - URL

public extension IndieAuth {
    // TODO: static func preprocess(urlString _: String) -> URL {}

    static func validate(_ url: URL, with rules: [URLRule]) -> [IndieAuthError] {
        rules.compactMap { rule in
            rule.conformed(by: url) ? nil : IndieAuthError.invalidURL(urlString: url.absoluteString, type: nil, reason: rule)
        }
    }
}

// MARK: - Network

public extension IndieAuth {
    @available(iOS 15.0, *)
    static func load(_ url: URL, using session: URLSession? = nil) async throws -> (Data, HTTPURLResponse) {
        let session = session ?? URLSession(configuration: .default)
        let (data, response) = try await session.data(from: url)
        return try validateURLResult(from: url.absoluteString, data: data, response: response)
    }

    static func load(
        _ url: URL,
        using session: URLSession? = nil,
        completionHandler: @escaping @Sendable (Data?, HTTPURLResponse?, Error?) -> Void
    ) {
        let session = session ?? URLSession(configuration: .default)
        session.dataTask(with: url) { data, response, error in
            validateURLResult(from: url.absoluteString, data: data, response: response, error: error) {
                completionHandler($0, $1, $2)
            }
        }
    }

    @available(iOS 15.0, *)
    static func send(_ request: URLRequest, using session: URLSession? = nil) async throws -> (Data, HTTPURLResponse) {
        let session = session ?? URLSession(configuration: .default)
        let (data, response) = try await session.data(for: request)
        return try validateURLResult(from: request.url?.absoluteString ?? "", data: data, response: response)
    }

    static func send(
        _ request: URLRequest,
        using session: URLSession? = nil,
        completionHandler: @escaping @Sendable (Data?, HTTPURLResponse?, Error?) -> Void
    ) {
        let session = session ?? URLSession(configuration: .default)
        session.dataTask(with: request) { data, response, error in
            validateURLResult(from: request.url?.absoluteString ?? "", data: data, response: response, error: error) {
                completionHandler($0, $1, $2)
            }
        }
    }

    private static func validateURLResult(from urlString: String, data: Data, response: URLResponse) throws -> (Data, HTTPURLResponse) {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw IndieAuthError.invalidHTTPResponse(urlString: urlString, statusCode: nil)
        }
        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw IndieAuthError.invalidHTTPResponse(urlString: urlString, statusCode: httpResponse.statusCode)
        }
        return (data, httpResponse)
    }

    private static func validateURLResult(
        from urlString: String,
        data: Data?,
        response: URLResponse?,
        error: Error?,
        completionHandler: @escaping @Sendable (Data?, HTTPURLResponse?, Error?) -> Void
    ) {
        if let httpResponse = response as? HTTPURLResponse {
            if (200 ... 299).contains(httpResponse.statusCode) {
                completionHandler(data, httpResponse, error)
            } else {
                let error = error ?? IndieAuthError.invalidHTTPResponse(urlString: urlString, statusCode: httpResponse.statusCode)
                completionHandler(data, httpResponse, error)
            }
        } else {
            let error = error ?? IndieAuthError.invalidHTTPResponse(urlString: urlString, statusCode: nil)
            completionHandler(data, nil, error)
        }
    }
}

public extension HTMLDocument {
    func search(link relation: String) -> [URL] {
        guard let head = firstChild(xpath: "/html/head") else { return [] }

        let tags = head.xpath("link[@rel='\(relation)']")
        return tags
            .compactMap { $0.attr("href") }
            .compactMap { URL(string: $0) }
    }
}
