//
//  Constants.swift
//
//
//  Created by Weiyi Kong on 8/8/2023.
//

import Foundation

public enum IndieAuth {
    // MARK: - Configurable

    // Required

    public static var clientID: URL!
    public static var redirectURI: URL!

    // Optional

    public static var stateLength: Int = 20
    public static var codeVerifierLength: Int? = 128

    // MARK: - Constant

    internal static let codeVerifierLengthRange = 43 ... 128
    internal static let codeVerifierCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    internal static let stateCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
}
