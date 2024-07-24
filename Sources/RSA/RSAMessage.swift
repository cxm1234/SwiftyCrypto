//
//  RSAMessage.swift
//  SwiftyCrypto
//
//  Created by Shuo Wang on 2018/1/16.
//  Copyright © 2018年 Yufu. All rights reserved.
//

import Foundation

public class RSAMessage: Message {
    public var data: Data
    
    public var base64String: String
    
    public required init(data: Data) {
        self.data = data
        self.base64String = data.base64EncodedString()
    }
    
    public required convenience init(base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyCryptoError.invalidBase64String
        }
        self.init(data: data)
    }
    
    public func sign(signingKey: RSAKey, digestType: RSASignature.DigestType) throws -> RSASignature {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(signingKey.key, digestType.algorithm, data as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return RSASignature(data: signature as Data)
    }
    
    public func verify(verifyKey: RSAKey, signature: RSASignature, digestType: RSASignature.DigestType) throws -> Bool {
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(verifyKey.key, digestType.algorithm, data as CFData, signature.data as CFData, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        return isValid
    }
    
    func digest(digestType: RSASignature.DigestType) -> Data {
        
        let digest: Data
        
        switch digestType {
        case .sha1:
            digest = (data as NSData).sha1
        case .sha224:
            digest = (data as NSData).sha224
        case .sha256:
            digest = (data as NSData).sha256
        case .sha384:
            digest = (data as NSData).sha384
        case .sha512:
            digest = (data as NSData).sha512
        }
        
        return digest
    }
}
