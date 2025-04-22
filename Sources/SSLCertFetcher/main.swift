//
//  main.swift
//  SSLCertFetcher
//
//  Created by Arie Mobile Dev on 22/04/2025.
//

import Foundation
import Security

class CertificateFetcher: NSObject, URLSessionDelegate {
    private let host: String
    private let port: Int
    private let semaphore = DispatchSemaphore(value: 0)

    init(host: String, port: Int = 443) {
        self.host = host
        self.port = port
    }

    func run() {
        guard let url = URL(string: "https://\(host):\(port)") else {
            print("❌ Invalid URL")
            return
        }

        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: url) { _, _, error in
            if let error = error {
                print("❌ Request error: \(error)")
            }
            self.semaphore.signal()
        }

        task.resume()
        semaphore.wait()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let certificate = certChain.first else {
            print("❌ Failed to get certificate chain")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }


        let certData = SecCertificateCopyData(certificate) as Data
        let fileBase = host.replacingOccurrences(of: ".", with: "_")

        let currentDir = FileManager.default.currentDirectoryPath
        let derPath = "\(currentDir)/\(fileBase).cer"
        let pemPath = "\(currentDir)/\(fileBase).pem"

        do {
            try certData.write(to: URL(fileURLWithPath: derPath))
            print("✅ DER file saved at: \(derPath)")
        } catch {
            print("❌ Failed to save .cer: \(error)")
        }

        savePEM(from: certData, to: pemPath)

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
        semaphore.signal()
    }

    func savePEM(from data: Data, to filename: String) {
        let base64 = data.base64EncodedString(options: [.lineLength64Characters])
        let pem = """
        -----BEGIN CERTIFICATE-----
        \(base64)
        -----END CERTIFICATE-----
        """

        do {
            try pem.write(to: URL(fileURLWithPath: filename), atomically: true, encoding: .utf8)
            print("✅ PEM file saved at: \(filename)")
        } catch {
            print("❌ Failed to save .pem: \(error)")
        }
    }
}

// MARK: - Main
let args = CommandLine.arguments
guard args.count > 1 else {
    print("Usage: certfetcher <hostname>")
    exit(1)
}

let host = args[1]
let fetcher = CertificateFetcher(host: host)
fetcher.run()
