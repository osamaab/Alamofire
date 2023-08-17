//
//  SessionDelegate.swift
//
//  Copyright (c) 2014-2018 Alamofire Software Foundation (http://alamofire.org/)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

struct IdentityAndTrust {
  var identityRef: SecIdentity
  var trust: SecTrust
  var certificates: [SecCertificate]
 }

// Method to extract the identity, certificate chain and trust

func extractIdentity(certData: NSData, certPassword: String) -> IdentityAndTrust? {
  
  var identityAndTrust: IdentityAndTrust?
  var securityStatus: OSStatus = errSecSuccess
  
  var items: CFArray?
  let certOptions: Dictionary = [kSecImportExportPassphrase as String : certPassword]
  securityStatus = SecPKCS12Import(certData, certOptions as CFDictionary, &items)
  if securityStatus == errSecSuccess {
    let certificateItems: CFArray = items! as CFArray
    let certItemsArray: Array = certificateItems as Array
    let dict: AnyObject? = certItemsArray.first
    
    if let certificateDict: Dictionary = dict as? Dictionary<String, AnyObject> {
      
      // get the identity
      let identityPointer: AnyObject? = certificateDict["identity"]
      let secIdentityRef: SecIdentity = identityPointer as! SecIdentity
      
      // get the trust
      let trustPointer: AnyObject? = certificateDict["trust"]
      let trustRef: SecTrust = trustPointer as! SecTrust
      
      // get the certificate chain
      var certRef: SecCertificate? // <- write on
      SecIdentityCopyCertificate(secIdentityRef, &certRef)
      var certificateArray = [SecCertificate]()
      certificateArray.append(certRef! as SecCertificate)
      
      let count = SecTrustGetCertificateCount(trustRef)
      if count > 1 {
        for i in 1..<count {
          if let cert = SecTrustGetCertificateAtIndex(trustRef, i) {
            certificateArray.append(cert)
          }
        }
      }
      
      identityAndTrust = IdentityAndTrust(identityRef: secIdentityRef, trust: trustRef, certificates: certificateArray)
    }
  }
  
  return identityAndTrust
}


public class PKCS12 {
  var label:String?
  var keyID:NSData?
  var trust:SecTrust?
  var certChain:[SecTrust]?
  var identity:SecIdentity?

  public init(PKCS12Data:NSData,password:String)
  {
    let importPasswordOption:NSDictionary = [kSecImportExportPassphrase as NSString:password]
    var items : CFArray?
    let secError:OSStatus = SecPKCS12Import(PKCS12Data, importPasswordOption, &items)
    
    guard secError == errSecSuccess else {
      if secError == errSecAuthFailed {
        NSLog("ERROR: SecPKCS12Import returned errSecAuthFailed. Incorrect password?")
      }
      fatalError("SecPKCS12Import returned an error trying to import PKCS12 data")
    }
    
    guard let theItemsCFArray = items else { fatalError()  }
    let theItemsNSArray:NSArray = theItemsCFArray as NSArray
    guard let dictArray = theItemsNSArray as? [[String:AnyObject]] else { fatalError() }
    
    func f<T>(key:CFString) -> T? {
      for d in dictArray {
        if let v = d[key as String] as? T {
          return v
        }
        if(key == kSecImportItemLabel || key == kSecImportItemKeyID){
          var cert: SecCertificate?
          if let cd = d["identity"]{
            SecIdentityCopyCertificate(cd as! SecIdentity, &cert)
            if let certData = cert{
              if(key == kSecImportItemLabel){
                let lblDer = SecCertificateCopySubjectSummary(certData)
                if let lblVallue = lblDer {
                  return lblVallue as? T
                }
              }
              var key: SecKey?
              SecIdentityCopyPrivateKey(cd as! SecIdentity, &key)
              if let keyData = key{
                let keyDict = SecKeyCopyAttributes(keyData)
                if let keyDictUnwrapped = keyDict, let keyValue = (keyDictUnwrapped as NSDictionary)["v_Data"] as? NSData {
                  return keyValue as? T
                }
              }
              
            }
            
          }
          
        }
      }
      return nil
    }
    self.label = f(key: kSecImportItemLabel)
    self.keyID = f(key: kSecImportItemKeyID)
    self.trust = f(key: kSecImportItemTrust)
    self.certChain = f(key: kSecImportItemCertChain)
    self.identity =  f(key: kSecImportItemIdentity)
  }
}

extension URLCredential {
  public convenience init?(PKCS12 thePKCS12:PKCS12) {
    if let identity = thePKCS12.identity {
      self.init(
        identity: identity,
        certificates: thePKCS12.certChain,
        persistence: URLCredential.Persistence.forSession)
    }
    else { return nil }
  }
}



/// Class which implements the various `URLSessionDelegate` methods to connect various Alamofire features.
open class SessionDelegate: NSObject {
    private let fileManager: FileManager

    weak var stateProvider: SessionStateProvider?
    var eventMonitor: EventMonitor?

    /// Creates an instance from the given `FileManager`.
    ///
    /// - Parameter fileManager: `FileManager` to use for underlying file management, such as moving downloaded files.
    ///                          `.default` by default.
    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    /// Internal method to find and cast requests while maintaining some integrity checking.
    ///
    /// - Parameters:
    ///   - task: The `URLSessionTask` for which to find the associated `Request`.
    ///   - type: The `Request` subclass type to cast any `Request` associate with `task`.
    func request<R: Request>(for task: URLSessionTask, as type: R.Type) -> R? {
        guard let provider = stateProvider else {
            assertionFailure("StateProvider is nil.")
            return nil
        }

        return provider.request(for: task) as? R
    }
}

/// Type which provides various `Session` state values.
protocol SessionStateProvider: AnyObject {
    var serverTrustManager: ServerTrustManager? { get }
    var redirectHandler: RedirectHandler? { get }
    var cachedResponseHandler: CachedResponseHandler? { get }

    func request(for task: URLSessionTask) -> Request?
    func didGatherMetricsForTask(_ task: URLSessionTask)
    func didCompleteTask(_ task: URLSessionTask, completion: @escaping () -> Void)
    func credential(for task: URLSessionTask, in protectionSpace: URLProtectionSpace) -> URLCredential?
    func cancelRequestsForSessionInvalidation(with error: Error?)
}

// MARK: URLSessionDelegate

extension SessionDelegate: URLSessionDelegate {
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
      if let localCertPath = Bundle.main.url(forResource: "cert", withExtension: "p12"),
         let localCertData = try?  Data(contentsOf: localCertPath)
      {
        let certificatePassword = "2475"
        let identityAndTrust:IdentityAndTrust = extractIdentity(certData: localCertData as NSData, certPassword: certificatePassword)!
        
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
          
            let urlCredential: URLCredential = URLCredential(PKCS12: PKCS12(PKCS12Data: localCertData as NSData, password: certificatePassword))!
          completionHandler(URLSession.AuthChallengeDisposition.useCredential, urlCredential);
          
          return
        }
          
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            let urlCredential: URLCredential = URLCredential(PKCS12: PKCS12(PKCS12Data: localCertData as NSData, password: certificatePassword))!
          completionHandler(URLSession.AuthChallengeDisposition.useCredential, urlCredential);
          return
        }
        completionHandler (URLSession.AuthChallengeDisposition.performDefaultHandling, Optional.none);
        return
      }
      
      challenge.sender?.cancel(challenge)
      completionHandler(URLSession.AuthChallengeDisposition.rejectProtectionSpace, nil)
    }
    
    open func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        eventMonitor?.urlSession(session, didBecomeInvalidWithError: error)

        stateProvider?.cancelRequestsForSessionInvalidation(with: error)
    }
}

// MARK: URLSessionTaskDelegate

extension SessionDelegate: URLSessionTaskDelegate {
    /// Result of a `URLAuthenticationChallenge` evaluation.
    typealias ChallengeEvaluation = (disposition: URLSession.AuthChallengeDisposition, credential: URLCredential?, error: AFError?)

    open func urlSession(_ session: URLSession,
                         task: URLSessionTask,
                         didReceive challenge: URLAuthenticationChallenge,
                         completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        eventMonitor?.urlSession(session, task: task, didReceive: challenge)

        let evaluation: ChallengeEvaluation
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodHTTPBasic, NSURLAuthenticationMethodHTTPDigest, NSURLAuthenticationMethodNTLM,
             NSURLAuthenticationMethodNegotiate:
            evaluation = attemptCredentialAuthentication(for: challenge, belongingTo: task)
        #if !(os(Linux) || os(Windows))
        case NSURLAuthenticationMethodServerTrust:
            evaluation = attemptServerTrustAuthentication(with: challenge)
        case NSURLAuthenticationMethodClientCertificate:
            evaluation = attemptCredentialAuthentication(for: challenge, belongingTo: task)
        #endif
        default:
            evaluation = (.performDefaultHandling, nil, nil)
        }

        if let error = evaluation.error {
            stateProvider?.request(for: task)?.didFailTask(task, earlyWithError: error)
        }

        completionHandler(evaluation.disposition, evaluation.credential)
    }

    #if !(os(Linux) || os(Windows))
    /// Evaluates the server trust `URLAuthenticationChallenge` received.
    ///
    /// - Parameter challenge: The `URLAuthenticationChallenge`.
    ///
    /// - Returns:             The `ChallengeEvaluation`.
    func attemptServerTrustAuthentication(with challenge: URLAuthenticationChallenge) -> ChallengeEvaluation {
        let host = challenge.protectionSpace.host

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            return (.performDefaultHandling, nil, nil)
        }

        do {
            guard let evaluator = try stateProvider?.serverTrustManager?.serverTrustEvaluator(forHost: host) else {
                return (.performDefaultHandling, nil, nil)
            }

            try evaluator.evaluate(trust, forHost: host)

            return (.useCredential, URLCredential(trust: trust), nil)
        } catch {
            return (.cancelAuthenticationChallenge, nil, error.asAFError(or: .serverTrustEvaluationFailed(reason: .customEvaluationFailed(error: error))))
        }
    }
    #endif

    /// Evaluates the credential-based authentication `URLAuthenticationChallenge` received for `task`.
    ///
    /// - Parameters:
    ///   - challenge: The `URLAuthenticationChallenge`.
    ///   - task:      The `URLSessionTask` which received the challenge.
    ///
    /// - Returns:     The `ChallengeEvaluation`.
    func attemptCredentialAuthentication(for challenge: URLAuthenticationChallenge,
                                         belongingTo task: URLSessionTask) -> ChallengeEvaluation {
        guard challenge.previousFailureCount == 0 else {
            return (.rejectProtectionSpace, nil, nil)
        }

        guard let credential = stateProvider?.credential(for: task, in: challenge.protectionSpace) else {
            return (.performDefaultHandling, nil, nil)
        }

        return (.useCredential, credential, nil)
    }

    open func urlSession(_ session: URLSession,
                         task: URLSessionTask,
                         didSendBodyData bytesSent: Int64,
                         totalBytesSent: Int64,
                         totalBytesExpectedToSend: Int64) {
        eventMonitor?.urlSession(session,
                                 task: task,
                                 didSendBodyData: bytesSent,
                                 totalBytesSent: totalBytesSent,
                                 totalBytesExpectedToSend: totalBytesExpectedToSend)

        stateProvider?.request(for: task)?.updateUploadProgress(totalBytesSent: totalBytesSent,
                                                                totalBytesExpectedToSend: totalBytesExpectedToSend)
    }

    open func urlSession(_ session: URLSession,
                         task: URLSessionTask,
                         needNewBodyStream completionHandler: @escaping (InputStream?) -> Void) {
        eventMonitor?.urlSession(session, taskNeedsNewBodyStream: task)

        guard let request = request(for: task, as: UploadRequest.self) else {
            assertionFailure("needNewBodyStream did not find UploadRequest.")
            completionHandler(nil)
            return
        }

        completionHandler(request.inputStream())
    }

    open func urlSession(_ session: URLSession,
                         task: URLSessionTask,
                         willPerformHTTPRedirection response: HTTPURLResponse,
                         newRequest request: URLRequest,
                         completionHandler: @escaping (URLRequest?) -> Void) {
        eventMonitor?.urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: request)

        if let redirectHandler = stateProvider?.request(for: task)?.redirectHandler ?? stateProvider?.redirectHandler {
            redirectHandler.task(task, willBeRedirectedTo: request, for: response, completion: completionHandler)
        } else {
            completionHandler(request)
        }
    }

    open func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        eventMonitor?.urlSession(session, task: task, didFinishCollecting: metrics)

        stateProvider?.request(for: task)?.didGatherMetrics(metrics)

        stateProvider?.didGatherMetricsForTask(task)
    }

    open func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        eventMonitor?.urlSession(session, task: task, didCompleteWithError: error)

        let request = stateProvider?.request(for: task)

        stateProvider?.didCompleteTask(task) {
            request?.didCompleteTask(task, with: error.map { $0.asAFError(or: .sessionTaskFailed(error: $0)) })
        }
    }

    @available(macOS 10.13, iOS 11.0, tvOS 11.0, watchOS 4.0, *)
    open func urlSession(_ session: URLSession, taskIsWaitingForConnectivity task: URLSessionTask) {
        eventMonitor?.urlSession(session, taskIsWaitingForConnectivity: task)
    }
}

// MARK: URLSessionDataDelegate

extension SessionDelegate: URLSessionDataDelegate {
    open func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        eventMonitor?.urlSession(session, dataTask: dataTask, didReceive: data)

        if let request = request(for: dataTask, as: DataRequest.self) {
            request.didReceive(data: data)
        } else if let request = request(for: dataTask, as: DataStreamRequest.self) {
            request.didReceive(data: data)
        } else {
            assertionFailure("dataTask did not find DataRequest or DataStreamRequest in didReceive")
            return
        }
    }

    open func urlSession(_ session: URLSession,
                         dataTask: URLSessionDataTask,
                         willCacheResponse proposedResponse: CachedURLResponse,
                         completionHandler: @escaping (CachedURLResponse?) -> Void) {
        eventMonitor?.urlSession(session, dataTask: dataTask, willCacheResponse: proposedResponse)

        if let handler = stateProvider?.request(for: dataTask)?.cachedResponseHandler ?? stateProvider?.cachedResponseHandler {
            handler.dataTask(dataTask, willCacheResponse: proposedResponse, completion: completionHandler)
        } else {
            completionHandler(proposedResponse)
        }
    }
}

// MARK: URLSessionDownloadDelegate

extension SessionDelegate: URLSessionDownloadDelegate {
    open func urlSession(_ session: URLSession,
                         downloadTask: URLSessionDownloadTask,
                         didResumeAtOffset fileOffset: Int64,
                         expectedTotalBytes: Int64) {
        eventMonitor?.urlSession(session,
                                 downloadTask: downloadTask,
                                 didResumeAtOffset: fileOffset,
                                 expectedTotalBytes: expectedTotalBytes)
        guard let downloadRequest = request(for: downloadTask, as: DownloadRequest.self) else {
            assertionFailure("downloadTask did not find DownloadRequest.")
            return
        }

        downloadRequest.updateDownloadProgress(bytesWritten: fileOffset,
                                               totalBytesExpectedToWrite: expectedTotalBytes)
    }

    open func urlSession(_ session: URLSession,
                         downloadTask: URLSessionDownloadTask,
                         didWriteData bytesWritten: Int64,
                         totalBytesWritten: Int64,
                         totalBytesExpectedToWrite: Int64) {
        eventMonitor?.urlSession(session,
                                 downloadTask: downloadTask,
                                 didWriteData: bytesWritten,
                                 totalBytesWritten: totalBytesWritten,
                                 totalBytesExpectedToWrite: totalBytesExpectedToWrite)
        guard let downloadRequest = request(for: downloadTask, as: DownloadRequest.self) else {
            assertionFailure("downloadTask did not find DownloadRequest.")
            return
        }

        downloadRequest.updateDownloadProgress(bytesWritten: bytesWritten,
                                               totalBytesExpectedToWrite: totalBytesExpectedToWrite)
    }

    open func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        eventMonitor?.urlSession(session, downloadTask: downloadTask, didFinishDownloadingTo: location)

        guard let request = request(for: downloadTask, as: DownloadRequest.self) else {
            assertionFailure("downloadTask did not find DownloadRequest.")
            return
        }

        let (destination, options): (URL, DownloadRequest.Options)
        if let response = request.response {
            (destination, options) = request.destination(location, response)
        } else {
            // If there's no response this is likely a local file download, so generate the temporary URL directly.
            (destination, options) = (DownloadRequest.defaultDestinationURL(location), [])
        }

        eventMonitor?.request(request, didCreateDestinationURL: destination)

        do {
            if options.contains(.removePreviousFile), fileManager.fileExists(atPath: destination.path) {
                try fileManager.removeItem(at: destination)
            }

            if options.contains(.createIntermediateDirectories) {
                let directory = destination.deletingLastPathComponent()
                try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            }

            try fileManager.moveItem(at: location, to: destination)

            request.didFinishDownloading(using: downloadTask, with: .success(destination))
        } catch {
            request.didFinishDownloading(using: downloadTask, with: .failure(.downloadedFileMoveFailed(error: error,
                                                                                                       source: location,
                                                                                                       destination: destination)))
        }
    }
}
