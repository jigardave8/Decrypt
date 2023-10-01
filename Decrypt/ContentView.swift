//
//  ContentView.swift
//  Decrypt
//
//  Created by Jigar on 01/10/23.
//

import SwiftUI
import CommonCrypto
import MobileCoreServices

class DocumentPickerDelegate: NSObject, UIDocumentPickerDelegate {
    var parent: ContentView

    init(parent: ContentView) {
        self.parent = parent
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        if let selectedFile = urls.first {
            parent.updateSelectedFile(selectedFile)
        }
    }
}


struct ContentView: View {
    @State private var selectedFile: URL?
    @State private var password: String = ""
    @State private var documentPickerDelegate: DocumentPickerDelegate?


    var body: some View {
        NavigationView {
            VStack {
                Button("Select File") {
                    #if os(iOS)
                    let documentPicker = UIDocumentPickerViewController(documentTypes: [String(kUTTypeData)], in: .import)
                    documentPickerDelegate = DocumentPickerDelegate(parent: self)
                    documentPicker.delegate = documentPickerDelegate
                    UIApplication.shared.windows.first?.rootViewController?.present(documentPicker, animated: true, completion: nil)
                    #endif
                }
                .padding()

                if let selectedFile = selectedFile {
                    Text("Selected file: \(selectedFile.lastPathComponent)")
                } else {
                    Text("Select a file to process")
                }

                TextField("Password", text: $password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())

                HStack {
                    Button("Encrypt") {
                        encryptFile(selectedFile, password: password)
                    }
                    .padding()

                    Button("Decrypt") {
                        decryptFile(selectedFile, password: password)
                    }
                    .padding()
                }
            }
            .padding()
            .navigationTitle("File Encryptor")
        }
    }
    func updateSelectedFile(_ file: URL?) {
          selectedFile = file
      }

    private func encryptFile(_ file: URL?, password: String) {
        guard let file = file else { return }

        do {
            let data = try Data(contentsOf: file)
            let passwordData = Data(password.utf8)
            let encryptedData = try CCCryptorWrapper.encrypt(data: data, key: passwordData)

            let encryptedFile = file.deletingPathExtension().appendingPathExtension("encrypted")
            try encryptedData.write(to: encryptedFile)

            #if os(iOS)
            UIApplication.shared.open(encryptedFile, options: [:], completionHandler: nil)
            #elseif os(macOS)
            NSWorkspace.shared.open(encryptedFile)
            #endif
        } catch {
            print(error.localizedDescription)
        }
    }

    private func decryptFile(_ file: URL?, password: String) {
        guard let file = file else { return }

        do {
            let data = try Data(contentsOf: file)
            let passwordData = Data(password.utf8)
            let decryptedData = try CCCryptorWrapper.decrypt(data: data, key: passwordData)

            let decryptedFile = file.deletingPathExtension().appendingPathExtension("decrypted")
            try decryptedData.write(to: decryptedFile)

            #if os(iOS)
            UIApplication.shared.open(decryptedFile, options: [:], completionHandler: nil)
            #elseif os(macOS)
            NSWorkspace.shared.open(decryptedFile)
            #endif
        } catch {
            print(error.localizedDescription)
        }
    }
}

class CCCryptorWrapper {
    static func encrypt(data: Data, key: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesEncrypted = 0

        let status = key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    UInt32(kCCEncrypt),
                    UInt32(kCCAlgorithmAES),
                    UInt32(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count,
                    nil,
                    dataBytes.baseAddress, data.count,
                    &buffer, bufferSize,
                    &numBytesEncrypted
                )
            }
        }

        guard status == kCCSuccess else {
            throw NSError(domain: "com.example.app", code: 1, userInfo: nil)
        }

        return Data(buffer.prefix(numBytesEncrypted))
    }

    static func decrypt(data: Data, key: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesDecrypted = 0

        let status = key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    UInt32(kCCDecrypt),
                    UInt32(kCCAlgorithmAES),
                    UInt32(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count,
                    nil,
                    dataBytes.baseAddress, data.count,
                    &buffer, bufferSize,
                    &numBytesDecrypted
                )
            }
        }

        guard status == kCCSuccess else {
            throw NSError(domain: "com.example.app", code: 1, userInfo: nil)
        }

        return Data(buffer.prefix(numBytesDecrypted))
    }
}

