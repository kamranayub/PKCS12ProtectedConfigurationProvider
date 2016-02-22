/*
Microsoft Limited Permissive License (Ms-LPL)

This license governs use of the accompanying software. If you use the software, you accept this license. If you do not accept the license, do not use the software.

1. Definitions

The terms “reproduce,” “reproduction,” “derivative works,” and “distribution” have the same meaning here as under U.S. copyright law.
A “contribution” is the original software, or any additions or changes to the software.
A “contributor” is any person that distributes its contribution under this license.
“Licensed patents” are a contributor’s patent claims that read directly on its contribution.

2. Grant of Rights

(A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create.
(B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.

3. Conditions and Limitations

(A) No Trademark License- This license does not grant you rights to use any contributors’ name, logo, or trademarks.
(B) If you bring a patent claim against any contributor over patents that you claim are infringed by the software, your patent license from such contributor to the software ends automatically.
(C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and attribution notices that are present in the software.
(D) If you distribute any portion of the software in source code form, you may do so only under this license by including a complete copy of this license with your distribution. If you distribute any portion of the software in compiled or object code form, you may only do so under a license that complies with this license.
(E) The software is licensed “as-is.” You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement.
(F) Platform Limitation- The licenses granted in sections 2(A) & 2(B) extend only to the software or derivative works that you create that run on a Microsoft Windows operating system product.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Collections.Specialized;


namespace Pkcs12ProtectedConfigurationProvider
{
    public class Pkcs12ProtectedConfigurationProvider : ProtectedConfigurationProvider
    {
        private string thumbprint;
        private StoreLocation storeLocation = StoreLocation.LocalMachine;

        /// <summary>
        /// Initializes the provider with default settings.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="configurationValues">A NameValueCollection collection of values to use 
        /// when initializing the object. This must include a thumbprint value for the thumbprint of 
        /// the certificate used to encrypt the configuration section. 
        /// </param>
        public override void Initialize(string name, NameValueCollection configurationValues)
        {
            base.Initialize(name, configurationValues);
            if (configurationValues["thumbprint"] == null || configurationValues["thumbprint"].Length == 0)
            {
                throw new ApplicationException("thumbprint not set in the configuration");
            }

            if (configurationValues["storeLocation"] != null)
            {
                Enum.TryParse(configurationValues["storeLocation"], out storeLocation);
            }

            this.thumbprint = configurationValues["thumbprint"];
        }

        /// <summary>
        /// Decrypts the XML node passed to it.
        /// </summary>
        /// <param name="encryptedNode">The XmlNode to decrypt.</param>
        /// <returns></returns>
        public override XmlNode Decrypt(XmlNode encryptedNode)
        {
            XmlDocument document = new XmlDocument();
            EncryptedXml xml = null;

            // Get the RSA private key.  This key will decrypt
            // a symmetric key that was embedded in the XML document.
            RSACryptoServiceProvider cryptoServiceProvider = this.GetCryptoServiceProvider(false);
            document.PreserveWhitespace = true;
            document.LoadXml(encryptedNode.OuterXml);
            xml = new EncryptedXml(document);

            // Add a key-name mapping.This method can only decrypt documents
            // that present the specified key name.
            xml.AddKeyNameMapping("rsaKey", cryptoServiceProvider);
            xml.DecryptDocument();
            cryptoServiceProvider.Clear();
            return document.DocumentElement;
        }

        /// <summary>
        /// Encrypts the XML node passed to it. 
        /// </summary>
        /// <param name="node">The XmlNode to encrypt.</param>
        /// <returns></returns>
        public override XmlNode Encrypt(XmlNode node)
        {
            // Get the RSA public key to encrypt the node. This key will encrypt
            // a symmetric key, which will then be encryped in the XML document.
            RSACryptoServiceProvider cryptoServiceProvider = this.GetCryptoServiceProvider(true);

            // Create an XML document and load the node to be encrypted in it. 
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml("<Data>" + node.OuterXml + "</Data>");

            // Create a new instance of the EncryptedXml class
            // and use it to encrypt the XmlElement with the
            // a new random symmetric key.
            EncryptedXml xml = new EncryptedXml(document);
            XmlElement documentElement = document.DocumentElement;
            SymmetricAlgorithm symmetricAlgorithm = new RijndaelManaged();

            // Create a 192 bit random key.
            symmetricAlgorithm.Key = this.GetRandomKey();
            symmetricAlgorithm.GenerateIV();
            symmetricAlgorithm.Padding = PaddingMode.PKCS7;

            byte[] buffer = xml.EncryptData(documentElement, symmetricAlgorithm, true);

            // Construct an EncryptedData object and populate
            // it with the encryption information.
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the
            // receiver knows which algorithm to use for decryption.
            encryptedData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES192Url);
            encryptedData.KeyInfo = new KeyInfo();

            // Encrypt the session key and add it to an EncryptedKey element.
            EncryptedKey encryptedKey = new EncryptedKey();
            encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            encryptedKey.KeyInfo = new KeyInfo();
            encryptedKey.CipherData = new CipherData();
            encryptedKey.CipherData.CipherValue = EncryptedXml.EncryptKey(symmetricAlgorithm.Key, cryptoServiceProvider, false);
            KeyInfoName clause = new KeyInfoName();
            clause.Value = "rsaKey";

            // Add the encrypted key to the EncryptedData object.
            encryptedKey.KeyInfo.AddClause(clause);
            KeyInfoEncryptedKey key2 = new KeyInfoEncryptedKey(encryptedKey);
            encryptedData.KeyInfo.AddClause(key2);
            encryptedData.CipherData = new CipherData();
            encryptedData.CipherData.CipherValue = buffer;

            // Replace the element from the original XmlDocument
            // object with the EncryptedData element.
            EncryptedXml.ReplaceElement(documentElement, encryptedData, true);
            foreach (XmlNode node2 in document.ChildNodes)
            {
                if (node2.NodeType == XmlNodeType.Element)
                {
                    foreach (XmlNode node3 in node2.ChildNodes)
                    {
                        if (node3.NodeType == XmlNodeType.Element)
                        {
                            return node3;
                        }
                    }

                }
            }
            return null;
        }

        private byte[] GetRandomKey()
        {
            byte[] data = new byte[0x18];
            new RNGCryptoServiceProvider().GetBytes(data);
            return data;
        }

        /// <summary>
        /// Get either the public key for encrypting configuration sections or the private key to decrypt them. 
        /// </summary>
        /// <param name="IsEncryption"></param>
        /// <returns></returns>
        private RSACryptoServiceProvider GetCryptoServiceProvider(bool IsEncryption)
        {
            RSACryptoServiceProvider provider;
            X509Certificate2 cert = GetCertificate(this.thumbprint);
            if (IsEncryption)
            {
                provider = (RSACryptoServiceProvider)cert.PublicKey.Key;
            }
            else
            {
                provider = (RSACryptoServiceProvider)cert.PrivateKey;
            }
            return provider;
        }

        /// <summary>
        /// Get certificate from the Local Machine store, based on the given thumbprint
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <returns></returns>
        private X509Certificate2 GetCertificate(string thumbprint)
        {
            X509Store store = new X509Store(StoreName.My, storeLocation);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                certificates = store.Certificates;

                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.Thumbprint.ToLower().CompareTo(thumbprint.ToLower()) == 0)
                    {
                        result = new X509Certificate2(cert);

                        return result;
                    }
                }

                if (result == null)
                {
                    throw new ApplicationException(string.Format("No certificate was found for thumbprint {0}", thumbprint));
                }

                return null;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }
    }
}