using System;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using Chromia.PostchainClient.GTX;

namespace Postchain.Examples.Messenger
{
    public struct Message
    {
        public string sender;
        public int timestamp;
        public string content;
    }
    public class PostchainMessenger
    {
        private GTXClient _gtxClient;
        private byte[] _gtxPrivateKey;
        private byte[] _gtxPublicKey;
        private Dictionary<string, DHParameters> _dhParameters;
        private Dictionary<string, AsymmetricCipherKeyPair> _dhKeys;
        private Dictionary<string, byte[]> _dhSecretHashes;
        private int _lastFriendRequestTimestamp = 0;
        private int _lastMessageTimestamp = 0;

        public PostchainMessenger(GTXClient gtxClient, byte[] gtxPrivateKey, byte[] gtxPublicKey)
        {
            _gtxClient = gtxClient;
            _gtxPrivateKey = gtxPrivateKey;
            _gtxPublicKey = gtxPublicKey;

            _dhKeys = new Dictionary<string, AsymmetricCipherKeyPair>();
            _dhParameters = new Dictionary<string, DHParameters>();
            _dhSecretHashes = new Dictionary<string, byte[]>();
        }

        public async void SendFriendRequest(string name)
        {
            if (IsNameInLocalData(name))
            {
                Console.WriteLine("SendFriendRequest: Friend already exists in local data");
                return;
            }

            DHParameters newDHParameters = GenerateParameters();
            AsymmetricCipherKeyPair newDHKeys = GenerateKeys(newDHParameters);
            AddDHParametersToLocalData(name, newDHParameters);
            AddKeysToLocalData(name, newDHKeys);

            Transaction tx = _gtxClient.NewTransaction(new byte[][] {_gtxPublicKey});
            tx.AddOperation("send_friend_request", _gtxPublicKey, name, newDHParameters.G.ToString(), newDHParameters.P.ToString(), GetPublicDHKeyAsStringForName(name));
            tx.Sign(_gtxPrivateKey, _gtxPublicKey);

            string response = (string) await tx.PostAndWaitConfirmation();
            if (!String.IsNullOrEmpty(response))
            {
                Console.WriteLine("SendFriendRequest: Sending friend request failed: " + response);
            }
        }

        public async Task<List<string>> GetFriendRequests()
        {
            var newFriendRequests =  await _gtxClient.Query("get_friend_requests", new dynamic[]{("pubkey", _gtxPublicKey), ("last_timestamp", _lastFriendRequestTimestamp)});
            List<string> friendRequestNames = new List<string>();
            
            foreach (var friendRequest in newFriendRequests)
            {
                string name = (string) friendRequest["name"];
                int timestamp = (int) friendRequest["time"];
                string g = (string) friendRequest["g"];
                string p = (string) friendRequest["p"];
                DHParameters newDHParameters = new DHParameters(new BigInteger(p), new BigInteger(g));

                AddDHParametersToLocalData(name, newDHParameters);
                friendRequestNames.Add(name);

                if (timestamp > _lastFriendRequestTimestamp)
                {
                    _lastFriendRequestTimestamp = timestamp;
                }
            }

            return friendRequestNames;
        }

        public async void AcceptFriendRequest(string name)
        {
            if (!ParametersExistForName(name))
            {
                Console.WriteLine("AcceptFriendRequest: Parameters already exist for " + name);
                return;
            }

            DHParameters dhParameters = GetDHParametersForName(name);
            if (dhParameters == null)
            {
                Console.WriteLine("GetSharedSecretHash: Could not find parameters for " + name);
                return;
            }

            AsymmetricCipherKeyPair newDHKeys = GenerateKeys(dhParameters);
            AddKeysToLocalData(name, newDHKeys);

            Transaction tx = _gtxClient.NewTransaction(new byte[][] {_gtxPublicKey});
            tx.AddOperation("accept_friend_request", _gtxPublicKey, name, GetPublicDHKeyAsStringForName(name));
            tx.Sign(_gtxPrivateKey, _gtxPublicKey);

            string response = (string) await tx.PostAndWaitConfirmation();
            if (!String.IsNullOrEmpty(response))
            {
                Console.WriteLine("AcceptFriendRequest: Accepting friend request failed: " + response);
            }
        }

        public async void SendMessage(string recipient, string message)
        {
            byte[] hashedSharedSecret = await GetSharedSecretHash(recipient);
            if (hashedSharedSecret.Length == 0)
            {
                Console.WriteLine("SendMessage: Could not get shared secret hash for " + recipient);
                return;
            }

            string encryptedMessage = Encrypt(message, hashedSharedSecret);

            Transaction tx = _gtxClient.NewTransaction(new byte[][] {_gtxPublicKey});
            tx.AddOperation("send_message", _gtxPublicKey, recipient, encryptedMessage);
            tx.AddOperation("nop", new SecureRandom().NextInt());
            tx.Sign(_gtxPrivateKey, _gtxPublicKey);

            string response = (string) await tx.PostAndWaitConfirmation();
            if (!String.IsNullOrEmpty(response))
            {
                Console.WriteLine("SendMessage: Sending message failed: " + response);
            }
        }

        public async Task<List<Message>> GetNewMessages()
        {
            var messages = await _gtxClient.Query("get_messages", new dynamic[]{("pubkey", _gtxPublicKey), ("last_timestamp", _lastMessageTimestamp)});
            List<Message> decodedMessages = new List<Message>();

            foreach (var message in messages)
            {
                string sender = (string) message["from"];
                int timestamp = (int) message["time"];
                string encodedMessage = (string) message["content"];

                byte[] hashedSharedSecret = await GetSharedSecretHash(sender);
                if (hashedSharedSecret.Length == 0)
                {
                    Console.WriteLine("GetNewMessages: Could not get shared secret hash for " + sender);
                    continue;
                }

                string decodedMessage = Decrypt(encodedMessage, hashedSharedSecret);

                Message newMessage = new Message() {sender = sender, timestamp = timestamp, content = decodedMessage};
                decodedMessages.Add(newMessage);

                if (timestamp > _lastMessageTimestamp)
                {
                    _lastMessageTimestamp = timestamp;
                }
            }

            return decodedMessages;
        }

        public static AsymmetricCipherKeyPair GenerateKeys(DHParameters parameters)
        {
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("DH");
            var kgp = new DHKeyGenerationParameters(new SecureRandom(), parameters);
            keyGen.Init(kgp);
            return keyGen.GenerateKeyPair();
        }

        private async Task<string> GetFriendsPublicKey(string name)
        {
            string friendPublicKey;
            var queryRet = await _gtxClient.Query("get_friends_A", new dynamic[]{("pubkey", _gtxPublicKey), ("friend_name", name)});
            try 
            {
                friendPublicKey = (string) queryRet;
            }
            catch (ArgumentException)
            {
                Console.WriteLine("GetFriendsPublicKey: Failed with message " + queryRet.message);
                return null;
            }
            
            return friendPublicKey;
        }

        private bool IsNameInLocalData(string name)
        {
            return _dhParameters.ContainsKey(name) || _dhKeys.ContainsKey(name);
        }

        private bool ParametersExistForName(string name)
        {
            return _dhParameters.ContainsKey(name);
        }

        private void AddDHParametersToLocalData(string name, DHParameters parameters)
        {
            if (!_dhParameters.ContainsKey(name))
            {
                _dhParameters.Add(name, parameters);
            }
        }

        private void AddKeysToLocalData(string name, AsymmetricCipherKeyPair keys)
        {
            if (!_dhKeys.ContainsKey(name))
            {
                _dhKeys.Add(name, keys);
            }
        }

        private void AddSecretHashToLocalData(string name, byte[] hash)
        {
            if (!_dhSecretHashes.ContainsKey(name))
            {
                _dhSecretHashes.Add(name, hash);
            }
        }

        private byte[] GetHashedSecretForName(string name)
        {
            if (_dhSecretHashes.ContainsKey(name))
            {
                return _dhSecretHashes[name];
            }
            else
            {
                return null;
            }
        }

        private string GetPublicDHKeyAsStringForName(string name)
        {
            if (_dhKeys.ContainsKey(name))
            {
                DHPublicKeyParameters publicKey = (_dhKeys[name].Public as DHPublicKeyParameters);

                return publicKey.Y.ToString();
            }
            else
            {
                return null;
            }
            
        }

        private DHPrivateKeyParameters GetPrivateDHKeyForName(string name)
        {
            if (_dhKeys.ContainsKey(name))
            {
                DHPrivateKeyParameters privateKey = (_dhKeys[name].Private as DHPrivateKeyParameters);

                return privateKey;
            }
            else
            {
                return null;
            }
        }

        private DHParameters GetDHParametersForName(string name)
        {
            if (_dhParameters.ContainsKey(name))
            {
                return _dhParameters[name];
            }
            else
            {
                return null;
            }
        }


        private async Task<byte[]> GetSharedSecretHash(string name)
        {
            byte[] hashedSharedSecret;
            if (!_dhSecretHashes.ContainsKey(name))
            {
                string recipientsPublicKey = await GetFriendsPublicKey(name);
                if (String.IsNullOrEmpty(recipientsPublicKey)) 
                {
                    Console.WriteLine("GetSharedSecretHash: Could not retreive public key from " + name);
                    return new byte[0];
                }

                DHParameters parameters = GetDHParametersForName(name);
                if (parameters == null)
                {
                    Console.WriteLine("GetSharedSecretHash: Could not find parameters for " + name);
                    return new byte[0];
                }

                BigInteger sharedSecret = ComputeSharedSecret(recipientsPublicKey, GetPrivateDHKeyForName(name), parameters);
                hashedSharedSecret = ComputeSharedSecretHash(sharedSecret);
                AddSecretHashToLocalData(name, hashedSharedSecret);
            }
            else
            {
                hashedSharedSecret = GetHashedSecretForName(name);
            }

            return hashedSharedSecret;         
        }

        private DHParameters GenerateParameters()
        {
            DHParametersGenerator generator = new DHParametersGenerator();
            generator.Init(1024, 30, new SecureRandom());

            return generator.GenerateParameters();
        }

        private BigInteger ComputeSharedSecret(string A, AsymmetricKeyParameter privateKey, DHParameters dhParameters)
        {
            DHPublicKeyParameters importedKey = new DHPublicKeyParameters(new BigInteger(A), dhParameters);
            IBasicAgreement internalKeyAgree = AgreementUtilities.GetBasicAgreement("DH");            
            internalKeyAgree.Init(privateKey);

            BigInteger sharedSecret = internalKeyAgree.CalculateAgreement(importedKey);
            return sharedSecret;
        }

        private byte[] ComputeSharedSecretHash(BigInteger privateKey)
        {
            var encData = privateKey.ToByteArray();

            var digest = new Sha256Digest();
            digest.BlockUpdate(encData, 0, encData.Length);

            byte[] commonSecretHash = new byte[digest.GetDigestSize()];
            digest.DoFinal(commonSecretHash, 0);

            return commonSecretHash;
        }

        private string Encrypt(string data, byte[] key)
        {
            using (AesCryptoServiceProvider csp = new AesCryptoServiceProvider())
            {
                RijndaelManaged aes256 = GetAes256(key);
        
                ICryptoTransform encryptor = aes256.CreateEncryptor();
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                StreamWriter mSWriter = new StreamWriter(cs);
                mSWriter.Write(data);
                mSWriter.Flush();
                cs.FlushFinalBlock();
                byte[] cypherTextBytes = ms.ToArray();
                ms.Close();
                return Convert.ToBase64String(cypherTextBytes);
            }
        }

        private string Decrypt(string data, byte[] key)
        {
            RijndaelManaged aes256 = GetAes256(key);

            byte[] encryptedData = Convert.FromBase64String(data);
            ICryptoTransform transform = aes256.CreateDecryptor();
            byte[] plainText = transform.TransformFinalBlock(encryptedData, 0, encryptedData.Length);            
            return System.Text.Encoding.UTF8.GetString(plainText);
        }

        private RijndaelManaged GetAes256(byte[] key)
        {
            RijndaelManaged aes256 = new RijndaelManaged();
            aes256.KeySize = 256;
            aes256.BlockSize = 128;
            aes256.Padding = PaddingMode.Zeros;
            aes256.Mode = CipherMode.ECB;
            aes256.Key = key;
            aes256.GenerateIV();

            return aes256;
        }
    }
}