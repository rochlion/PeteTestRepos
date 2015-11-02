using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace EncryptCompare
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Block Size = " + bsBlockSize);
            Console.WriteLine("Cipher Mode = " + Enum.GetName(typeof(CipherMode), cmCipherMode.GetHashCode()));
            Console.WriteLine("Padding Mode = " + Enum.GetName(typeof(PaddingMode), pmPaddingMode.GetHashCode()));
            Console.WriteLine("");
            Console.WriteLine("Privacy Key:");
            DisplayByteArrayData(privacyKey, string.Empty);
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("Unencrypted Input:");
            Console.WriteLine("------------------");
            DisplayByteArrayData(pdu, string.Empty);
            Console.WriteLine("");
            Console.WriteLine("Encrypted Output:");
            Console.WriteLine("------------------");

            // RijndaelManaged class encryption
            byte[] rmEncrypt = EncryptRM(privacyKey, pdu, pdu.Length, engineBoots, engineTime, 128);
            DisplayByteArrayData(rmEncrypt, "EncryptRM");
            Console.WriteLine("");

            // AesCryptoServiceProvider encryption
            byte[] aesPrvdrEncrypt = EncryptAESCryptProvider(privacyKey, pdu, pdu.Length, engineBoots, engineTime, 128);
            DisplayByteArrayData(aesPrvdrEncrypt, "EncryptAESCryptProvider");
        }

        // Encryption Parameters
        private static int bsBlockSize = 128;
        private static PaddingMode pmPaddingMode = PaddingMode.Zeros;
        private static CipherMode cmCipherMode = CipherMode.CFB;

        // Input Data
        private static byte[] privacyKey = {58, 79,	223, 189, 228, 243, 128, 227, 149, 213, 192, 92, 56, 17, 67, 173, 205, 251, 25, 242};
        private static int engineBoots = 11;
        private static int engineTime = 1248487;
        private static byte[] pdu = { 48, 52, 4, 12, 0, 0, 0, 11, 160, 72, 28, 108, 173, 150, 0, 1, 4, 9, 74, 101, 116, 100, 105, 114, 101, 99, 116, 161, 25, 2, 2, 26, 52, 2, 1, 0, 2, 1, 0, 48, 13, 48, 11, 6, 7, 43, 6, 1, 2, 1, 1, 2, 5, 0 };

        private static void DisplayByteArrayData(byte[] encryptedData, string routine)
        {
            try
            {
                string encryptedDataStr = null;
                foreach (byte b in encryptedData)
                    encryptedDataStr += b.ToString("X2") + " ";
                if (!string.IsNullOrEmpty(routine))
                    Console.WriteLine(routine);
                Console.WriteLine(encryptedDataStr);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(routine + ": EXCEPTION: " + ex.Message);
            }
        }

        public static byte[] EncryptAESCryptProvider(byte[] privacyKey, byte[] scopedPDU, int pduLen, int snmpEngineBoots, int snmpEngineTime, int keySize)
        {
            int keyBytes = (keySize == 128) ? 16 : 32;

            // Salt determinitation for Privacy Parameters
            Int64 saltInt = NextSalt();
            byte[] saltInvert = BitConverter.GetBytes(saltInt);
            byte[] salt = new byte[8];
            salt[0] = saltInvert[7];
            salt[1] = saltInvert[6];
            salt[2] = saltInvert[5];
            salt[3] = saltInvert[4];
            salt[4] = saltInvert[3];
            salt[5] = saltInvert[2];
            salt[6] = saltInvert[1];
            salt[7] = saltInvert[0];

            byte[] IV = new byte[keyBytes];
            byte[] bootsBytes = BitConverter.GetBytes(snmpEngineBoots);
            IV[0] = bootsBytes[3];
            IV[1] = bootsBytes[2];
            IV[2] = bootsBytes[1];
            IV[3] = bootsBytes[0];
            byte[] timeBytes = BitConverter.GetBytes(snmpEngineTime);
            IV[4] = timeBytes[3];
            IV[5] = timeBytes[2];
            IV[6] = timeBytes[1];
            IV[7] = timeBytes[0];

            // Copy salt value to the iv array
            Buffer.BlockCopy(salt, 0, IV, 8, 8);

            // Create AES Key
            byte[] aesKey = new byte[keyBytes];
            Buffer.BlockCopy(privacyKey, 0, aesKey, 0, keyBytes);

            byte[] encryptedRtn = new byte[scopedPDU.Length];
            try
            {
                //perform the encyption..
                //step 1.. Create the stream which will contain the encrypted data
                System.IO.MemoryStream memStrm = new System.IO.MemoryStream();
                //create the DES crypto service provider object
                System.Security.Cryptography.AesCryptoServiceProvider des = new AesCryptoServiceProvider();
                //set the cipher mode
                des.KeySize = keyBytes * 8;
                // PVC Setting to 128 caused Bad Data err des.FeedbackSize = 128;
                des.BlockSize = bsBlockSize;
                des.Padding = pmPaddingMode;
                des.Mode = cmCipherMode;
                des.Key = aesKey;
                des.IV = IV;
                
                //create the stream which will convert the data into enryped form and write into underline stream
                ICryptoTransform cryptoTransform = des.CreateEncryptor(aesKey, IV);
                CryptoStream encryptStrm = new CryptoStream(memStrm, cryptoTransform /* PVC des.CreateEncryptor(aesKey, IV)*/, CryptoStreamMode.Write);

                //wencypt and write data into underline stream
                encryptStrm.Write(scopedPDU, 0, scopedPDU.Length);
                //flush the final block to stream
                encryptStrm.FlushFinalBlock();
                //close the streams
                encryptStrm.Close();
                //set the encypted data buffer
                encryptedRtn = memStrm.ToArray();
                //close the memory stream
                memStrm.Close();
                des.Clear();
            }
            catch (Exception exp)
            {
            }
            return encryptedRtn;
        }



        public static byte[] EncryptRM(byte[] privacyKey, byte[] scopedPDU, int pduLen, int snmpEngineBoots, int snmpEngineTime,  int keySize)
        {
            int keyBytes = (keySize == 128) ? 16 : 32;

            // Salt determinitation for Privacy Parameters
            Int64 saltInt = NextSalt();
            byte[] saltInvert = BitConverter.GetBytes(saltInt);
            byte[] salt = new byte[8];
            salt[0] = saltInvert[7];
            salt[1] = saltInvert[6];
            salt[2] = saltInvert[5];
            salt[3] = saltInvert[4];
            salt[4] = saltInvert[3];
            salt[5] = saltInvert[2];
            salt[6] = saltInvert[1];
            salt[7] = saltInvert[0];

            byte[] IV = new byte[keyBytes];
            byte[] bootsBytes = BitConverter.GetBytes(snmpEngineBoots);
            IV[0] = bootsBytes[3];
            IV[1] = bootsBytes[2];
            IV[2] = bootsBytes[1];
            IV[3] = bootsBytes[0];
            byte[] timeBytes = BitConverter.GetBytes(snmpEngineTime);
            IV[4] = timeBytes[3];
            IV[5] = timeBytes[2];
            IV[6] = timeBytes[1];
            IV[7] = timeBytes[0];

            // Copy salt value to the iv array
            Buffer.BlockCopy(salt, 0, IV, 8, 8);
             
            Rijndael rm = new RijndaelManaged();
            rm.KeySize = keyBytes * 8;
            rm.FeedbackSize = 128;
            rm.BlockSize = bsBlockSize;
            // we have to use Zeros padding otherwise we get encrypt buffer size exception
            rm.Padding = pmPaddingMode;

            rm.Mode = cmCipherMode;
            //Create AES Key
            byte[] aesKey = new byte[keyBytes];
            Buffer.BlockCopy(privacyKey, 0, aesKey, 0, keyBytes);
            rm.Key = aesKey;
            rm.IV = IV;

            byte[] encryptedRtn = new byte[scopedPDU.Length];
            try
            {
                ICryptoTransform cryptor = rm.CreateEncryptor();
                byte[] encryptedData = cryptor.TransformFinalBlock(scopedPDU, 0, pduLen);
                // check if encrypted data is the same length as source data
                if (encryptedData.Length != scopedPDU.Length)
                {
                    // cut out the padding
                    byte[] tmp = new byte[scopedPDU.Length];
                    Buffer.BlockCopy(encryptedData, 0, tmp, 0, scopedPDU.Length);
                    encryptedRtn = tmp;
                }
                else
                {
                    //set the encypted data buffer
                    encryptedRtn = encryptedData;
                }
            }
            catch (Exception exp)
            {
            }
            return encryptedRtn;
        }


        /// <summary>
        /// Get next salt Int64 value. Used internally to encrypt data.
        /// </summary>
        /// <returns>Random Int64 value</returns>
        /// 
        static Int64 salt = Int64.MinValue;
        static protected Int64 NextSalt()
        {
            if (salt == Int64.MaxValue)
                salt = 1;
            else
                salt += 1;
            return salt;
        }
    }
}
