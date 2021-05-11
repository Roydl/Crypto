namespace Roydl.Crypto.SymmetricKey
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides enumerated bits of the key size.
    /// </summary>
    public enum RijndaelKeySize
    {
        /// <summary>
        ///     128 bits.
        /// </summary>
        Aes128 = 128,

        /// <summary>
        ///     192 bits.
        /// </summary>
        Aes192 = 192,

        /// <summary>
        ///     256 bits.
        /// </summary>
        Aes256 = 256
    }

    /// <summary>
    ///     Provides functionality to encrypt and decrypt data using Advanced
    ///     Encryption Standard algorithm.
    /// </summary>
    public sealed class Rijndael : SymmetricKeyAlgorithm
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="Rijndael"/> class.
        /// </summary>
        /// <param name="password">
        ///     The sequence of bytes which is used as password.
        /// </param>
        /// <param name="salt">
        ///     The sequence of bytes which is used as salt.
        /// </param>
        /// <param name="iterations">
        ///     The number of iterations for the operation.
        /// </param>
        /// <param name="keySize">
        ///     The size of the secret key.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream, outputStream, password or salt is null.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     iterations is less than 1.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     salt size is smaller than 8 bytes.
        /// </exception>
        public Rijndael(byte[] password, byte[] salt, int iterations = 1000, RijndaelKeySize keySize = RijndaelKeySize.Aes256) : base(password, salt, iterations, 128, (int)keySize) { }

        /// <summary>
        ///     Encrypts the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to encrypt.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for encryption.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        public override void EncryptStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            using var rm = new RijndaelManaged
            {
                BlockSize = BlockSize,
                KeySize = KeySize,
                Mode = Mode,
                Padding = Padding
            };
            using (var db = new Rfc2898DeriveBytes((byte[])Password, (byte[])Salt, Iterations))
            {
                rm.Key = db.GetBytes(rm.KeySize / 8);
                rm.IV = db.GetBytes(rm.BlockSize / 8);
            }
            try
            {
                var ba = new byte[short.MaxValue];
                int i;
                using var cs = new CryptoStream(outputStream, rm.CreateEncryptor(), CryptoStreamMode.Write);
                while ((i = inputStream.Read(ba, 0, ba.Length)) > 0)
                    cs.Write(ba, 0, i);
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }

        /// <summary>
        ///     Decrypts the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to decrypt.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for decryption.
        /// </param>
        /// <param name="dispose">
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        public override void DecryptStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            using var rm = new RijndaelManaged
            {
                BlockSize = BlockSize,
                KeySize = KeySize,
                Mode = Mode,
                Padding = Padding
            };
            using (var db = new Rfc2898DeriveBytes((byte[])Password, (byte[])Salt, Iterations))
            {
                rm.Key = db.GetBytes(rm.KeySize / 8);
                rm.IV = db.GetBytes(rm.BlockSize / 8);
            }
            try
            {
                var ba = new byte[short.MaxValue];
                int i;
                using var cs = new CryptoStream(outputStream, rm.CreateDecryptor(), CryptoStreamMode.Write);
                while ((i = inputStream.Read(ba, 0, ba.Length)) > 0)
                    cs.Write(ba, 0, i);
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }
    }
}
