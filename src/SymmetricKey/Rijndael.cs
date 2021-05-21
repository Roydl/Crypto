﻿namespace Roydl.Crypto.SymmetricKey
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

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
        ///     <para>
        ///         For more information, see
        ///         <see cref="SymmetricKeyAlgorithm.DestroySecretData()">
        ///             here
        ///         </see>
        ///         .
        ///     </para>
        /// </param>
        /// <param name="salt">
        ///     The sequence of bytes which is used as salt.
        ///     <para>
        ///         For more information, see
        ///         <see cref="SymmetricKeyAlgorithm.DestroySecretData()">
        ///             here
        ///         </see>
        ///         .
        ///     </para>
        /// </param>
        /// <param name="iterations">
        ///     The number of iterations for the operation.
        /// </param>
        /// <param name="keySize">
        ///     The size of the secret key.
        /// </param>
        /// <inheritdoc cref="SymmetricKeyAlgorithm(byte[], byte[], int, int, SymmetricKeySize)"/>
        public Rijndael(byte[] password, byte[] salt, int iterations = 1000, SymmetricKeySize keySize = SymmetricKeySize.Large) : base(password, salt, iterations, 128, keySize) { }

        /// <inheritdoc/>
        public override void EncryptStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            using var rm = new RijndaelManaged
            {
                BlockSize = BlockSize,
                KeySize = (int)KeySize,
                Mode = (CipherMode)Mode,
                Padding = (PaddingMode)Padding
            };
            using (var db = new Rfc2898DeriveBytes((byte[])Password, (byte[])Salt, Iterations))
            {
                rm.Key = db.GetBytes(rm.KeySize / 8);
                rm.IV = db.GetBytes(rm.BlockSize / 8);
            }
            try
            {
                var ba = CryptoUtils.CreateBuffer(inputStream);
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

        /// <inheritdoc/>
        public override void DecryptStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            using var rm = new RijndaelManaged
            {
                BlockSize = BlockSize,
                KeySize = (int)KeySize,
                Mode = (CipherMode)Mode,
                Padding = (PaddingMode)Padding
            };
            using (var db = new Rfc2898DeriveBytes((byte[])Password, (byte[])Salt, Iterations))
            {
                rm.Key = db.GetBytes(rm.KeySize / 8);
                rm.IV = db.GetBytes(rm.BlockSize / 8);
            }
            try
            {
                var ba = CryptoUtils.CreateBuffer(inputStream);
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
