namespace Roydl.Crypto.SymmetricKey
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to encrypt and decrypt data using Advanced Encryption Standard algorithm.</summary>
    public sealed class Rijndael : SymmetricKeyAlgorithm
    {
        /// <summary>Initializes a new instance of the <see cref="Rijndael"/> class.</summary>
        /// <param name="password">The sequence of bytes which is used as password.
        ///     <para>For more information, see <see cref="SymmetricKeyAlgorithm.DestroySecretData()">here</see>.</para>
        /// </param>
        /// <param name="salt">The sequence of bytes which is used as salt.
        ///     <para>For more information, see <see cref="SymmetricKeyAlgorithm.DestroySecretData()">here</see>.</para>
        /// </param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="keySize">The size of the secret key.</param>
        /// <param name="keyAlgo">The hash algorithm to use to derive the symmetric key.</param>
        /// <inheritdoc cref="SymmetricKeyAlgorithm(byte[], byte[], int, int, SymmetricKeySize, SymmetricKeyAlgo)"/>
        public Rijndael(byte[] password, byte[] salt, int iterations = 1000, SymmetricKeySize keySize = SymmetricKeySize.Large, SymmetricKeyAlgo keyAlgo = SymmetricKeyAlgo.Sha256) : base(password, salt, iterations, 128, keySize, keyAlgo) { }

        /// <inheritdoc/>
        public override void Encrypt(Stream inputStream, Stream outputStream, bool dispose = false) =>
            InternalEncryptDecrypt(inputStream, outputStream, true, dispose);

        /// <inheritdoc/>
        public override void Decrypt(Stream inputStream, Stream outputStream, bool dispose = false) =>
            InternalEncryptDecrypt(inputStream, outputStream, false, dispose);

        private void InternalEncryptDecrypt(Stream inputStream, Stream outputStream, bool encrypt, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            using var man = Aes.Create();
            if (man == null)
                throw new NullReferenceException();

            man.BlockSize = BlockSize;
            man.KeySize = (int)KeySize;
            man.Mode = (CipherMode)Mode;
            man.Padding = (PaddingMode)Padding;

            var keyAlgo = KeyAlgo switch
            {
                SymmetricKeyAlgo.Sha1 => HashAlgorithmName.SHA1,
                SymmetricKeyAlgo.Sha384 => HashAlgorithmName.SHA384,
                SymmetricKeyAlgo.Sha512 => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };

            using var db = new Rfc2898DeriveBytes((byte[])Password, (byte[])Salt, Iterations, keyAlgo);
            man.Key = db.GetBytes(man.KeySize / 8);
            man.IV = db.GetBytes(man.BlockSize / 8);

            try
            {
                var ba = new byte[inputStream.GetBufferSize()];
                int len;
                using var cs = new CryptoStream(outputStream, encrypt ? man.CreateEncryptor() : man.CreateDecryptor(), CryptoStreamMode.Write);
                while ((len = inputStream.Read(ba)) > 0)
                    cs.Write(ba, 0, len);
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
