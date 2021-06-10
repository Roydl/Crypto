namespace Roydl.Crypto.SymmetricKey
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using Internal;
    using Resources;

    /// Wrapper to kick out unsupported modes
    /// <inheritdoc cref="CipherMode"/>
    public enum BlockCipherMode
    {
        /// <inheritdoc cref="CipherMode.CBC"/>
        Cbc = CipherMode.CBC,

        /// <inheritdoc cref="CipherMode.CFB"/>
        Cfb = CipherMode.CFB
    }

    /// Wrapper to prevent additional namespace for a single feature
    /// <inheritdoc cref="PaddingMode"/>
    public enum BlockPaddingMode
    {
        /// <inheritdoc cref="PaddingMode.None"/>
        None = PaddingMode.None,

        /// <inheritdoc cref="PaddingMode.PKCS7"/>
        Pkcs7 = PaddingMode.PKCS7,

        /// <inheritdoc cref="PaddingMode.Zeros"/>
        Zeros = PaddingMode.Zeros,

        /// <inheritdoc cref="PaddingMode.ANSIX923"/>
        Ansix923 = PaddingMode.ANSIX923,

        /// <inheritdoc cref="PaddingMode.ISO10126"/>
        Iso10126 = PaddingMode.ISO10126
    }

    /// <summary>Specifies the bit widths of a symmetric key.</summary>
    public enum SymmetricKeySize
    {
        /// <summary>128 bits.</summary>
        Small = 128,

        /// <summary>192 bits.</summary>
        Medium = 192,

        /// <summary>256 bits.</summary>
        Large = 256
    }

    /// <summary>Represents the base class from which all implementations of symmetric key encryption algorithms must derive.</summary>
    public abstract class SymmetricKeyAlgorithm : IDisposable
    {
        private byte[] _password, _salt;

        /// <summary>The block size, in bits, of the cryptographic operation.</summary>
        public int BlockSize { get; }

        /// <summary>The size, in bits, of the secret key used for the symmetric algorithm.</summary>
        public SymmetricKeySize KeySize { get; }

        /// <summary>The mode for operation of the symmetric algorithm. The default is <see cref="BlockCipherMode.Cbc"/>.</summary>
        public BlockCipherMode Mode { get; set; } = BlockCipherMode.Cbc;

        /// <summary>The padding mode used in the symmetric algorithm. The default is <see cref="BlockPaddingMode.Pkcs7"/>.</summary>
        public BlockPaddingMode Padding { get; set; } = BlockPaddingMode.Pkcs7;

        /// <summary>The number of iterations for the operation.</summary>
        public int Iterations { get; }

        /// <summary>The sequence of bytes which is used as password.</summary>
        /// <remarks>For more information, see <see cref="DestroySecretData">here</see>.</remarks>
        public IReadOnlyList<byte> Password => _password;

        /// <summary>The sequence of bytes which is used as salt.</summary>
        /// <remarks>For more information, see <see cref="DestroySecretData">here</see>.</remarks>
        public IReadOnlyList<byte> Salt => _salt;

        /// <summary>Initializes a new instance of the <see cref="SymmetricKeyAlgorithm"/> class.</summary>
        /// <param name="password">The sequence of bytes which is used as password.
        ///     <para>For more information, see <see cref="DestroySecretData()">here</see>.</para>
        /// </param>
        /// <param name="salt">The sequence of bytes which is used as salt.
        ///     <para>For more information, see <see cref="DestroySecretData()">here</see>.</para>
        /// </param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="blockSize">The block size, in bits, of the cryptographic operation.</param>
        /// <param name="keySize">The size, in bits, of the secret key used for the symmetric algorithm.</param>
        /// <exception cref="ArgumentNullException">inputStream, outputStream, password or salt is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">iterations is less than 1.</exception>
        /// <exception cref="ArgumentException">salt size is smaller than 8 bytes.</exception>
        protected SymmetricKeyAlgorithm(byte[] password, byte[] salt, int iterations, int blockSize, SymmetricKeySize keySize)
        {
            _password = password ?? throw new ArgumentNullException(nameof(password));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length < 8)
                throw new ArgumentException(ExceptionMessages.ArgumentSizeTooSmall, nameof(salt));
            _salt = salt;
            if (iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(iterations), iterations, null);
            Iterations = iterations;
            BlockSize = blockSize;
            KeySize = keySize;
        }

        /// <summary>Encrypts the specified input stream into the specified output stream.</summary>
        /// <param name="inputStream">The input stream to encrypt.</param>
        /// <param name="outputStream">The output stream for encryption.</param>
        /// <param name="dispose"><see langword="true"/> to release all resources used by the input and output <see cref="Stream"/> ; otherwise, <see langword="false"/>.</param>
        public abstract void EncryptStream(Stream inputStream, Stream outputStream, bool dispose = false);

        /// <summary>Encrypts the specified sequence of bytes.</summary>
        /// <param name="bytes">The sequence of bytes to encrypt.</param>
        /// <returns>A sequence of bytes that contains the results of encrypting the specified sequence of bytes.</returns>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        /// <exception cref="ArgumentException">bytes is empty.</exception>
        public byte[] EncryptBytes(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentSizeTooSmall, nameof(bytes));
            using var msi = new MemoryStream(bytes);
            using var mso = new MemoryStream();
            EncryptStream(msi, mso);
            return mso.ToArray();
        }

        /// <summary>Encrypts the specified source file to the specified destination file.</summary>
        /// <param name="srcPath">The source file to encrypt.</param>
        /// <param name="destPath">The destination file to create.</param>
        /// <param name="overwrite"><see langword="true"/> to allow an existing file to be overwritten; otherwise, <see langword="false"/>.</param>
        /// <returns><see langword="true"/> if the destination file exists; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException">srcPath or destPath is null.</exception>
        /// <exception cref="FileNotFoundException">srcPath cannot be found.</exception>
        /// <exception cref="DirectoryNotFoundException">destPath is invalid.</exception>
        public bool EncryptFile(string srcPath, string destPath, bool overwrite = true)
        {
            if (srcPath == null)
                throw new ArgumentNullException(nameof(srcPath));
            if (destPath == null)
                throw new ArgumentNullException(nameof(destPath));
            if (!File.Exists(srcPath))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, srcPath);
            var dir = Path.GetDirectoryName(destPath);
            if (!Directory.Exists(dir))
                throw new DirectoryNotFoundException(ExceptionMessages.DirectoryNotFoundDestPath);
            using var fsi = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
            using var fso = new FileStream(destPath, overwrite ? FileMode.Create : FileMode.CreateNew);
            EncryptStream(fsi, fso);
            return File.Exists(destPath);
        }

        /// <summary>Encrypts the specified file.</summary>
        /// <param name="path">The file to encrypt.</param>
        /// <returns>A sequence of bytes that contains the results of encrypting the specified file.</returns>
        /// <exception cref="ArgumentNullException">path is null.</exception>
        /// <exception cref="FileNotFoundException">path cannot be found.</exception>
        public byte[] EncryptFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var ms = new MemoryStream();
            EncryptStream(fs, ms);
            return ms.ToArray();
        }

        /// <summary>Decrypts the specified input stream into the specified output stream.</summary>
        /// <param name="inputStream">The input stream to decrypt.</param>
        /// <param name="outputStream">The output stream for decryption.</param>
        /// <param name="dispose"><see langword="true"/> to release all resources used by the input and output <see cref="Stream"/> ; otherwise, <see langword="false"/>.</param>
        public abstract void DecryptStream(Stream inputStream, Stream outputStream, bool dispose = false);

        /// <summary>Decrypts the specified sequence of bytes.</summary>
        /// <param name="code">The sequence of bytes to decrypt.</param>
        /// <returns>A sequence of bytes that contains the results of decrypting the specified sequence of bytes.</returns>
        /// <exception cref="ArgumentNullException">code is null.</exception>
        /// <exception cref="ArgumentException">code is empty.</exception>
        public byte[] DecryptBytes(byte[] code)
        {
            if (code == null)
                throw new ArgumentNullException(nameof(code));
            if (code.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentSizeTooSmall, nameof(code));
            using var msi = new MemoryStream(code);
            using var mso = new MemoryStream();
            DecryptStream(msi, mso);
            return mso.ToArray();
        }

        /// <summary>Decrypts the specified source file to the specified destination file.</summary>
        /// <param name="srcPath">The source file to decrypt.</param>
        /// <param name="destPath">The destination file to create.</param>
        /// <param name="overwrite"><see langword="true"/> to allow an existing file to be overwritten; otherwise, <see langword="false"/>.</param>
        /// <returns><see langword="true"/> if the destination file exists; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException">srcPath or destPath is null.</exception>
        /// <exception cref="FileNotFoundException">srcPath cannot be found.</exception>
        /// <exception cref="DirectoryNotFoundException">destPath is invalid.</exception>
        public bool DecryptFile(string srcPath, string destPath, bool overwrite = true)
        {
            if (srcPath == null)
                throw new ArgumentNullException(nameof(srcPath));
            if (destPath == null)
                throw new ArgumentNullException(nameof(destPath));
            if (!File.Exists(srcPath))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, srcPath);
            using var fsi = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
            using var fso = new FileStream(destPath, overwrite ? FileMode.Create : FileMode.CreateNew);
            DecryptStream(fsi, fso);
            return File.Exists(destPath);
        }

        /// <summary>Decrypts the specified file.</summary>
        /// <param name="path">The file to decrypt.</param>
        /// <returns>A sequence of bytes that contains the results of decrypting the specified file.</returns>
        /// <exception cref="ArgumentNullException">path is null.</exception>
        /// <exception cref="FileNotFoundException">path cannot be found.</exception>
        public byte[] DecryptFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var ms = new MemoryStream();
            DecryptStream(fs, ms);
            return ms.ToArray();
        }

        /// <summary>Removes the password and salt of this instance from current process memory.</summary>
        /// <remarks>Additional information:
        ///     <list type="bullet">
        ///         <item><description>The data cannot be removed if they are referenced outside of this instance.</description></item>
        ///         <item><description>Depending on the system, removing the data can take several seconds.</description></item>
        ///         <item><description>This function is called automatically when disposing this instance.</description></item>
        ///     </list>
        /// </remarks>
        public void DestroySecretData()
        {
            GarbageHelper.DestroyElement(ref _password);
            GarbageHelper.DestroyElement(ref _salt);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc cref="Dispose()"/>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposing)
                return;
            DestroySecretData();
        }
    }
}
