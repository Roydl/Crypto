namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Adler32(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Adler32(byte[] bytes) : base(32, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Adler32(string textOrFile, bool strIsFilePath) : base(32, textOrFile, strIsFilePath) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Adler32(string text) : base(32, text) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Adler32(FileInfo fileInfo) : base(32, fileInfo) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc cref="ChecksumAlgorithm.Encrypt(Stream)"/>
        public override unsafe void Encrypt(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            uint sum = 0;
            fixed (uint* sums = new[] { 1u, 0u })
            {
                var size = stream.GetBufferSize();
                var bytes = new byte[size];
                fixed (byte* buffer = bytes)
                {
                    int len;
                    while ((len = stream.Read(bytes, 0, size)) > 0)
                    {
                        for (var i = 0; i < len; i++)
                        {
                            var value = buffer[i];
                            sums[0] = (sums[0] + value) % 0xfff1;
                            sums[1] = (sums[1] + sums[0]) % 0xfff1;
                        }
                    }
                }
                sum = ((sums[1] << 16) | sums[0]) & uint.MaxValue;
            }
            HashNumber = sum;
            RawHash = CryptoUtils.GetByteArray(sum, !BitConverter.IsLittleEndian);
        }
    }
}
