namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc cref="ChecksumAlgorithm.Encrypt(Stream)"/>
        public override void Encrypt(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Span<uint> sums = stackalloc[] { 1u, 0u };
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            int len;
            while ((len = stream.Read(bytes)) > 0)
            {
                for (var i = 0; i < len; i++)
                    ComputeHash(bytes[i], ref sums);
            }
            FinalizeHash(sums);
        }

        /// <inheritdoc cref="ChecksumAlgorithm.Encrypt(byte[])"/>
        public override void Encrypt(byte[] bytes)
        {
            Reset();
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            Span<uint> sums = stackalloc[] { 1u, 0u };
            foreach (var value in bytes)
                ComputeHash(value, ref sums);
            FinalizeHash(sums);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ComputeHash(byte value, ref Span<uint> hash)
        {
            if (hash.Length < 2)
                throw new IndexOutOfRangeException();
            hash[0] = (hash[0] + value) % 0xfff1;
            hash[1] = (hash[1] + hash[0]) % 0xfff1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FinalizeHash(ReadOnlySpan<uint> hash)
        {
            if (hash.Length < 2)
                throw new IndexOutOfRangeException();
            var sum = ((hash[1] << 16) | hash[0]) & uint.MaxValue;
            HashNumber = sum;
            RawHash = CryptoUtils.GetByteArray(sum, !BitConverter.IsLittleEndian);
        }
    }
}
