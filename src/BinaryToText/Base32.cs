namespace Roydl.Crypto.BinaryToText
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Text;
    using AbstractSamples;
    using Properties;

    /// <summary>
    ///     Provides functionality for translating data into the Base32 text
    ///     representations and back.
    /// </summary>
    public sealed class Base32 : BinaryToTextSample
    {
        /// ReSharper disable CommentTypo
        /// <summary>
        ///     Standard 32-character set: <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>
        /// </summary>
        /// ReSharper restore CommentTypo
        private static ReadOnlySpan<byte> CharacterTable32 => new byte[]
        {
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
        };

        /// <summary>
        ///     Initializes a new instance of the <see cref="Base32"/> class.
        /// </summary>
        [SuppressMessage("ReSharper", "EmptyConstructor")]
        public Base32() { }

        /// <summary>
        ///     Encodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to encode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for encoding.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     inputStream or outputStream is invalid.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void EncodeStream(Stream inputStream, Stream outputStream, int lineLength = 0, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            try
            {
                int i, p = 0, len = 0;
                var ba = new byte[16384];
                while ((i = inputStream.Read(ba, 0, ba.Length)) > 0)
                {
                    for (var j = 0; j < i * 8; j += 5)
                    {
                        len++;
                        var b = ba[j / 8] << 8;
                        if (j / 8 + 1 < i)
                            b |= ba[j / 8 + 1];
                        b = 31 & (b >> (16 - j % 8 - 5));
                        WriteLine(outputStream, CharacterTable32[b], lineLength, ref p);
                    }
                }
                while (len++ % 8 != 0)
                    WriteLine(outputStream, (byte)'=', lineLength, ref p);
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
        ///     Decodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to decode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for decoding.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     inputStream or outputStream is invalid.
        /// </exception>
        /// <exception cref="DecoderFallbackException">
        ///     inputStream contains invalid characters.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void DecodeStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            try
            {
                int i;
                var buf = new byte[16384];
                var c32 = Utils.Utf8NoBom.GetString(CharacterTable32);
                while ((i = inputStream.Read(buf, 0, buf.Length)) > 0)
                {
                    var ba = buf.Take(i).Where(b => (int)b is not ('\0' or '\t' or '\n' or '\r' or ' ')).TakeWhile(b => b != '=').ToArray();
                    var len = ba.Length * 5;
                    for (var j = 0; j < len; j += 8)
                    {
                        var b = (int)ba[j / 5];
                        var c = c32.IndexOf((char)b) << 10;
                        var n = j / 5 + 1;
                        if (n < ba.Length)
                        {
                            b = ba[n];
                            LocalDecoderFallbackCheck(b);
                            var p = c32.IndexOf((char)b);
                            c |= p << 5;
                            c |= p << 5;
                        }
                        n++;
                        if (n < ba.Length)
                        {
                            b = ba[n];
                            LocalDecoderFallbackCheck(b);
                            c |= c32.IndexOf((char)b);
                        }
                        c = 255 & (c >> (15 - j % 5 - 8));
                        if (j + 5 > len && c < 1)
                            break;
                        outputStream.WriteByte((byte)c);
                    }
                }

                static void LocalDecoderFallbackCheck(int i)
                {
                    if (i is >= '2' and <= '7' or >= 'A' and <= 'Z')
                        return;
                    throw new DecoderFallbackException(ExceptionMessages.FollowingCharCodeIsInvalid + i);
                }
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
