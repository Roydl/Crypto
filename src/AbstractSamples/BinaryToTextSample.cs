namespace Roydl.Crypto.AbstractSamples
{
    using System;
    using System.IO;
    using Properties;

    /// <summary>
    ///     Represents the base class from which all implementations of binary-to-text
    ///     encoding algorithms must derive.
    /// </summary>
    public abstract class BinaryToTextSample
    {
        /// <summary>
        ///     Gets the separator.
        /// </summary>
        protected static readonly byte[] Separator = Utils.Utf8NoBom.GetBytes(Environment.NewLine);

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
        public abstract void EncodeStream(Stream inputStream, Stream outputStream, int lineLength = 0, bool dispose = false);

        /// <summary>
        ///     Encodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to encode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for encoding.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="NotSupportedException">
        ///     <see cref="EncodeStream(Stream, Stream, int, bool)"/> method has no
        ///     functionality.
        /// </exception>
        public void EncodeStream(Stream inputStream, Stream outputStream, bool dispose) =>
            EncodeStream(inputStream, outputStream, 0, dispose);

        /// <summary>
        ///     Encodes the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encode.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <returns>
        ///     A string that contains the result of encoding the specified sequence of
        ///     bytes.
        /// </returns>
        public string EncodeBytes(byte[] bytes, int lineLength = 0)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            using var msi = new MemoryStream(bytes);
            using var mso = new MemoryStream();
            EncodeStream(msi, mso, lineLength);
            return Utils.Utf8NoBom.GetString(mso.ToArray());
        }

        /// <summary>
        ///     Encodes the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encode.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <returns>
        ///     A string that contains the result of encoding the specified string.
        /// </returns>
        public string EncodeString(string text, int lineLength = 0)
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            var ba = Utils.Utf8NoBom.GetBytes(text);
            return EncodeBytes(ba, lineLength);
        }

        /// <summary>
        ///     Encodes the specified source file to the specified destination file.
        /// </summary>
        /// <param name="srcPath">
        ///     The source file to encode.
        /// </param>
        /// <param name="destPath">
        ///     The destination file to create.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <param name="overwrite">
        ///     <see langword="true"/> to allow an existing file to be overwritten;
        ///     otherwise, <see langword="false"/>.
        /// </param>
        /// <returns>
        ///     <see langword="true"/> if the destination file exists; otherwise,
        ///     <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///     srcPath or destPath is null.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     srcPath cannot be found.
        /// </exception>
        /// <exception cref="DirectoryNotFoundException">
        ///     destPath is invalid.
        /// </exception>
        public bool EncodeFile(string srcPath, string destPath, int lineLength = 0, bool overwrite = true)
        {
            if (srcPath == null)
                throw new ArgumentNullException(nameof(srcPath));
            if (destPath == null)
                throw new ArgumentNullException(nameof(destPath));
            if (!File.Exists(srcPath))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, srcPath);
            var dir = Path.GetDirectoryName(destPath);
            if (!Directory.Exists(dir))
                throw new DirectoryNotFoundException(ExceptionMessages.DestPathNotValid);
            using var fsi = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
            using var fso = new FileStream(destPath, overwrite ? FileMode.Create : FileMode.CreateNew);
            EncodeStream(fsi, fso, lineLength);
            return File.Exists(destPath);
        }

        /// <summary>
        ///     Encodes the specified file.
        /// </summary>
        /// <param name="path">
        ///     The file to encode.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     path is null.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     path cannot be found.
        /// </exception>
        /// <returns>
        ///     A string that contains the result of encoding the file in the specified
        ///     path.
        /// </returns>
        public string EncodeFile(string path, int lineLength = 0)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var ms = new MemoryStream();
            EncodeStream(fs, ms, lineLength);
            return Utils.Utf8NoBom.GetString(ms.ToArray());
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
        public abstract void DecodeStream(Stream inputStream, Stream outputStream, bool dispose = false);

        /// <summary>
        ///     Decodes the specified string into a sequence of bytes.
        /// </summary>
        /// <param name="code">
        ///     The string to decode.
        /// </param>
        /// <returns>
        ///     A sequence of bytes that contains the results of decoding the specified
        ///     string.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///     code is null.
        /// </exception>
        public byte[] DecodeBytes(string code)
        {
            if (code == null)
                throw new ArgumentNullException(nameof(code));
            var ba = Utils.Utf8NoBom.GetBytes(code);
            using var msi = new MemoryStream(ba);
            using var mso = new MemoryStream();
            DecodeStream(msi, mso);
            return mso.ToArray();
        }

        /// <summary>
        ///     Decodes the specified string into a string.
        /// </summary>
        /// <param name="code">
        ///     The string to decode.
        /// </param>
        /// <returns>
        ///     A string that contains the result of decoding the specified string.
        /// </returns>
        public string DecodeString(string code)
        {
            var ba = DecodeBytes(code);
            if (ba == null)
                throw new NullReferenceException();
            return Utils.Utf8NoBom.GetString(ba);
        }

        /// <summary>
        ///     Decodes the specified source file to the specified destination file.
        /// </summary>
        /// <param name="srcPath">
        ///     The source file to encode.
        /// </param>
        /// <param name="destPath">
        ///     The destination file to create.
        /// </param>
        /// <param name="overwrite">
        ///     <see langword="true"/> to allow an existing file to be overwritten;
        ///     otherwise, <see langword="false"/>.
        /// </param>
        /// <returns>
        ///     <see langword="true"/> if the destination file exists; otherwise,
        ///     <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///     srcPath or destPath is null.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     srcPath cannot be found.
        /// </exception>
        /// <exception cref="DirectoryNotFoundException">
        ///     destPath is invalid.
        /// </exception>
        public bool DecodeFile(string srcPath, string destPath, bool overwrite = true)
        {
            if (srcPath == null)
                throw new ArgumentNullException(nameof(srcPath));
            if (destPath == null)
                throw new ArgumentNullException(nameof(destPath));
            if (!File.Exists(srcPath))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, srcPath);
            var dir = Path.GetDirectoryName(destPath);
            if (!Directory.Exists(dir))
                throw new DirectoryNotFoundException(ExceptionMessages.DestPathNotValid);
            using var fsi = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
            using var fso = new FileStream(destPath, overwrite ? FileMode.Create : FileMode.CreateNew);
            DecodeStream(fsi, fso);
            return File.Exists(destPath);
        }

        /// <summary>
        ///     Decodes the specified string into a sequence of bytes containing a small
        ///     file.
        /// </summary>
        /// <param name="path">
        ///     The file to decode.
        /// </param>
        /// <returns>
        ///     A sequence of bytes that contains the results of decoding the file in
        ///     specified string.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///     path is null.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     path cannot be found.
        /// </exception>
        public byte[] DecodeFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var ms = new MemoryStream();
            DecodeStream(fs, ms);
            return ms.ToArray();
        }

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Write the specified byte into the stream and add a line separator depending
        ///     on the specified line length.
        /// </summary>
        /// <param name="stream">
        ///     The stream in which to write the single byte.
        /// </param>
        /// <param name="singleByte">
        ///     The single byte.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <param name="linePos">
        ///     The position in the line.
        /// </param>
        protected static void WriteLine(Stream stream, byte singleByte, int lineLength, ref int linePos)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            stream.WriteByte(singleByte);
            if (lineLength < 1 || lineLength > ++linePos)
                return;
            linePos = 0;
            stream.Write(Separator, 0, Separator.Length);
        }
    }
}
